using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;

namespace SentryShield.Database
{
    public class ImportResult
    {
        public long RecordsImported { get; set; }
        public long RecordsSkipped { get; set; }
        public string SourceMachine { get; set; } = string.Empty;
        public string ExportTimestamp { get; set; } = string.Empty;
        public bool Success { get; set; }
    }

    public class SneakernetImporter
    {
        private readonly string _dbPath;
        private readonly ILogger _logger;

        public SneakernetImporter(string dbPath, ILogger logger)
        {
            _dbPath = dbPath;
            _logger = logger;
        }

        public ImportResult ImportThreatBundle(string bundlePath)
        {
            var result = new ImportResult { Success = false };

            if (!File.Exists(bundlePath))
            {
                if (_logger != null) _logger.LogError($"Threat bundle not found: {bundlePath}");
                return result;
            }

            string? syncKey = Environment.GetEnvironmentVariable("SENTRY_SYNC_KEY");
            if (string.IsNullOrEmpty(syncKey))
            {
                if (_logger != null) _logger.LogWarning("SENTRY_SYNC_KEY environment variable is not set. Cannot import threat bundle.");
                return result;
            }

            string tmpDir = Path.Combine(Path.GetTempPath(), "SentryImport_" + Guid.NewGuid().ToString("N"));

            try
            {
                Directory.CreateDirectory(tmpDir);
                ZipFile.ExtractToDirectory(bundlePath, tmpDir);

                string manifestPath = Path.Combine(tmpDir, "manifest.json");
                string signaturePath = Path.Combine(tmpDir, "signature.sig");
                string threatsDbPath = Path.Combine(tmpDir, "threats.db");

                if (!File.Exists(manifestPath) || !File.Exists(signaturePath) || !File.Exists(threatsDbPath))
                {
                    if (_logger != null) _logger.LogWarning("Invalid bundle format: missing required files inside the archive.");
                    return result;
                }

                string manifestJson = File.ReadAllText(manifestPath, Encoding.UTF8);
                string signature = File.ReadAllText(signaturePath, Encoding.UTF8);

                // 1. Verify HMAC Signature
                string expectedSignature = ComputeHmacSha256(manifestJson, syncKey);
                if (!string.Equals(signature.Trim(), expectedSignature, StringComparison.OrdinalIgnoreCase))
                {
                    if (_logger != null) _logger.LogWarning($"HMAC signature verification failed for bundle: {bundlePath}. Rejecting.");
                    return result;
                }

                // 2. Parse Manifest values
                string sourceMachine = ExtractJsonValue(manifestJson, "SourceMachine");
                string exportTimestamp = ExtractJsonValue(manifestJson, "ExportTimestamp");
                string expectedDbHash = ExtractJsonValue(manifestJson, "ThreatsDbHash");

                long totalIocs = ParseJsonLong(manifestJson, "IocCount");
                long totalVulns = ParseJsonLong(manifestJson, "VulnerabilityCount");
                long totalYara = ParseJsonLong(manifestJson, "YaraCount");

                result.SourceMachine = sourceMachine;
                result.ExportTimestamp = exportTimestamp;

                // 3. Verify Database Integrity (SHA-256)
                string actualDbHash = ComputeSha256(threatsDbPath);
                if (!string.Equals(expectedDbHash, actualDbHash, StringComparison.OrdinalIgnoreCase))
                {
                    if (_logger != null) _logger.LogWarning($"Database SHA-256 mismatch for bundle: {bundlePath}. Expected {expectedDbHash}, got {actualDbHash}.");
                    return result;
                }

                long recordsImported = 0;
                long totalRecordsInBundle = totalIocs + totalVulns + totalYara;

                // 4. Execute INSERT OR IGNORE import strategy
                using (var conn = new SqliteConnection($"Data Source={_dbPath}"))
                {
                    conn.Open();
                    using (var transaction = conn.BeginTransaction())
                    {
                        using (var cmd = conn.CreateCommand())
                        {
                            cmd.Transaction = transaction;

                            // Attach the bundled snapshot
                            cmd.CommandText = $"ATTACH DATABASE '{threatsDbPath.Replace("'", "''")}' AS threats;";
                            cmd.ExecuteNonQuery();

                            // Import iocs (skipping the autoincrement PK to allow local IDs to generate naturally)
                            cmd.CommandText = @"
                                INSERT OR IGNORE INTO iocs (file_hash, malware_name, malware_family, confidence, source, detection_date)
                                SELECT file_hash, malware_name, malware_family, confidence, source, detection_date FROM threats.iocs;";
                            cmd.ExecuteNonQuery();
                            cmd.CommandText = "SELECT changes();";
                            recordsImported += (long)(cmd.ExecuteScalar() ?? 0L);

                            // Import vulnerabilities
                            cmd.CommandText = @"
                                INSERT OR IGNORE INTO vulnerabilities (id, product_name, affected_versions, cvss_score, severity, description, remediation, source, first_seen, last_updated)
                                SELECT id, product_name, affected_versions, cvss_score, severity, description, remediation, source, first_seen, last_updated FROM threats.vulnerabilities;";
                            cmd.ExecuteNonQuery();
                            cmd.CommandText = "SELECT changes();";
                            recordsImported += (long)(cmd.ExecuteScalar() ?? 0L);

                            // Import yara_rules_metadata if it was exported
                            cmd.CommandText = "SELECT COUNT(*) FROM threats.sqlite_master WHERE type='table' AND name='yara_rules_metadata';";
                            long yaraExists = (long)(cmd.ExecuteScalar() ?? 0L);
                            if (yaraExists > 0)
                            {
                                cmd.CommandText = "INSERT OR IGNORE INTO yara_rules_metadata SELECT * FROM threats.yara_rules_metadata;";
                                cmd.ExecuteNonQuery();
                                cmd.CommandText = "SELECT changes();";
                                recordsImported += (long)(cmd.ExecuteScalar() ?? 0L);
                            }

                            // Detach the bundled snapshot
                            cmd.CommandText = "DETACH DATABASE threats;";
                            cmd.ExecuteNonQuery();

                            // 5. Write to audit_log
                            string bundleHash = ComputeSha256(bundlePath);
                            cmd.CommandText = @"
                                INSERT INTO audit_log (source_machine, records_imported, bundle_hash)
                                VALUES (@sm, @ri, @bh);";
                            cmd.Parameters.AddWithValue("@sm", sourceMachine);
                            cmd.Parameters.AddWithValue("@ri", recordsImported);
                            cmd.Parameters.AddWithValue("@bh", bundleHash);
                            cmd.ExecuteNonQuery();
                        }
                        transaction.Commit();
                    }
                }

                result.RecordsImported = recordsImported;
                result.RecordsSkipped = totalRecordsInBundle - recordsImported;
                if (result.RecordsSkipped < 0) result.RecordsSkipped = 0;
                result.Success = true;

                if (_logger != null)
                {
                    _logger.LogInformation($"Successfully imported threat bundle from {sourceMachine}. Inserted {recordsImported}, Skipped {result.RecordsSkipped}.");
                }
            }
            catch (Exception ex)
            {
                if (_logger != null)
                {
                    _logger.LogError(ex, $"Error importing threat bundle: {bundlePath}");
                }
            }
            finally
            {
                try
                {
                    if (Directory.Exists(tmpDir))
                    {
                        Directory.Delete(tmpDir, true);
                    }
                }
                catch { }
            }

            return result;
        }

        private string ExtractJsonValue(string json, string key)
        {
            var match = Regex.Match(json, $"\"{key}\"\\s*:\\s*\"(.*?)\"");
            if (match.Success) return match.Groups[1].Value.Replace("\\\\", "\\").Replace("\\\"", "\"");
            return string.Empty;
        }

        private long ParseJsonLong(string json, string key)
        {
            var match = Regex.Match(json, $"\"{key}\"\\s*:\\s*(\\d+)");
            if (match.Success && long.TryParse(match.Groups[1].Value, out long val)) return val;
            return 0;
        }

        private string ComputeSha256(string filePath)
        {
            using (var sha256 = SHA256.Create())
            {
                using (var stream = File.OpenRead(filePath))
                {
                    byte[] hash = sha256.ComputeHash(stream);
                    StringBuilder sb = new StringBuilder();
                    foreach (byte b in hash)
                    {
                        sb.Append(b.ToString("x2"));
                    }
                    return sb.ToString();
                }
            }
        }

        private string ComputeHmacSha256(string data, string key)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            using (var hmac = new HMACSHA256(keyBytes))
            {
                byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
                StringBuilder sb = new StringBuilder();
                foreach (byte b in hash)
                {
                    sb.Append(b.ToString("x2"));
                }
                return sb.ToString();
            }
        }
    }
}
