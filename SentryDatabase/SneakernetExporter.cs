using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;

namespace SentryShield.Database
{
    public class SneakernetExporter
    {
        private readonly string _dbPath;
        private readonly ILogger _logger;

        public SneakernetExporter(string dbPath, ILogger logger)
        {
            _dbPath = dbPath;
            _logger = logger;
        }

        public void ExportThreatBundle(string outputPath)
        {
            string? syncKey = Environment.GetEnvironmentVariable("SENTRY_SYNC_KEY");
            if (string.IsNullOrEmpty(syncKey))
            {
                throw new InvalidOperationException("SENTRY_SYNC_KEY environment variable is not set. Cannot export threat bundle.");
            }

            string tmpDir = Path.Combine(Path.GetTempPath(), "SentryExport_" + Guid.NewGuid().ToString("N"));
            string tmpZipPath = outputPath + ".tmp";

            try
            {
                Directory.CreateDirectory(tmpDir);

                string threatsDbPath = Path.Combine(tmpDir, "threats.db");
                long iocCount = 0;
                long vulnCount = 0;
                long yaraCount = 0;

                // 1. Create SQLite snapshot containing only the required tables
                using (var conn = new SqliteConnection($"Data Source={_dbPath}"))
                {
                    conn.Open();
                    using (var cmd = conn.CreateCommand())
                    {
                        cmd.CommandText = $"ATTACH DATABASE '{threatsDbPath.Replace("'", "''")}' AS threats;";
                        cmd.ExecuteNonQuery();

                        // Export iocs
                        cmd.CommandText = "CREATE TABLE threats.iocs AS SELECT * FROM iocs;";
                        cmd.ExecuteNonQuery();
                        cmd.CommandText = "SELECT COUNT(*) FROM threats.iocs;";
                        iocCount = (long)(cmd.ExecuteScalar() ?? 0L);

                        // Export vulnerabilities
                        cmd.CommandText = "CREATE TABLE threats.vulnerabilities AS SELECT * FROM vulnerabilities;";
                        cmd.ExecuteNonQuery();
                        cmd.CommandText = "SELECT COUNT(*) FROM threats.vulnerabilities;";
                        vulnCount = (long)(cmd.ExecuteScalar() ?? 0L);

                        // Export yara_rules_metadata if it exists
                        cmd.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='yara_rules_metadata';";
                        long yaraExists = (long)(cmd.ExecuteScalar() ?? 0L);
                        if (yaraExists > 0)
                        {
                            cmd.CommandText = "CREATE TABLE threats.yara_rules_metadata AS SELECT * FROM yara_rules_metadata;";
                            cmd.ExecuteNonQuery();
                            cmd.CommandText = "SELECT COUNT(*) FROM threats.yara_rules_metadata;";
                            yaraCount = (long)(cmd.ExecuteScalar() ?? 0L);
                        }

                        cmd.CommandText = "DETACH DATABASE threats;";
                        cmd.ExecuteNonQuery();
                    }
                }

                // 2. Compute SHA-256 of the extracted threats.db
                string threatsDbHash = ComputeSha256(threatsDbPath);

                // 3. Create manifest.json (manually serialized to remain strictly independent of JSON libraries across frameworks)
                string manifestPath = Path.Combine(tmpDir, "manifest.json");
                string timestamp = DateTime.UtcNow.ToString("o");
                string machineName = Environment.MachineName;

                string manifestJson = "{\n" +
                    $"  \"ExportTimestamp\": \"{timestamp}\",\n" +
                    $"  \"SourceMachine\": \"{EscapeJson(machineName)}\",\n" +
                    $"  \"IocCount\": {iocCount},\n" +
                    $"  \"VulnerabilityCount\": {vulnCount},\n" +
                    $"  \"YaraCount\": {yaraCount},\n" +
                    $"  \"ThreatsDbHash\": \"{threatsDbHash}\"\n" +
                    "}";

                File.WriteAllText(manifestPath, manifestJson, Encoding.UTF8);

                // 4. Create signature.sig (HMAC-SHA256 of manifest.json)
                string signaturePath = Path.Combine(tmpDir, "signature.sig");
                string signature = ComputeHmacSha256(manifestJson, syncKey);
                File.WriteAllText(signaturePath, signature, Encoding.UTF8);

                // 5. Compress to ZIP (.sentry format internally)
                if (File.Exists(tmpZipPath))
                {
                    File.Delete(tmpZipPath);
                }
                ZipFile.CreateFromDirectory(tmpDir, tmpZipPath, CompressionLevel.Optimal, false);

                // 6. Atomic write via rename
                if (File.Exists(outputPath))
                {
                    File.Delete(outputPath);
                }
                File.Move(tmpZipPath, outputPath);

                if (_logger != null)
                {
                    _logger.LogInformation($"Successfully exported threat bundle to {outputPath}");
                }
            }
            catch (Exception ex)
            {
                if (_logger != null)
                {
                    _logger.LogError(ex, $"Failed to export threat bundle to {outputPath}");
                }

                try
                {
                    if (File.Exists(tmpZipPath))
                    {
                        File.Delete(tmpZipPath);
                    }
                }
                catch { }
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

        private string EscapeJson(string str)
        {
            if (string.IsNullOrEmpty(str)) return "";
            return str.Replace("\\", "\\\\").Replace("\"", "\\\"");
        }
    }
}
