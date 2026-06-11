using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SentryShield.Database;

namespace SentryShield.Service
{
    public class UpdatePoller : BackgroundService
    {
        private readonly ILogger<UpdatePoller> _logger;
        private readonly IConfiguration _config;
        private readonly VulnerabilityDb _vulnDb;
        private readonly string _rulesDir;
        private readonly string _dbPath;

        public UpdatePoller(ILogger<UpdatePoller> logger, IConfiguration config, VulnerabilityDb vulnDb)
        {
            _logger = logger;
            _config = config;
            _vulnDb = vulnDb;

            string baseDir = AppContext.BaseDirectory;
            _dbPath = _config["Database:Path"] ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "SentryShield", "vulnerability.db");
            _rulesDir = _config["Yara:RulesPath"] ?? Path.Combine(baseDir, "rules");
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            string? baseUrl = _config["UpdateServer:BaseUrl"];
            if (string.IsNullOrWhiteSpace(baseUrl))
            {
                _logger.LogInformation("[UpdatePoller] UpdateServer:BaseUrl is not configured. Network update polling is completely disabled.");
                return; // Skip silently
            }

            baseUrl = baseUrl.TrimEnd('/');

            using var httpClient = new HttpClient { Timeout = TimeSpan.FromMinutes(5) };

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    await PollUpdatesAsync(httpClient, baseUrl, stoppingToken);
                }
                catch (Exception ex)
                {
                    // Never propagate exceptions to the service host
                    _logger.LogError(ex, "[UpdatePoller] Critical error during the update polling cycle. Suppressing exception to keep service alive.");
                }

                try
                {
                    await Task.Delay(TimeSpan.FromHours(6), stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
            }
        }

        private async Task PollUpdatesAsync(HttpClient client, string baseUrl, CancellationToken ct)
        {
            // 1. Fetch Version Info
            var versionResponse = await FetchWithIntegrityAsync(client, $"{baseUrl}/api/version", ct);
            if (versionResponse == null) return;

            using var doc = JsonDocument.Parse(versionResponse);
            var root = doc.RootElement;
            string remoteYaraVersion = root.GetProperty("yara_version").GetString() ?? "";
            string remoteDbVersion = root.GetProperty("db_version").GetString() ?? "";

            // 2. Evaluate and Update YARA Rules
            string localYaraPath = Path.Combine(_rulesDir, "malware.yar");
            string localYaraVersion = "unknown";
            if (File.Exists(localYaraPath))
            {
                localYaraVersion = File.GetLastWriteTimeUtc(localYaraPath).ToString("o");
            }

            if (remoteYaraVersion != "unknown" && remoteYaraVersion != localYaraVersion)
            {
                _logger.LogInformation("[UpdatePoller] New YARA rules available from Star Node. Downloading...");
                var yaraBytes = await FetchWithIntegrityAsync(client, $"{baseUrl}/api/yara", ct);
                
                if (yaraBytes != null && yaraBytes.Length > 0)
                {
                    if (!Directory.Exists(_rulesDir)) Directory.CreateDirectory(_rulesDir);
                    
                    // Atomic write
                    string tmpYara = localYaraPath + ".tmp";
                    File.WriteAllBytes(tmpYara, yaraBytes);
                    
                    if (File.Exists(localYaraPath)) File.Delete(localYaraPath);
                    File.Move(tmpYara, localYaraPath);
                    
                    _logger.LogInformation("[UpdatePoller] Successfully updated malware.yar atomically.");
                }
            }

            // 3. Evaluate and Update Vulnerability Database Delta
            string localDbVersion = GetLocalDbMaxTimestamp();
            if (remoteDbVersion != "unknown" && remoteDbVersion != localDbVersion)
            {
                _logger.LogInformation($"[UpdatePoller] New CVE delta available since {localDbVersion}. Requesting payload...");
                string queryUrl = $"{baseUrl}/api/cvedelta?since={Uri.EscapeDataString(localDbVersion)}";
                var deltaBytes = await FetchWithIntegrityAsync(client, queryUrl, ct);
                
                if (deltaBytes != null && deltaBytes.Length > 0)
                {
                    var records = ParseCveDelta(deltaBytes);
                    if (records != null && records.Count > 0)
                    {
                        int inserted = await _vulnDb.BulkUpsertAsync(records);
                        _logger.LogInformation($"[UpdatePoller] Successfully applied CVE delta. Upserted {inserted} records into local SQLite.");
                    }
                }
            }
        }

        private async Task<byte[]?> FetchWithIntegrityAsync(HttpClient client, string url, CancellationToken ct)
        {
            using var response = await client.GetAsync(url, ct);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning($"[UpdatePoller] Fetch failed for {url}. HTTP Status: {response.StatusCode}");
                return null;
            }

            byte[] data = await response.Content.ReadAsByteArrayAsync(ct);

            // Enforce SHA-256 Validation
            if (response.Headers.TryGetValues("Content-SHA256", out var values))
            {
                string expectedHash = values.FirstOrDefault() ?? "";
                using var sha256 = SHA256.Create();
                byte[] hashBytes = sha256.ComputeHash(data);
                string actualHash = BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();

                if (!string.Equals(expectedHash, actualHash, StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogError($"[UpdatePoller] CRITICAL: Integrity check failed for {url}. Expected SHA-256: {expectedHash}, Actual: {actualHash}. Payload has been rejected.");
                    return null;
                }
            }
            else
            {
                _logger.LogWarning($"[UpdatePoller] Response from {url} is missing Content-SHA256 header. This violates v2.7 integrity standards. Payload rejected.");
                return null;
            }

            return data;
        }

        private List<VulnerabilityDb.VulnerabilityRecord> ParseCveDelta(byte[] jsonBytes)
        {
            var records = new List<VulnerabilityDb.VulnerabilityRecord>();
            using var doc = JsonDocument.Parse(jsonBytes);
            
            if (doc.RootElement.ValueKind != JsonValueKind.Array) return records;

            foreach (var element in doc.RootElement.EnumerateArray())
            {
                records.Add(new VulnerabilityDb.VulnerabilityRecord
                {
                    Id = GetStringOrEmpty(element, "id"),
                    ProductName = GetStringOrEmpty(element, "product_name"),
                    AffectedVersions = GetStringOrEmpty(element, "affected_versions", "[]"),
                    CvssScore = GetDoubleOrZero(element, "cvss_score"),
                    Severity = GetStringOrEmpty(element, "severity", "MEDIUM"),
                    Description = GetStringOrEmpty(element, "description"),
                    Remediation = GetStringOrEmpty(element, "remediation"),
                    Source = GetStringOrEmpty(element, "source", "CURATED"),
                    FirstSeen = GetStringOrEmpty(element, "first_seen")
                });
            }
            return records;
        }

        private string GetStringOrEmpty(JsonElement el, string key, string def = "")
        {
            if (el.TryGetProperty(key, out var prop) && prop.ValueKind != JsonValueKind.Null)
            {
                return prop.GetString() ?? def;
            }
            return def;
        }

        private double GetDoubleOrZero(JsonElement el, string key)
        {
            if (el.TryGetProperty(key, out var prop) && prop.ValueKind != JsonValueKind.Null)
            {
                if (prop.ValueKind == JsonValueKind.Number && prop.TryGetDouble(out double d)) return d;
            }
            return 0;
        }

        private string GetLocalDbMaxTimestamp()
        {
            if (!File.Exists(_dbPath)) return "";

            try
            {
                using var conn = new SqliteConnection($"Data Source={_dbPath}");
                conn.Open();
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "SELECT MAX(last_updated) FROM vulnerabilities;";
                var res = cmd.ExecuteScalar();
                if (res != DBNull.Value && res != null)
                {
                    return res.ToString() ?? "";
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[UpdatePoller] Failed to query local DB max timestamp for delta calculation.");
            }
            return "";
        }
    }
}
