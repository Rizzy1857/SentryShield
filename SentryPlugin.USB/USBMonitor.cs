using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;

namespace SentryShield.Plugin.USB
{
    public class USBThreat
    {
        public string ThreatType { get; set; } = string.Empty;
        public string DevicePath { get; set; } = string.Empty;
        public string FilePath { get; set; } = string.Empty;
        public string FileName { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Remediation { get; set; } = string.Empty;
        public string Severity { get; set; } = string.Empty;
    }

    public class USBMonitor
    {
        private readonly ILogger _logger;
        private readonly string _globalDbPath;

        private static readonly Dictionary<string, byte[][]> MagicSignatures = new(StringComparer.OrdinalIgnoreCase)
        {
            [".exe"] = new[] { new byte[] { 0x4D, 0x5A } },
            [".dll"] = new[] { new byte[] { 0x4D, 0x5A } },
            [".sys"] = new[] { new byte[] { 0x4D, 0x5A } },
            [".zip"] = new[] { new byte[] { 0x50, 0x4B, 0x03, 0x04 } },
            [".7z"]  = new[] { new byte[] { 0x37, 0x7A, 0xBC, 0xAF } },
            [".rar"] = new[] { new byte[] { 0x52, 0x61, 0x72, 0x21 } },
            [".pdf"] = new[] { new byte[] { 0x25, 0x50, 0x44, 0x46 } },
            [".jpg"] = new[] { new byte[] { 0xFF, 0xD8, 0xFF } },
            [".png"] = new[] { new byte[] { 0x89, 0x50, 0x4E, 0x47 } },
            [".doc"] = new[] { new byte[] { 0xD0, 0xCF, 0x11, 0xE0 } },
            [".xls"] = new[] { new byte[] { 0xD0, 0xCF, 0x11, 0xE0 } },
            [".docx"] = new[] { new byte[] { 0x50, 0x4B } },
            [".xlsx"] = new[] { new byte[] { 0x50, 0x4B } },
        };

        private const double HighEntropyThreshold = 7.5;
        private static readonly HashSet<string> HighEntropyExemptExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".bin", ".fw", ".hex", ".img", ".enc", ".dat"
        };

        public USBMonitor(ILogger logger, string globalDbPath)
        {
            _logger = logger;
            _globalDbPath = globalDbPath;
        }

        public Func<string, Task<string>>? MockYaraRunner { get; set; }

        public async Task<List<USBThreat>> ScanUSBDriveAsync(string drivePath)
        {
            _logger.LogInformation("[USBPlugin] Scanning USB drive: {Path}", drivePath);
            var allThreats = new List<USBThreat>();

            string[] files;
            try
            {
                files = Directory.GetFiles(drivePath, "*.*", SearchOption.AllDirectories);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[USBPlugin] Cannot enumerate drive: {Path}", drivePath);
                return allThreats;
            }

            var yaraThreats = await RunYaraScanAsync(drivePath);
            allThreats.AddRange(yaraThreats);

            foreach (var file in files)
            {
                try
                {
                    var fileThreats = await AnalyzeFileAsync(file, drivePath);
                    allThreats.AddRange(fileThreats);
                }
                catch (UnauthorizedAccessException) { }
                catch (Exception ex) { _logger.LogWarning(ex, "[USBPlugin] Error analyzing file: {File}", file); }
            }

            return allThreats;
        }

        private async Task<List<USBThreat>> RunYaraScanAsync(string drivePath)
        {
            var threats = new List<USBThreat>();
            var baseDir = AppDomain.CurrentDomain.BaseDirectory;
            var solutionDir = Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", ".."));
            var pythonPath = "python";
            var scriptPath = Path.Combine(solutionDir, "SentryPython", "yara_scanner.py");
            var rulesDir = Path.Combine(solutionDir, "rules");

            try
            {
                string output;
                if (MockYaraRunner != null)
                {
                    output = await MockYaraRunner(drivePath);
                }
                else
                {
                    if (!File.Exists(scriptPath))
                    {
                        _logger.LogWarning("[USBPlugin] Python or yara_scanner.py not found.");
                        return threats;
                    }

                    var args = $"\"{scriptPath}\" \"{rulesDir}\" \"{drivePath}\"";
                    var psi = new ProcessStartInfo
                    {
                        FileName = pythonPath,
                        Arguments = args,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };

                    using var process = Process.Start(psi);
                    if (process == null) return threats;

                    output = await process.StandardOutput.ReadToEndAsync();
                    await Task.Run(() => process.WaitForExit());
                }

                if (string.IsNullOrWhiteSpace(output)) return threats;

#if NET48
                var matches = Newtonsoft.Json.JsonConvert.DeserializeObject<List<YaraMatch>>(output);
#else
                var matches = System.Text.Json.JsonSerializer.Deserialize<List<YaraMatch>>(output);
#endif
                if (matches == null) return threats;

                foreach (var match in matches)
                {
                    threats.Add(new USBThreat
                    {
                        ThreatType = "Malware",
                        DevicePath = drivePath,
                        FilePath = match.FilePath,
                        FileName = Path.GetFileName(match.FilePath),
                        Description = match.Description,
                        Remediation = $"Detected by YARA rule: {match.RuleName}. Eject USB immediately.",
                        Severity = match.Severity
                    });
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[USBPlugin] YARA scan failed");
            }

            return threats;
        }

        private async Task<List<USBThreat>> AnalyzeFileAsync(string filePath, string drivePath)
        {
            var threats = new List<USBThreat>();
            var ext = Path.GetExtension(filePath).ToLower();

            bool isEntropyExempt = HighEntropyExemptExtensions.Contains(ext);
            var entropy = CalculateEntropy(filePath);

            if (!isEntropyExempt && entropy > HighEntropyThreshold)
            {
                threats.Add(new USBThreat
                {
                    ThreatType = "Entropy",
                    DevicePath = drivePath,
                    FilePath = filePath,
                    FileName = Path.GetFileName(filePath),
                    Description = $"High entropy ({entropy:F2}/8.0)",
                    Remediation = "File may be encrypted/packed. Quarantine.",
                    Severity = "MEDIUM"
                });
            }

            if (!string.IsNullOrEmpty(ext))
            {
                var magicBytes = ReadMagicBytes(filePath);
                bool isExecutableExtension = ext is ".exe" or ".dll" or ".sys" or ".com" or ".scr";
                bool hasMzHeader = magicBytes.Length >= 2 && magicBytes[0] == 0x4D && magicBytes[1] == 0x5A;

                if (hasMzHeader && !isExecutableExtension)
                {
                    threats.Add(new USBThreat
                    {
                        ThreatType = "Suspicious",
                        DevicePath = drivePath,
                        FilePath = filePath,
                        FileName = Path.GetFileName(filePath),
                        Description = $"Executable disguise: '{ext}' file has a Windows PE (MZ) header",
                        Remediation = "Possible renamed malware. Quarantine.",
                        Severity = "HIGH"
                    });
                }
                else if (!isEntropyExempt && !IsMagicByteMatch(magicBytes, ext))
                {
                    threats.Add(new USBThreat
                    {
                        ThreatType = "Suspicious",
                        DevicePath = drivePath,
                        FilePath = filePath,
                        FileName = Path.GetFileName(filePath),
                        Description = $"Extension mismatch: '{ext}'",
                        Remediation = "Verify file type. Quarantine.",
                        Severity = "MEDIUM"
                    });
                }
            }

            var hash = ComputeSHA256(filePath);
            if (!string.IsNullOrEmpty(hash) && IsKnownBadHash(hash))
            {
                threats.Add(new USBThreat
                {
                    ThreatType = "IOC",
                    DevicePath = drivePath,
                    FilePath = filePath,
                    FileName = Path.GetFileName(filePath),
                    Description = $"File hash {hash.Substring(0, 16)}... matches known malware",
                    Remediation = "CRITICAL: Malware matched known IOC.",
                    Severity = "CRITICAL"
                });
            }

            return await Task.FromResult(threats);
        }

        private bool IsKnownBadHash(string hash)
        {
            try
            {
                using var conn = new SqliteConnection($"Data Source={_globalDbPath}");
                conn.Open();
                var cmd = conn.CreateCommand();
                cmd.CommandText = "SELECT COUNT(1) FROM iocs WHERE hash = @hash";
                cmd.Parameters.AddWithValue("@hash", hash);
                var count = Convert.ToInt32(cmd.ExecuteScalar());
                return count > 0;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[USBPlugin] Failed to check IOC DB");
                return false;
            }
        }

        private static double CalculateEntropy(string filePath)
        {
            try
            {
                var fileLen = new FileInfo(filePath).Length;
                if (fileLen == 0) return 0;
                var bytes = new byte[Math.Min(4096, fileLen)];
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                var read = fs.Read(bytes, 0, bytes.Length);

                var freq = new long[256];
                for (int i = 0; i < read; i++) freq[bytes[i]]++;

                double entropy = 0;
                for (int i = 0; i < 256; i++)
                {
                    if (freq[i] == 0) continue;
                    double p = (double)freq[i] / read;
                    entropy -= p * Math.Log(p, 2);
                }
                return entropy;
            }
            catch { return 0; }
        }

        private static byte[] ReadMagicBytes(string filePath, int count = 8)
        {
            try
            {
                var buf = new byte[count];
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                int bytesRead = fs.Read(buf, 0, count);
                if (bytesRead < count) Array.Resize(ref buf, bytesRead);
                return buf;
            }
            catch { return Array.Empty<byte>(); }
        }

        private static bool IsMagicByteMatch(byte[] actual, string extension)
        {
            if (!MagicSignatures.TryGetValue(extension, out var expectedSigs)) return true;
            if (actual.Length == 0) return true;
            return expectedSigs.Any(sig => actual.Length >= sig.Length && actual.Take(sig.Length).SequenceEqual(sig));
        }

        private static string ComputeSHA256(string filePath)
        {
            try
            {
                using var sha = System.Security.Cryptography.SHA256.Create();
                using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                var hash = sha.ComputeHash(fs);
                return BitConverter.ToString(hash).Replace("-", "").ToLower();
            }
            catch { return string.Empty; }
        }

        private class YaraMatch
        {
#if NET48
            [Newtonsoft.Json.JsonProperty("file_path")]
#else
            [System.Text.Json.Serialization.JsonPropertyName("file_path")]
#endif
            public string FilePath { get; set; } = string.Empty;

#if NET48
            [Newtonsoft.Json.JsonProperty("rule_name")]
#else
            [System.Text.Json.Serialization.JsonPropertyName("rule_name")]
#endif
            public string RuleName { get; set; } = string.Empty;

#if NET48
            [Newtonsoft.Json.JsonProperty("severity")]
#else
            [System.Text.Json.Serialization.JsonPropertyName("severity")]
#endif
            public string Severity { get; set; } = string.Empty;

#if NET48
            [Newtonsoft.Json.JsonProperty("description")]
#else
            [System.Text.Json.Serialization.JsonPropertyName("description")]
#endif
            public string Description { get; set; } = string.Empty;
        }
    }
}
