using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

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

            // 1. Notify User
            ShowToastNotification("USB Detected", "Scanning before use...");

            // 2. Lock Down
            SetGlobalUsbWriteProtect(true);
            LockDriveExecution(drivePath);

            var allThreats = new List<USBThreat>();

            string[] files = Array.Empty<string>();
            try
            {
                files = Directory.GetFiles(drivePath, "*.*", SearchOption.AllDirectories);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[USBPlugin] Cannot enumerate drive: {Path}", drivePath);
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

            // 3. Post-scan decision
            if (allThreats.Count == 0)
            {
                UnlockDriveExecution(drivePath);
                SetGlobalUsbWriteProtect(false);
                ShowToastNotification("USB Cleared", "No threats found. Safe to use.");
            }
            else
            {
                // Leave WriteProtect and ACL Deny active
                ShowToastNotification("USB Blocked", "Threats found! Drive remains locked.");
            }

            return allThreats;
        }

        // -------------------------------------------------------------------------
        // Auto-Block Helpers
        // -------------------------------------------------------------------------

        private void SetGlobalUsbWriteProtect(bool enable)
        {
            if (!System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows)) return;
            try
            {
                using var key = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies");
                key.SetValue("WriteProtect", enable ? 1 : 0, RegistryValueKind.DWord);
                _logger.LogInformation("[USBPlugin] Global USB WriteProtect set to {State}", enable);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[USBPlugin] Failed to toggle USB WriteProtect (requires Administrator)");
            }
        }

        private void LockDriveExecution(string drivePath)
        {
            if (!System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows)) return;
            try
            {
                var dInfo = new DirectoryInfo(drivePath);
                var security = dInfo.GetAccessControl();
                var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
                security.AddAccessRule(new FileSystemAccessRule(everyone, FileSystemRights.ExecuteFile, AccessControlType.Deny));
                dInfo.SetAccessControl(security);
                _logger.LogInformation("[USBPlugin] Drive execution locked via ACL: {Path}", drivePath);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[USBPlugin] Failed to lock drive execution: {Path}", drivePath);
            }
        }

        private void UnlockDriveExecution(string drivePath)
        {
            if (!System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows)) return;
            try
            {
                var dInfo = new DirectoryInfo(drivePath);
                var security = dInfo.GetAccessControl();
                var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
                security.RemoveAccessRule(new FileSystemAccessRule(everyone, FileSystemRights.ExecuteFile, AccessControlType.Deny));
                dInfo.SetAccessControl(security);
                _logger.LogInformation("[USBPlugin] Drive execution unlocked via ACL: {Path}", drivePath);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[USBPlugin] Failed to unlock drive execution: {Path}", drivePath);
            }
        }

        private void ShowToastNotification(string title, string message)
        {
            if (!System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform(System.Runtime.InteropServices.OSPlatform.Windows)) return;
            try
            {
                System.Diagnostics.EventLog.WriteEntry(
                    "SentryShield",
                    $"{title} - {message}",
                    System.Diagnostics.EventLogEntryType.Information,
                    2001);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "[USBPlugin] Failed to display toast notification");
            }
        }

        private async Task<List<USBThreat>> RunYaraScanAsync(string drivePath)
        {
            var threats = new List<USBThreat>();

            try
            {
                string output;
                if (MockYaraRunner != null)
                {
                    output = await MockYaraRunner(drivePath);
                }
                else
                {
                    // Resolve paths: prefer scripts/ copied next to the executable first,
                    // then fall back to the source tree (dev environment).
                    var baseDir = AppDomain.CurrentDomain.BaseDirectory;
                    var localScript = Path.Combine(baseDir, "scripts", "yara_scanner.py");
                    var localRules  = Path.Combine(baseDir, "rules");

                    // Source-tree fallback (4 levels up from bin/Debug/net8.0-windows/)
                    var solutionDir  = Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", ".."));
                    var sourceScript = Path.Combine(solutionDir, "SentryPython", "yara_scanner.py");
                    var sourceRules  = Path.Combine(solutionDir, "rules");

                    var scriptPath = File.Exists(localScript) ? localScript : sourceScript;
                    var rulesDir   = Directory.Exists(localRules) ? localRules : sourceRules;

                    if (!File.Exists(scriptPath))
                    {
                        _logger.LogWarning("[USBPlugin] yara_scanner.py not found at '{Local}' or '{Source}'. Skipping YARA scan.",
                            localScript, sourceScript);
                        return threats;
                    }

                    if (!Directory.Exists(rulesDir))
                    {
                        _logger.LogWarning("[USBPlugin] YARA rules directory not found at '{Rules}'. Skipping YARA scan.", rulesDir);
                        return threats;
                    }

                    // Try local virtual environment first, then fallback to system Python.
                    var venvWin = Path.Combine(solutionDir, "SentryPython", "venv", "Scripts", "python.exe");
                    var venvMac = Path.Combine(solutionDir, "SentryPython", "venv", "bin", "python");

                    string? pythonExe = null;
                    var candidates = new[] { venvWin, venvMac, "py", "python", "python3" };

                    foreach (var candidate in candidates)
                    {
                        try
                        {
                            var probe = new ProcessStartInfo
                            {
                                FileName = candidate,
                                Arguments = "--version",
                                RedirectStandardOutput = true,
                                RedirectStandardError = true,
                                UseShellExecute = false,
                                CreateNoWindow = true
                            };
                            using var p = Process.Start(probe);
                            if (p != null) { p.WaitForExit(2000); pythonExe = candidate; break; }
                        }
                        catch { /* not found, try next */ }
                    }

                    if (pythonExe == null)
                    {
                        _logger.LogWarning("[USBPlugin] No Python interpreter found (tried py, python, python3). Skipping YARA scan.");
                        return threats;
                    }

                    // Use the proper named-argument CLI format that yara_scanner.py expects.
                    var args = $"\"{scriptPath}\" --scan-dir \"{drivePath}\" --rules \"{rulesDir}\" --json";

                    var psi = new ProcessStartInfo
                    {
                        FileName = pythonExe,
                        Arguments = args,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        UseShellExecute = false,
                        CreateNoWindow = true
                    };

                    using var process = Process.Start(psi);
                    if (process == null) return threats;

                    // Read stdout (JSON) and stderr (logs) concurrently to avoid deadlock
                    // on processes that write large amounts to either stream.
                    var stdoutTask = process.StandardOutput.ReadToEndAsync();
                    var stderrTask = process.StandardError.ReadToEndAsync();
                    await Task.WhenAll(stdoutTask, stderrTask);
                    await Task.Run(() => process.WaitForExit());

                    output = stdoutTask.Result;
                    var stderr = stderrTask.Result;

                    if (!string.IsNullOrWhiteSpace(stderr))
                        _logger.LogDebug("[USBPlugin] YARA stderr: {Err}", stderr.Trim());

                    if (process.ExitCode != 0)
                    {
                        _logger.LogWarning("[USBPlugin] yara_scanner.py exited with code {Code}. Stderr: {Err}",
                            process.ExitCode, stderr.Trim());
                        return threats;
                    }
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
                cmd.CommandText = "SELECT COUNT(1) FROM iocs WHERE file_hash = @hash";
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
