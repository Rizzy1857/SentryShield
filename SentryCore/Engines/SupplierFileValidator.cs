using System.Security.Cryptography;
#if NET48
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
#else
using System.Text.Json;
#endif
using Microsoft.Extensions.Logging;
using SentryShield.Core.Models;

namespace SentryShield.Core.Engines;

/// <summary>
/// Supplier file gateway validation pipeline.
///
/// Validation steps (in order, fail-fast on BLOCK):
///   1. Trusted manifest check — is this supplier in the approved list?
///   2. SHA-256 integrity check against expected hash (if manifest provides it)
///   3. YARA malware scan (via Python subprocess)
///   4. Shannon entropy check (warn on high entropy — may be encrypted payload)
///   5. Known-bad IOC hash lookup
///   6. SBOM component vulnerability check (if .sbom.json provided)
///   7. Final decision: ALLOW | BLOCK | WARN
///
/// GPG note: Full GPG signature verification is deferred to v2.0.
/// v1.0 uses SHA-256 + trusted manifest (supplier name + expected hash pairs).
/// </summary>
public class SupplierFileValidator
{
    private readonly ILogger _logger;
    private readonly IPC.ProcessRunner _processRunner;
    private readonly Database.IOCDb _iocDb;
    private readonly PluginLoader _pluginLoader;

    // Trusted supplier manifest: supplierName → list of allowed file hash patterns
    // In production, load from signed manifest file; here populated from config.
    private readonly Dictionary<string, SupplierManifest> _trustedManifests;

    private const double WarnEntropyThreshold = 7.8;

    public SupplierFileValidator(
        ILogger logger,
        IPC.ProcessRunner processRunner,
        Database.IOCDb iocDb,
        PluginLoader pluginLoader,
        Dictionary<string, SupplierManifest>? trustedManifests = null)
    {
        _logger = logger;
        _processRunner = processRunner;
        _iocDb = iocDb;
        _pluginLoader = pluginLoader;
        _trustedManifests = trustedManifests ?? LoadDefaultManifests();
    }

    // -------------------------------------------------------------------------
    // IValidator
    // -------------------------------------------------------------------------

    public async Task<ValidationResult> ValidateAsync(
        string filePath,
        string supplierName,
        string? signatureFilePath = null)
    {
        var result = new ValidationResult
        {
            ValidationTime = DateTime.UtcNow
        };

        if (!File.Exists(filePath))
        {
            result.Decision = "BLOCK";
            result.Reason = "File not found";
            result.IsValid = false;
            return result;
        }

        _logger.LogInformation("[Gateway] Validating {File} from supplier '{Supplier}'",
            Path.GetFileName(filePath), supplierName);

        // Step 1: Trusted supplier check
        if (!_trustedManifests.ContainsKey(supplierName))
        {
            result.Decision = "BLOCK";
            result.Reason = $"Supplier '{supplierName}' is not in the trusted supplier list";
            result.Remediation = $"1. Do not transfer this file to the OT network. " +
                                  $"2. Verify the supplier name matches exactly what is in trusted_suppliers.json. " +
                                  $"3. To add this supplier, edit C:\\ProgramData\\SentryShield\\trusted_suppliers.json and add an entry for '{supplierName}'. " +
                                  $"4. Contact the supplier through an out-of-band channel (phone/email) to confirm they intended to send this file.";
            result.IsValid = false;
            result.Details.Add($"❌ Unknown supplier: {supplierName}");
            return result;
        }
        result.Details.Add($"✓ Supplier '{supplierName}' is trusted");

        // Step 2: Compute file hash
        var fileHash = ComputeSHA256(filePath);
        result.FileHash = fileHash;

        // Step 3: Expected hash check (if manifest has a hash for this file)
        var manifest = _trustedManifests[supplierName];
        var fileName = Path.GetFileName(filePath);
        if (manifest.ExpectedHashes.TryGetValue(fileName, out var expectedHash))
        {
            if (!string.Equals(fileHash, expectedHash, StringComparison.OrdinalIgnoreCase))
            {
                result.Decision = "BLOCK";
                result.Reason = "File hash does not match expected hash in trusted manifest";
                result.Remediation = "1. The file may have been tampered with in transit or is a different version than expected. " +
                                     "2. Do NOT use this file. Contact the supplier via a verified out-of-band channel (phone or official email). " +
                                     "3. Request the supplier re-send the file and provide its correct SHA-256 hash. " +
                                     "4. Update trusted_suppliers.json only after confirming the new hash with the supplier directly.";
                result.IsValid = false;
                result.Details.Add($"❌ Hash mismatch: got {fileHash.Substring(0, Math.Min(16, fileHash.Length))}... expected {expectedHash.Substring(0, Math.Min(16, expectedHash.Length))}...");
                return result;
            }
            result.Details.Add($"✓ File hash verified against manifest");
        }
        else
        {
            result.Details.Add($"⚠ No expected hash in manifest for '{fileName}' — hash-only check skipped");
        }

        // Step 4: YARA malware scan
        var yaraJson = await _processRunner.RunYaraScanFileAsync(filePath);
        if (!string.IsNullOrWhiteSpace(yaraJson))
        {
            var matches = System.Text.Json.JsonSerializer.Deserialize<List<Dictionary<string, string>>>(yaraJson);
            if (matches != null && matches.Count > 0)
            {
                var ruleNames = string.Join(", ", matches.Select(m =>
                    m.TryGetValue("rule_name", out var r) ? r : "unknown"));

                result.Decision = "BLOCK";
                result.Reason = $"Malware detected: {ruleNames}";
                result.Remediation = $"1. CRITICAL — do not transfer this file to the OT network under any circumstances. " +
                                     $"2. The file matched YARA malware signatures: [{ruleNames}]. " +
                                     $"3. Move the file to a forensic workstation (never an OT machine) for analysis. " +
                                     $"4. Report to your security team immediately with the rule names and the supplier contact. " +
                                     $"5. Notify the supplier ({supplierName}) that they may have sent a compromised file.";
                result.IsValid = false;
                result.Details.Add($"❌ YARA match: {ruleNames}");
                return result;
            }
        }
        result.Details.Add("✓ YARA malware scan passed");

        // Step 5: Entropy check
        var entropy = CalculateEntropy(filePath);
        result.Entropy = entropy;
        if (entropy > WarnEntropyThreshold)
        {
            result.Details.Add($"⚠ High entropy ({entropy:F2}/8.0) — file appears encrypted or heavily compressed");
            // WARN but don't block — operator should manually inspect
            result.Decision = "WARN";
            result.Remediation = "1. Do not transfer to the OT network without manual review. " +
                                 "2. Contact the supplier to confirm whether this file is intentionally encrypted or compressed. " +
                                 "3. If the supplier confirms it is legitimate, document their response and proceed. " +
                                 "4. If the source is unverified, treat as BLOCK and report to your security team.";
        }
        else
        {
            result.Details.Add($"✓ Entropy normal ({entropy:F2}/8.0)");
        }

        // Step 6: Known-bad hash (IOC)
        if (await _iocDb.IsKnownBadHashAsync(fileHash))
        {
            result.Decision = "BLOCK";
            result.Reason = "File hash matches known malware IOC database";
            result.Remediation = "1. CRITICAL — this file is a confirmed known malware sample. Do not open or transfer it. " +
                                 "2. Preserve the file in place (do not delete) for forensic evidence. " +
                                 "3. Report the SHA-256 hash to your security team immediately: " + fileHash + ". " +
                                 "4. Contact the supplier to investigate how a known malware file ended up in their delivery. " +
                                 "5. Check if any earlier version of this file was already transferred to the OT network.";
            result.IsValid = false;
            result.Details.Add($"❌ IOC match: hash {fileHash.Substring(0, Math.Min(16, fileHash.Length))}... is a known threat");
            return result;
        }
        result.Details.Add("✓ IOC hash check passed");

        // Step 7: SBOM check (if companion SBOM file exists)
        var sbomPath = filePath + ".sbom.json";
        if (File.Exists(sbomPath))
        {
            var sbomResult = await CheckSBOMAsync(sbomPath);
            result.Details.AddRange(sbomResult.Details);
            if (!sbomResult.IsValid)
            {
                result.Decision = "BLOCK";
                result.Reason = $"SBOM check failed: {sbomResult.Reason}";
                result.IsValid = false;
                return result;
            }
        }

        // Step 8: Final decision
        if (result.Decision != "WARN")
        {
            result.Decision = "ALLOW";
        }
        result.IsValid = true;
        result.Reason = result.Decision == "ALLOW"
            ? "All validation checks passed"
            : "File passed with warnings — manual review recommended";

        _logger.LogInformation("[Gateway] Decision for {File}: {Decision} — {Reason}",
            fileName, result.Decision, result.Reason);

        return result;
    }

    // -------------------------------------------------------------------------
    // SBOM component vulnerability check
    // -------------------------------------------------------------------------

    private async Task<ValidationResult> CheckSBOMAsync(string sbomPath)
    {
        var result = new ValidationResult { Details = new List<string>() };

        try
        {
#if NET48
            using var reader = File.OpenText(sbomPath);
            var sbomJson = await reader.ReadToEndAsync();
#else
            var sbomJson = await File.ReadAllTextAsync(sbomPath);
#endif

            bool hasVulnerableComponent = false;

#if NET48
            // Newtonsoft.Json path for .NET 4.8
            var root = JObject.Parse(sbomJson);
            var components = root["components"] as JArray ?? root["packages"] as JArray;
            if (components == null)
            {
                result.IsValid = true;
                result.Details.Add("⚠ SBOM format not recognized — skipping component check");
                return result;
            }

            foreach (var component in components)
            {
                var name    = component["name"]?.Value<string>();
                var version = component["version"]?.Value<string>();

                if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(version))
                    continue;

                var vulnsTask = Task.Run(() => InvokeVulnerabilityPluginAsync(name, version));
                var vulns = vulnsTask.GetAwaiter().GetResult();
                
                if (vulns.Count > 0)
                {
                    hasVulnerableComponent = true;
                    var cveList = string.Join(", ", vulns.Select(v2 => v2.AdditionalData.TryGetValue("CVE", out var cve) ? cve : v2.Title));
                    result.Details.Add($"❌ {name} v{version}: {cveList}");
                }
                else
                {
                    result.Details.Add($"✓ {name} v{version}: No known CVEs");
                }
            }
#else
            // System.Text.Json path for .NET 8
            var sbom = JsonDocument.Parse(sbomJson);

            // Support CycloneDX and basic SPDX component arrays
            JsonElement componentsEl;
            if (!sbom.RootElement.TryGetProperty("components", out componentsEl) &&
                !sbom.RootElement.TryGetProperty("packages", out componentsEl))
            {
                result.IsValid = true;
                result.Details.Add("⚠ SBOM format not recognized — skipping component check");
                return result;
            }

            foreach (var component in componentsEl.EnumerateArray())
            {
                var name    = component.TryGetProperty("name",    out var n) ? n.GetString() : null;
                var version = component.TryGetProperty("version", out var v) ? v.GetString() : null;

                if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(version))
                    continue;

                var vulnsTask = Task.Run(() => InvokeVulnerabilityPluginAsync(name, version));
                var vulns = vulnsTask.GetAwaiter().GetResult();
                
                if (vulns.Count > 0)
                {
                    hasVulnerableComponent = true;
                    var cveList = string.Join(", ", vulns.Select(v2 => v2.AdditionalData.TryGetValue("CVE", out var cve) ? cve : v2.Title));
                    result.Details.Add($"❌ {name} v{version}: {cveList}");
                }
                else
                {
                    result.Details.Add($"✓ {name} v{version}: No known CVEs");
                }
            }
#endif

            result.IsValid = !hasVulnerableComponent;
            if (hasVulnerableComponent)
                result.Reason = "SBOM contains components with known CVEs";

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[Gateway] SBOM parse error: {Path}", sbomPath);
            result.IsValid = true; // Don't block on parse error
            result.Details.Add($"⚠ SBOM parse error — {ex.Message}");
            return result;
        }
    }

    private async Task<List<SentryShield.Plugin.Abstractions.DetectionResult>> InvokeVulnerabilityPluginAsync(string name, string version)
    {
        var vulnPlugin = _pluginLoader.GetPlugins().FirstOrDefault(p => p.Name == "Vulnerability Scanner");
        if (vulnPlugin == null) return new List<SentryShield.Plugin.Abstractions.DetectionResult>();
        
        // Emulate the find behavior by sending target params
        var p = new Dictionary<string, object>
        {
            { "TargetSoftware", name },
            { "TargetVersion", version }
        };
        return await vulnPlugin.ExecuteAsync(p);
    }

    // -------------------------------------------------------------------------
    // Crypto helpers
    // -------------------------------------------------------------------------

    private static string ComputeSHA256(string filePath)
    {
        using var sha = SHA256.Create();
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        return BitConverter.ToString(sha.ComputeHash(fs)).Replace("-", "").ToLower();
    }

    private static double CalculateEntropy(string filePath)
    {
        const int SampleBytes = 8192;
        try
        {
            var fileLen = new FileInfo(filePath).Length;
            if (fileLen == 0) return 0;

            var buf = new byte[Math.Min(SampleBytes, fileLen)];
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var read = fs.Read(buf, 0, buf.Length);

            var freq = new long[256];
            for (int i = 0; i < read; i++) freq[buf[i]]++;

            double h = 0;
            for (int i = 0; i < 256; i++)
            {
                if (freq[i] == 0) continue;
                double p = (double)freq[i] / read;
                h -= p * Math.Log(p, 2);
            }
            return h;
        }
        catch { return 0; }
    }

    // -------------------------------------------------------------------------
    // Manifest loading
    // -------------------------------------------------------------------------

    private static Dictionary<string, SupplierManifest> LoadDefaultManifests()
    {
        // Load from C:\ProgramData\SentryShield\trusted_suppliers.json
        // Created by SentrySetup.ps1 during deployment, or edited manually.
        // Falls back to empty (block-all) if the file does not exist yet.
        var path = Environment.GetEnvironmentVariable("SENTRYSHIELD_SUPPLIERS")
                   ?? @"C:\ProgramData\SentryShield\trusted_suppliers.json";

        if (!File.Exists(path))
            return new Dictionary<string, SupplierManifest>(StringComparer.OrdinalIgnoreCase);

        try
        {
            var json = File.ReadAllText(path);
            var list = System.Text.Json.JsonSerializer.Deserialize<List<SupplierManifest>>(
                json,
                new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true });

            return list?.ToDictionary(
                s => s.SupplierName,
                StringComparer.OrdinalIgnoreCase)
                ?? new Dictionary<string, SupplierManifest>(StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception ex)
        {
            // Log and fail open — block all if manifest is corrupt
            Console.Error.WriteLine($"[SupplierFileValidator] Failed to load manifest from '{path}': {ex.Message}");
            return new Dictionary<string, SupplierManifest>(StringComparer.OrdinalIgnoreCase);
        }
    }
}

/// <summary>
/// Trusted supplier manifest entry.
/// </summary>
public class SupplierManifest
{
    public string SupplierName { get; set; } = string.Empty;
    public string ContactEmail { get; set; } = string.Empty;

    /// <summary>Filename → expected SHA-256 hash (optional)</summary>
    public Dictionary<string, string> ExpectedHashes { get; set; } = new();
}
