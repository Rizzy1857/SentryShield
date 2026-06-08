using System.Security.Cryptography;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;
using SentryShield.Core.Engines;
using SentryShield.Core.Models;
using SentryShield.Plugin.Abstractions;
using SentryShield.Core;

namespace SentryShield.Tests;

/// <summary>
/// Unit tests for SupplierFileValidator — the 7-step gateway pipeline.
///
/// What is tested:
///   Step 1  — Unknown supplier → immediate BLOCK
///   Step 2  — Known supplier → allowed through step 1
///   Step 3  — Hash mismatch against manifest → BLOCK
///   Step 3  — Hash matches manifest → passes
///   Step 4  — YARA match (via mock) → BLOCK
///   Step 5  — High entropy file → WARN (not BLOCK)
///   Step 6  — IOC hash match → BLOCK
///   Step 7  — SBOM with vulnerable component → BLOCK
///   Step 7  — SBOM with clean components → ALLOW
///   Edge    — Nonexistent file → BLOCK
///   Edge    — No hash in manifest (hash-only check skipped) → proceeds to YARA
///
/// WMI, real Python subprocesses, and real DB are replaced with test fakes.
/// </summary>
[TestFixture]
public class SupplierFileValidatorTests
{
    private string _testDir = string.Empty;
    private TestIOCDbV _iocDb = null!;
    private TestProcessRunner _processRunner = null!;
    private PluginLoader _pluginLoader = null!;
    private TestVulnPlugin _vulnPlugin = null!;
    private Dictionary<string, SupplierManifest> _manifests = null!;
    private SupplierFileValidator _validator = null!;

    private const string TrustedSupplier = "Siemens";
    private const string UnknownSupplier = "ShadyVendorCo";

    [SetUp]
    public void Setup()
    {
        _testDir = Path.Combine(Path.GetTempPath(), $"sentry_gw_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_testDir);

        _iocDb = new TestIOCDbV();
        _processRunner = new TestProcessRunner();
        
        _pluginLoader = new PluginLoader(NullLogger.Instance, ":memory:");
        _vulnPlugin = new TestVulnPlugin();
        _pluginLoader.AddPlugin(_vulnPlugin);

        _manifests = new Dictionary<string, SupplierManifest>(StringComparer.OrdinalIgnoreCase)
        {
            [TrustedSupplier] = new SupplierManifest
            {
                SupplierName = TrustedSupplier,
                ContactEmail = "security@siemens.com",
                ExpectedHashes = new()
            }
        };

        RebuildValidator();
    }

    [TearDown]
    public void Teardown()
    {
        _iocDb?.Dispose();
        if (Directory.Exists(_testDir))
            Directory.Delete(_testDir, recursive: true);
    }

    private void RebuildValidator()
    {
        _validator = new SupplierFileValidator(
            NullLogger.Instance,
            _processRunner,
            _iocDb,
            _pluginLoader,
            _manifests
        );
    }

    // ─────────────────────────────────────────────────────
    // Step 1: Trusted supplier check
    // ─────────────────────────────────────────────────────

    [Test]
    [Description("Unknown supplier must be immediately blocked before any file analysis")]
    public async Task Validate_UnknownSupplier_ShouldBlockImmediately()
    {
        var file = await CreateTestFile("payload.exe", new byte[] { 0x4D, 0x5A });

        var result = await _validator.ValidateAsync(file, UnknownSupplier);

        Assert.That(result.Decision, Is.EqualTo("BLOCK"));
        Assert.That(result.IsValid, Is.False);
        Assert.That(result.Reason, Does.Contain("not in the trusted supplier list").IgnoreCase);
    }

    [Test]
    [Description("Known supplier proceeds past step 1 — no immediate block")]
    public async Task Validate_KnownSupplier_ShouldPassStep1()
    {
        var file = await CreateTestFile("update.bin", new byte[64]);
        _processRunner.SetYaraResult("[]");

        var result = await _validator.ValidateAsync(file, TrustedSupplier);

        // Should not be blocked due to supplier — may be ALLOW or WARN but not supplier-BLOCK
        Assert.That(result.Reason, Does.Not.Contain("not in the trusted supplier list").IgnoreCase);
    }

    // ─────────────────────────────────────────────────────
    // Step 3: Hash manifest check
    // ─────────────────────────────────────────────────────

    [Test]
    [Description("File hash matching the manifest must pass the integrity check")]
    public async Task Validate_HashMatchesManifest_ShouldPassIntegrityCheck()
    {
        var file = await CreateTestFile("firmware_v2.bin", new byte[128]);
        var hash = ComputeSHA256(file);

        // Register correct hash in manifest
        _manifests[TrustedSupplier].ExpectedHashes["firmware_v2.bin"] = hash;
        RebuildValidator();

        _processRunner.SetYaraResult("[]");

        var result = await _validator.ValidateAsync(file, TrustedSupplier);

        Assert.That(result.Decision, Is.Not.EqualTo("BLOCK"));
        Assert.That(result.Details, Has.Some.Contains("hash verified").IgnoreCase);
    }

    [Test]
    [Description("File hash not matching manifest must be blocked with hash mismatch reason")]
    public async Task Validate_HashMismatch_ShouldBlock()
    {
        var file = await CreateTestFile("firmware_v2.bin", new byte[128]);

        // Register a WRONG expected hash
        _manifests[TrustedSupplier].ExpectedHashes["firmware_v2.bin"] =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        RebuildValidator();

        var result = await _validator.ValidateAsync(file, TrustedSupplier);

        Assert.That(result.Decision, Is.EqualTo("BLOCK"));
        Assert.That(result.Reason, Does.Contain("hash").IgnoreCase);
        Assert.That(result.IsValid, Is.False);
    }

    [Test]
    [Description("File with no manifest hash entry skips hash check and continues pipeline")]
    public async Task Validate_NoManifestHashForFile_ShouldSkipHashCheck()
    {
        // Manifest has no expected hash for this filename
        var file = await CreateTestFile("extras.pdf", new byte[64]);
        _processRunner.SetYaraResult("[]");

        var result = await _validator.ValidateAsync(file, TrustedSupplier);

        // Should have a note about skipped hash, but not blocked for it
        Assert.That(result.Details, Has.Some.Contains("hash").IgnoreCase);
        Assert.That(result.Decision, Is.Not.EqualTo("BLOCK").Or.Matches<string>(
            d => !result.Reason.Contains("hash", StringComparison.OrdinalIgnoreCase)));
    }

    // ─────────────────────────────────────────────────────
    // Step 4: YARA scan
    // ─────────────────────────────────────────────────────

    [Test]
    [Description("YARA match must immediately block the file with the rule name in reason")]
    public async Task Validate_YaraMatch_ShouldBlock()
    {
        var file = await CreateTestFile("dropper.exe", new byte[] { 0x4D, 0x5A });

        _processRunner.SetYaraResult("""
        [{"rule_name": "Mimikatz_Signature", "severity": "CRITICAL", "description": "Mimikatz detected"}]
        """);

        var result = await _validator.ValidateAsync(file, TrustedSupplier);

        Assert.That(result.Decision, Is.EqualTo("BLOCK"));
        Assert.That(result.Reason, Does.Contain("Mimikatz_Signature").IgnoreCase);
        Assert.That(result.IsValid, Is.False);
    }

    [Test]
    [Description("No YARA matches passes step 4 and continues the pipeline")]
    public async Task Validate_YaraNoMatch_ShouldPassStep4()
    {
        var file = await CreateTestFile("update.exe", new byte[] { 0x4D, 0x5A });
        _processRunner.SetYaraResult("[]");

        var result = await _validator.ValidateAsync(file, TrustedSupplier);

        Assert.That(result.Details, Has.Some.Contains("YARA").And.Contains("passed").IgnoreCase);
    }

    // ─────────────────────────────────────────────────────
    // Step 5: Entropy
    // ─────────────────────────────────────────────────────

    [Test]
    [Description("High-entropy file gets WARN decision — not blocked, but flagged for review")]
    public async Task Validate_HighEntropyFile_ShouldWarnNotBlock()
    {
        // Random bytes = high entropy
        var data = new byte[8192];
        RandomNumberGenerator.Fill(data);
        var file = await CreateTestFile("encrypted_payload.bin", data);

        _processRunner.SetYaraResult("[]");

        var result = await _validator.ValidateAsync(file, TrustedSupplier);

        Assert.That(result.Decision, Is.EqualTo("WARN").Or.EqualTo("ALLOW"),
            "High entropy should WARN, not BLOCK");
        Assert.That(result.IsValid, Is.True, "WARN is still valid — file is not blocked");
        Assert.That(result.Details, Has.Some.Contains("entropy").IgnoreCase);
    }

    // ─────────────────────────────────────────────────────
    // Step 6: IOC hash
    // ─────────────────────────────────────────────────────

    [Test]
    [Description("File with known-bad hash must be blocked even if YARA passes")]
    public async Task Validate_IOCHashMatch_ShouldBlock()
    {
        var file = await CreateTestFile("update.exe", new byte[] { 0x4D, 0x5A, 0x00, 0x01, 0x02, 0x03 });
        var hash = ComputeSHA256(file);
        _iocDb.RegisterBadHash(hash);

        _processRunner.SetYaraResult("[]"); // YARA clean — IOC should still catch it

        var result = await _validator.ValidateAsync(file, TrustedSupplier);

        Assert.That(result.Decision, Is.EqualTo("BLOCK"));
        Assert.That(result.Reason, Does.Contain("IOC").IgnoreCase);
        Assert.That(result.IsValid, Is.False);
    }

    // ─────────────────────────────────────────────────────
    // Step 7: SBOM check
    // ─────────────────────────────────────────────────────

    [Test]
    [Description("SBOM with a component matching a known CVE must block the file")]
    public async Task Validate_SBOMWithVulnerableComponent_ShouldBlock()
    {
        var file = await CreateTestFile("package.zip", new byte[] { 0x50, 0x4B, 0x03, 0x04 });

        // Write companion SBOM with a vulnerable component
        var sbomContent = """
        {
          "components": [
            {"name": "VulnerableLib", "version": "1.0.0"}
          ]
        }
        """;
        await File.WriteAllTextAsync(file + ".sbom.json", sbomContent);

        // Make the vuln plugin flag this component
        _vulnPlugin.AddVulnerableProduct("VulnerableLib", "1.0.0");

        _processRunner.SetYaraResult("[]");

        var result = await _validator.ValidateAsync(file, TrustedSupplier);

        Assert.That(result.Decision, Is.EqualTo("BLOCK"));
        Assert.That(result.Reason, Does.Contain("SBOM").IgnoreCase);
        Assert.That(result.IsValid, Is.False);
    }

    [Test]
    [Description("SBOM with all clean components must pass step 7 and reach ALLOW")]
    public async Task Validate_SBOMWithCleanComponents_ShouldAllow()
    {
        var file = await CreateTestFile("package.zip", new byte[] { 0x50, 0x4B, 0x03, 0x04 });

        var sbomContent = """
        {
          "components": [
            {"name": "SafeLib", "version": "2.0.0"}
          ]
        }
        """;
        await File.WriteAllTextAsync(file + ".sbom.json", sbomContent);

        // vuln matcher returns nothing for SafeLib 2.0.0
        _processRunner.SetYaraResult("[]");

        var result = await _validator.ValidateAsync(file, TrustedSupplier);

        Assert.That(result.Decision, Is.EqualTo("ALLOW").Or.EqualTo("WARN"));
        Assert.That(result.IsValid, Is.True);
    }

    // ─────────────────────────────────────────────────────
    // Edge cases
    // ─────────────────────────────────────────────────────

    [Test]
    [Description("Non-existent file must be blocked immediately with 'File not found' reason")]
    public async Task Validate_NonExistentFile_ShouldBlock()
    {
        var result = await _validator.ValidateAsync(
            @"C:\DoesNotExist\file.exe", TrustedSupplier);

        Assert.That(result.Decision, Is.EqualTo("BLOCK"));
        Assert.That(result.Reason, Does.Contain("not found").IgnoreCase);
        Assert.That(result.IsValid, Is.False);
    }

    [Test]
    [Description("Clean file from trusted supplier with no manifest hash should be ALLOWED")]
    public async Task Validate_CleanTrustedFile_ShouldAllow()
    {
        // Low entropy, valid MZ header, no IOC, no YARA
        var data = new byte[512];
        data[0] = 0x4D; // MZ
        data[1] = 0x5A;
        var file = await CreateTestFile("driver.exe", data);

        _processRunner.SetYaraResult("[]");

        var result = await _validator.ValidateAsync(file, TrustedSupplier);

        Assert.That(result.Decision, Is.EqualTo("ALLOW").Or.EqualTo("WARN"));
        Assert.That(result.IsValid, Is.True);
        Assert.That(result.FileHash, Has.Length.EqualTo(64), "FileHash must be 64-char SHA-256 hex");
    }

    [Test]
    [Description("FileHash property is always populated in the result")]
    public async Task Validate_ResultAlwaysContainsFileHash()
    {
        var file = await CreateTestFile("check.bin", new byte[64]);
        _processRunner.SetYaraResult("[]");

        var result = await _validator.ValidateAsync(file, TrustedSupplier);

        Assert.That(result.FileHash, Is.Not.Null.And.Not.Empty);
        Assert.That(result.FileHash.Length, Is.EqualTo(64)); // SHA-256 hex string
    }

    // ─────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────

    private async Task<string> CreateTestFile(string name, byte[] content)
    {
        var path = Path.Combine(_testDir, name);
        await File.WriteAllBytesAsync(path, content);
        return path;
    }

    private static string ComputeSHA256(string filePath)
    {
        using var sha = SHA256.Create();
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read);
        return BitConverter.ToString(sha.ComputeHash(fs)).Replace("-", "").ToLower();
    }
}

// ─────────────────────────────────────────────────────
// Test doubles
// ─────────────────────────────────────────────────────

/// <summary>In-memory IOC DB for SupplierFileValidator tests.</summary>
internal class TestIOCDbV : Database.IOCDb
{
    private readonly HashSet<string> _bad = new(StringComparer.OrdinalIgnoreCase);

    public TestIOCDbV() : base(NullLogger.Instance, ":memory:") { }

    public void RegisterBadHash(string hash) => _bad.Add(hash);

    public override Task<bool> IsKnownBadHashAsync(string sha256)
        => Task.FromResult(_bad.Contains(sha256));
}


/// <summary>
/// Fake Vulnerability Plugin — returns configurable matches without needing a DB.
/// </summary>
internal class TestVulnPlugin : IDetectionPlugin
{
    public string Name => "Vulnerability Scanner";
    public string Version => "Test";

    private readonly Dictionary<(string, string), List<DetectionResult>> _matches = new();

    public void Initialize(PluginContext context) { }

    public void AddVulnerableProduct(string product, string version)
    {
        _matches[(product.ToLower(), version)] = new List<DetectionResult>
        {
            new DetectionResult
            {
                Title = "TEST-CVE-001 - " + product,
                Severity = "CRITICAL",
                Description = "Test vulnerability",
                Remediation = "Update immediately",
                Target = "",
                AdditionalData = new Dictionary<string, string> { { "CVE", "TEST-CVE-001" }, { "InstalledVersion", version } }
            }
        };
    }

    public Task<List<DetectionResult>> ExecuteAsync(Dictionary<string, object> parameters)
    {
        if (parameters.TryGetValue("TargetSoftware", out var sw) && parameters.TryGetValue("TargetVersion", out var ver)
            && sw is string p && ver is string v)
        {
            var key = (p.ToLower(), v);
            return Task.FromResult(_matches.TryGetValue(key, out var list) ? list : new List<DetectionResult>());
        }
        return Task.FromResult(new List<DetectionResult>());
    }
}
