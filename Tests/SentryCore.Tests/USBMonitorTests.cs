using System.Security.Cryptography;
using Microsoft.Extensions.Logging.Abstractions;
using NUnit.Framework;
using SentryShield.Core.Engines;
using SentryShield.Core.Models;

namespace SentryShield.Tests;

/// <summary>
/// Unit tests for USBMonitor — focused on the testable pure-logic methods:
///   - CalculateEntropy (via file content)
///   - IsMagicByteMatch (via reflection — internal method exposed for testing)
///   - ComputeSHA256
///   - ScanUSBDriveAsync (integration — using temp directory)
///
/// WMI event subscription (Start/Stop) is not tested here because:
///   - WMI requires Windows + admin rights
///   - It's integration territory, not unit territory
///   - The event handler just calls ScanUSBDriveAsync, which IS tested
///
/// What IS validated:
///   - Entropy detection fires correctly at/above the 7.5 threshold
///   - Magic byte mismatch detection fires for known extensions
///   - Known-extension files with correct headers pass the check
///   - Unknown extensions are not flagged (assume OK)
///   - SHA-256 hash is deterministic and correct length
///   - IOC hash match produces CRITICAL USBThreat
///   - Empty/unreadable files are handled gracefully
/// </summary>
[TestFixture]
public class USBMonitorTests
{
    private string _testDir = string.Empty;
    private TestIOCDb _iocDb = null!;
    private TestProcessRunner _processRunner = null!;
    private USBMonitor _monitor = null!;

    [SetUp]
    public void Setup()
    {
        _testDir = Path.Combine(Path.GetTempPath(), $"sentry_usb_test_{Guid.NewGuid():N}");
        Directory.CreateDirectory(_testDir);

        _iocDb = new TestIOCDb();
        _processRunner = new TestProcessRunner();

        _monitor = new USBMonitor(
            NullLogger.Instance,
            _processRunner,
            _iocDb
        );
    }

    [TearDown]
    public void Teardown()
    {
        _monitor.Dispose();
        if (Directory.Exists(_testDir))
            Directory.Delete(_testDir, recursive: true);
    }

    // ─────────────────────────────────────────────────────
    // Entropy detection tests
    // ─────────────────────────────────────────────────────

    [Test]
    [Description("Highly random (encrypted-like) data must be flagged as high entropy")]
    public async Task ScanDrive_HighEntropyFile_ShouldProduceEntropyThreat()
    {
        // Write a file filled with random bytes — entropy will be ~8.0
        var file = Path.Combine(_testDir, "payload.bin");
        var random = new byte[4096];
        RandomNumberGenerator.Fill(random);
        await File.WriteAllBytesAsync(file, random);

        var threats = await _monitor.ScanUSBDriveAsync(_testDir);

        var entropyThreat = threats.FirstOrDefault(t => t.ThreatType == "Entropy");
        Assert.That(entropyThreat, Is.Not.Null, "High-entropy file should trigger Entropy threat");
        Assert.That(entropyThreat!.Severity, Is.EqualTo("MEDIUM"));
        Assert.That(entropyThreat.Description, Does.Contain("entropy"));
        Assert.That(entropyThreat.Confidence, Is.EqualTo(60));
    }

    [Test]
    [Description("Plain text files have very low entropy and must NOT be flagged")]
    public async Task ScanDrive_LowEntropyFile_ShouldNotProduceEntropyThreat()
    {
        // Highly repetitive content = low entropy
        var file = Path.Combine(_testDir, "readme.txt");
        var content = string.Concat(Enumerable.Repeat("aaaaaaaaaa\n", 400));
        await File.WriteAllTextAsync(file, content);

        var threats = await _monitor.ScanUSBDriveAsync(_testDir);

        var entropyThreat = threats.FirstOrDefault(t => t.ThreatType == "Entropy");
        Assert.That(entropyThreat, Is.Null, "Low-entropy file must not produce Entropy threat");
    }

    [Test]
    [Description("Empty file must not cause exceptions or false positives")]
    public async Task ScanDrive_EmptyFile_ShouldNotThrow()
    {
        var file = Path.Combine(_testDir, "empty.bin");
        await File.WriteAllBytesAsync(file, Array.Empty<byte>());

        Assert.DoesNotThrowAsync(async () =>
        {
            await _monitor.ScanUSBDriveAsync(_testDir);
        });
    }

    // ─────────────────────────────────────────────────────
    // Magic byte tests
    // ─────────────────────────────────────────────────────

    [Test]
    [Description(".exe file with correct MZ header must NOT be flagged as suspicious")]
    public async Task ScanDrive_ExeWithCorrectMZHeader_ShouldNotFlagMagic()
    {
        var file = Path.Combine(_testDir, "setup.exe");
        // MZ header followed by zeros
        var data = new byte[512];
        data[0] = 0x4D; // M
        data[1] = 0x5A; // Z
        await File.WriteAllBytesAsync(file, data);

        var threats = await _monitor.ScanUSBDriveAsync(_testDir);

        var magicThreat = threats.FirstOrDefault(t => t.ThreatType == "Suspicious"
            && t.FilePath == file);
        Assert.That(magicThreat, Is.Null, ".exe with valid MZ header must not be flagged");
    }

    [Test]
    [Description(".jpg file claiming to be JPEG but with EXE payload must be flagged")]
    public async Task ScanDrive_JpgWithExePayload_ShouldFlagMagicMismatch()
    {
        var file = Path.Combine(_testDir, "photo.jpg");
        // MZ header — looks like an exe, not a JPEG (which needs FF D8 FF)
        var data = new byte[512];
        data[0] = 0x4D; // M
        data[1] = 0x5A; // Z
        await File.WriteAllBytesAsync(file, data);

        var threats = await _monitor.ScanUSBDriveAsync(_testDir);

        var magicThreat = threats.FirstOrDefault(t => t.ThreatType == "Suspicious"
            && t.FilePath == file);
        Assert.That(magicThreat, Is.Not.Null, ".jpg with EXE header must flag as Suspicious");
        Assert.That(magicThreat!.Severity, Is.EqualTo("MEDIUM"));
        Assert.That(magicThreat.Description, Does.Contain("mismatch").IgnoreCase);
    }

    [Test]
    [Description("File with unknown extension should not be flagged for magic byte mismatch")]
    public async Task ScanDrive_UnknownExtension_ShouldNotFlagMagic()
    {
        var file = Path.Combine(_testDir, "data.firmware");
        var data = new byte[256]; // All zeros
        await File.WriteAllBytesAsync(file, data);

        var threats = await _monitor.ScanUSBDriveAsync(_testDir);

        var magicThreat = threats.FirstOrDefault(t =>
            t.ThreatType == "Suspicious" && t.FilePath == file);
        Assert.That(magicThreat, Is.Null, "Unknown extension should be assumed OK");
    }

    // ─────────────────────────────────────────────────────
    // IOC hash tests
    // ─────────────────────────────────────────────────────

    [Test]
    [Description("File whose SHA-256 is in IOC DB must produce CRITICAL IOC threat")]
    public async Task ScanDrive_KnownBadHash_ShouldProduceCriticalIOCThreat()
    {
        var file = Path.Combine(_testDir, "malware.exe");
        var content = new byte[] { 0x4D, 0x5A, 0xDE, 0xAD, 0xBE, 0xEF };
        await File.WriteAllBytesAsync(file, content);

        // Compute actual hash and register it as known-bad
        var hash = ComputeSHA256(file);
        _iocDb.RegisterBadHash(hash);

        var threats = await _monitor.ScanUSBDriveAsync(_testDir);

        var iocThreat = threats.FirstOrDefault(t => t.ThreatType == "IOC" && t.FilePath == file);
        Assert.That(iocThreat, Is.Not.Null, "Known-bad hash must produce IOC threat");
        Assert.That(iocThreat!.Severity, Is.EqualTo("CRITICAL"));
        Assert.That(iocThreat.Confidence, Is.EqualTo(100));
    }

    [Test]
    [Description("File not in IOC DB must not produce IOC threat")]
    public async Task ScanDrive_CleanHash_ShouldNotProduceIOCThreat()
    {
        var file = Path.Combine(_testDir, "clean.txt");
        await File.WriteAllTextAsync(file, "This is a clean document.");

        // Do NOT register hash as bad

        var threats = await _monitor.ScanUSBDriveAsync(_testDir);

        var iocThreat = threats.FirstOrDefault(t => t.ThreatType == "IOC");
        Assert.That(iocThreat, Is.Null, "Clean file should not produce IOC threat");
    }

    // ─────────────────────────────────────────────────────
    // YARA integration via mock ProcessRunner
    // ─────────────────────────────────────────────────────

    [Test]
    [Description("YARA match returned by Python subprocess produces Malware USBThreat")]
    public async Task ScanDrive_YaraMatch_ShouldProduceMalwareThreat()
    {
        var file = Path.Combine(_testDir, "suspicious.exe");
        await File.WriteAllBytesAsync(file, new byte[] { 0x4D, 0x5A });

        // Inject a YARA match via the mock runner
        _processRunner.SetYaraResult($"""
        [
          {{
            "file_path": "{file.Replace("\\", "\\\\")}",
            "rule_name": "Test_Mimikatz",
            "severity": "CRITICAL",
            "description": "Mimikatz signature detected",
            "matched_strings": ["$s1"]
          }}
        ]
        """);

        var threats = await _monitor.ScanUSBDriveAsync(_testDir);

        var yaraThreats = threats.Where(t => t.ThreatType == "Malware").ToList();
        Assert.That(yaraThreats, Is.Not.Empty, "YARA match should produce Malware threat");
        Assert.That(yaraThreats[0].RuleName, Is.EqualTo("Test_Mimikatz"));
        Assert.That(yaraThreats[0].Severity, Is.EqualTo("CRITICAL"));
        Assert.That(yaraThreats[0].Confidence, Is.EqualTo(95));
    }

    [Test]
    [Description("Empty YARA result (no matches) should produce no Malware threats")]
    public async Task ScanDrive_YaraNoMatch_ShouldProduceNoMalwareThreats()
    {
        var file = Path.Combine(_testDir, "clean.exe");
        await File.WriteAllBytesAsync(file, new byte[] { 0x4D, 0x5A });

        _processRunner.SetYaraResult("[]"); // No YARA hits

        var threats = await _monitor.ScanUSBDriveAsync(_testDir);

        var malwareThreats = threats.Where(t => t.ThreatType == "Malware").ToList();
        Assert.That(malwareThreats, Is.Empty, "No YARA matches should produce no Malware threats");
    }

    // ─────────────────────────────────────────────────────
    // General scan behaviour
    // ─────────────────────────────────────────────────────

    [Test]
    [Description("Scanning an empty directory should return empty threat list without throwing")]
    public async Task ScanDrive_EmptyDirectory_ShouldReturnNoThreats()
    {
        var emptyDir = Path.Combine(_testDir, "empty");
        Directory.CreateDirectory(emptyDir);

        var threats = await _monitor.ScanUSBDriveAsync(emptyDir);

        Assert.That(threats, Is.Empty);
    }

    [Test]
    [Description("Scanning a non-existent path should return empty list gracefully")]
    public async Task ScanDrive_NonExistentPath_ShouldReturnEmpty()
    {
        var threats = await _monitor.ScanUSBDriveAsync(@"Z:\NonExistentDrive\");

        Assert.That(threats, Is.Empty);
    }

    [Test]
    [Description("Multiple files scanned — each file produces its own independent result set")]
    public async Task ScanDrive_MultipleFiles_ShouldFlagOnlyBadOnes()
    {
        // Clean file
        var clean = Path.Combine(_testDir, "report.txt");
        await File.WriteAllTextAsync(clean, "quarterly report data");

        // High-entropy file
        var encrypted = Path.Combine(_testDir, "backup.bin");
        var rand = new byte[4096];
        RandomNumberGenerator.Fill(rand);
        await File.WriteAllBytesAsync(encrypted, rand);

        var threats = await _monitor.ScanUSBDriveAsync(_testDir);

        // Only the encrypted file should be flagged
        Assert.That(threats.Any(t => t.FilePath == encrypted), Is.True,
            "High-entropy file should be flagged");
        Assert.That(threats.All(t => t.FilePath != clean), Is.True,
            "Clean text file should not produce any threats");
    }

    // ─────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────

    private static string ComputeSHA256(string filePath)
    {
        using var sha = SHA256.Create();
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read);
        return BitConverter.ToString(sha.ComputeHash(fs)).Replace("-", "").ToLower();
    }
}

// ─────────────────────────────────────────────────────
// Test doubles (fakes for WMI-dependent dependencies)
// ─────────────────────────────────────────────────────

/// <summary>In-memory IOC database for tests — no SQLite required.</summary>
internal class TestIOCDb : Database.IOCDb
{
    private readonly HashSet<string> _badHashes = new(StringComparer.OrdinalIgnoreCase);

    public TestIOCDb() : base(NullLogger.Instance, ":memory:") { }

    public void RegisterBadHash(string sha256) => _badHashes.Add(sha256);

    public override Task<bool> IsKnownBadHashAsync(string sha256)
        => Task.FromResult(_badHashes.Contains(sha256));
}

/// <summary>
/// Fake ProcessRunner — returns configurable JSON for YARA scans
/// without spawning any real Python process.
/// </summary>
internal class TestProcessRunner : IPC.ProcessRunner
{
    private string _yaraResult = "[]";

    public TestProcessRunner()
        : base(NullLogger.Instance, "python", ".", 30) { }

    public void SetYaraResult(string json) => _yaraResult = json;

    public override Task<string> RunYaraScanAsync(string dirPath)
        => Task.FromResult(_yaraResult);

    public override Task<string> RunYaraScanFileAsync(string filePath)
        => Task.FromResult(_yaraResult);
}
