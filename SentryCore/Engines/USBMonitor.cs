using System.Management;
using Microsoft.Extensions.Logging;
using SentryShield.Core.Models;

namespace SentryShield.Core.Engines;

/// <summary>
/// Monitors USB device insertion via WMI event subscription.
/// On insertion, scans all files on removable drives using:
///   1. YARA rules (via Python subprocess)
///   2. Shannon entropy analysis
///   3. Magic byte / file extension mismatch detection
///   4. Known-bad hash (IOC) lookup
///
/// Threading: WMI events arrive on a background thread.
/// ThreatDetected event handlers must be thread-safe.
/// </summary>
public class USBMonitor : Interfaces.IUSBMonitor, IDisposable
{
    private readonly ILogger _logger;
    private readonly IPC.ProcessRunner _processRunner;
    private readonly Database.IOCDb _iocDb;

    private ManagementEventWatcher? _deviceWatcher;
    private bool _isRunning = false;

    public event EventHandler<USBThreat>? ThreatDetected;

    // Magic byte signatures: extension → expected header bytes
    private static readonly Dictionary<string, byte[][]> MagicSignatures = new(StringComparer.OrdinalIgnoreCase)
    {
        [".exe"] = new[] { new byte[] { 0x4D, 0x5A } },           // MZ
        [".dll"] = new[] { new byte[] { 0x4D, 0x5A } },           // MZ
        [".sys"] = new[] { new byte[] { 0x4D, 0x5A } },           // MZ (kernel driver)
        [".zip"] = new[] { new byte[] { 0x50, 0x4B, 0x03, 0x04 } }, // PK
        [".7z"]  = new[] { new byte[] { 0x37, 0x7A, 0xBC, 0xAF } }, // 7z
        [".rar"] = new[] { new byte[] { 0x52, 0x61, 0x72, 0x21 } }, // Rar!
        [".pdf"] = new[] { new byte[] { 0x25, 0x50, 0x44, 0x46 } }, // %PDF
        [".jpg"] = new[] { new byte[] { 0xFF, 0xD8, 0xFF } },      // JPEG
        [".png"] = new[] { new byte[] { 0x89, 0x50, 0x4E, 0x47 } }, // PNG
        [".doc"] = new[] { new byte[] { 0xD0, 0xCF, 0x11, 0xE0 } }, // OLE2
        [".xls"] = new[] { new byte[] { 0xD0, 0xCF, 0x11, 0xE0 } }, // OLE2
        [".docx"] = new[] { new byte[] { 0x50, 0x4B } },           // ZIP (OOXML)
        [".xlsx"] = new[] { new byte[] { 0x50, 0x4B } },           // ZIP (OOXML)
    };

    private const double HighEntropyThreshold = 7.5;

    public USBMonitor(
        ILogger logger,
        IPC.ProcessRunner processRunner,
        Database.IOCDb iocDb)
    {
        _logger = logger;
        _processRunner = processRunner;
        _iocDb = iocDb;
    }

    // -------------------------------------------------------------------------
    // IUSBMonitor
    // -------------------------------------------------------------------------

    public void Start()
    {
        if (_isRunning) return;

        try
        {
            var scope = new ManagementScope(@"\\.\root\cimv2");
            scope.Connect();

            // WMI event: fire within 2 seconds of USB controller device creation
            var query = new WqlEventQuery(
                "SELECT * FROM __InstanceCreationEvent WITHIN 2 " +
                "WHERE TargetInstance ISA 'Win32_USBControllerDevice'");

            _deviceWatcher = new ManagementEventWatcher(scope, query);
            _deviceWatcher.EventArrived += OnUSBConnected;
            _deviceWatcher.Start();

            _isRunning = true;
            _logger.LogInformation("[USBMonitor] Started — listening for USB device insertion");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[USBMonitor] Failed to start WMI event watcher");
        }
    }

    public void Stop()
    {
        _deviceWatcher?.Stop();
        _isRunning = false;
        _logger.LogInformation("[USBMonitor] Stopped");
    }

    // -------------------------------------------------------------------------
    // WMI event handler
    // -------------------------------------------------------------------------

    private void OnUSBConnected(object sender, EventArrivedEventArgs e)
    {
        _logger.LogInformation("[USBMonitor] USB device connected — scanning removable drives");

        var removableDrives = DriveInfo.GetDrives()
            .Where(d => d.DriveType == DriveType.Removable && d.IsReady)
            .ToList();

        if (!removableDrives.Any())
        {
            _logger.LogInformation("[USBMonitor] No ready removable drives found");
            return;
        }

        foreach (var drive in removableDrives)
        {
            Task.Run(() => ScanUSBDrive(drive.RootDirectory.FullName));
        }
    }

    // -------------------------------------------------------------------------
    // Drive scanning
    // -------------------------------------------------------------------------

    public async Task<List<USBThreat>> ScanUSBDriveAsync(string drivePath)
    {
        _logger.LogInformation("[USBMonitor] Scanning USB drive: {Path}", drivePath);
        var allThreats = new List<USBThreat>();

        string[] files;
        try
        {
            files = Directory.GetFiles(drivePath, "*.*", SearchOption.AllDirectories);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[USBMonitor] Cannot enumerate drive: {Path}", drivePath);
            return allThreats;
        }

        _logger.LogInformation("[USBMonitor] Found {Count} files on {Path}", files.Length, drivePath);

        // Run YARA scan on all files via Python subprocess (batch mode)
        var yaraThreats = await RunYaraScanAsync(drivePath);
        allThreats.AddRange(yaraThreats);

        // Per-file analysis (entropy + magic bytes + IOC hash)
        foreach (var file in files)
        {
            try
            {
                var fileThreats = await AnalyzeFileAsync(file, drivePath);
                allThreats.AddRange(fileThreats);
            }
            catch (UnauthorizedAccessException)
            {
                // Permission denied — skip
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[USBMonitor] Error analyzing file: {File}", file);
            }
        }

        _logger.LogInformation("[USBMonitor] Scan complete: {Threats} threats found on {Path}",
            allThreats.Count, drivePath);

        return allThreats;
    }

    // Internal sync wrapper for WMI event handler (can't await in event)
    private void ScanUSBDrive(string drivePath)
    {
        var threats = ScanUSBDriveAsync(drivePath).GetAwaiter().GetResult();
        foreach (var threat in threats)
        {
            ThreatDetected?.Invoke(this, threat);
        }
    }

    // -------------------------------------------------------------------------
    // YARA scan via Python subprocess
    // -------------------------------------------------------------------------

    private async Task<List<USBThreat>> RunYaraScanAsync(string drivePath)
    {
        var threats = new List<USBThreat>();

        try
        {
            var jsonResult = await _processRunner.RunYaraScanAsync(drivePath);
            if (string.IsNullOrWhiteSpace(jsonResult)) return threats;

            var matches = System.Text.Json.JsonSerializer.Deserialize<List<YaraMatch>>(jsonResult);
            if (matches == null) return threats;

            foreach (var match in matches)
            {
                threats.Add(new USBThreat
                {
                    ThreatType = "Malware",
                    DevicePath = drivePath,
                    FilePath = match.FilePath,
                    FileName = Path.GetFileName(match.FilePath),
                    RuleName = match.RuleName,
                    Description = match.Description,
                    Severity = match.Severity,
                    Confidence = 95,
                    DetectedAt = DateTime.UtcNow
                });
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[USBMonitor] YARA scan failed for {Path}", drivePath);
        }

        return threats;
    }

    // -------------------------------------------------------------------------
    // Per-file analysis
    // -------------------------------------------------------------------------

    private async Task<List<USBThreat>> AnalyzeFileAsync(string filePath, string drivePath)
    {
        var threats = new List<USBThreat>();
        var ext = Path.GetExtension(filePath).ToLower();

        // 1. Entropy analysis
        var entropy = CalculateEntropy(filePath);
        if (entropy > HighEntropyThreshold)
        {
            threats.Add(new USBThreat
            {
                ThreatType = "Entropy",
                DevicePath = drivePath,
                FilePath = filePath,
                FileName = Path.GetFileName(filePath),
                Description = $"High entropy ({entropy:F2}/8.0) — file may be encrypted, packed, or obfuscated",
                Severity = "MEDIUM",
                Confidence = 60,
                DetectedAt = DateTime.UtcNow
            });
        }

        // 2. Magic byte / extension mismatch
        if (!string.IsNullOrEmpty(ext))
        {
            var magicBytes = ReadMagicBytes(filePath);
            if (!IsMagicByteMatch(magicBytes, ext))
            {
                threats.Add(new USBThreat
                {
                    ThreatType = "Suspicious",
                    DevicePath = drivePath,
                    FilePath = filePath,
                    FileName = Path.GetFileName(filePath),
                    Description = $"Extension mismatch: '{ext}' extension but file header indicates different type",
                    Severity = "MEDIUM",
                    Confidence = 70,
                    DetectedAt = DateTime.UtcNow
                });
            }
        }

        // 3. Known-bad hash (IOC lookup)
        var hash = ComputeSHA256(filePath);
        if (!string.IsNullOrEmpty(hash) && await _iocDb.IsKnownBadHashAsync(hash))
        {
            threats.Add(new USBThreat
            {
                ThreatType = "IOC",
                DevicePath = drivePath,
                FilePath = filePath,
                FileName = Path.GetFileName(filePath),
                Description = $"File hash {hash[..16]}... matches known malware IOC",
                Severity = "CRITICAL",
                Confidence = 100,
                DetectedAt = DateTime.UtcNow
            });
        }

        return threats;
    }

    // -------------------------------------------------------------------------
    // Entropy calculation — Shannon entropy, 0–8 scale
    // -------------------------------------------------------------------------

    private static double CalculateEntropy(string filePath)
    {
        const int SampleBytes = 4096;

        try
        {
            var fileLen = new FileInfo(filePath).Length;
            if (fileLen == 0) return 0;

            var bytes = new byte[Math.Min(SampleBytes, fileLen)];
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var read = fs.Read(bytes, 0, bytes.Length);

            // Frequency table
            var freq = new long[256];
            for (int i = 0; i < read; i++)
                freq[bytes[i]]++;

            // Shannon entropy: H = -Σ p(x) * log₂(p(x))
            double entropy = 0;
            for (int i = 0; i < 256; i++)
            {
                if (freq[i] == 0) continue;
                double p = (double)freq[i] / read;
                entropy -= p * Math.Log2(p);
            }

            return entropy;
        }
        catch
        {
            return 0;
        }
    }

    // -------------------------------------------------------------------------
    // Magic byte helpers
    // -------------------------------------------------------------------------

    private static byte[] ReadMagicBytes(string filePath, int count = 8)
    {
        try
        {
            var buf = new byte[count];
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            fs.Read(buf, 0, count);
            return buf;
        }
        catch
        {
            return Array.Empty<byte>();
        }
    }

    private static bool IsMagicByteMatch(byte[] actual, string extension)
    {
        if (!MagicSignatures.TryGetValue(extension, out var expectedSigs))
            return true; // Unknown extension — assume OK

        if (actual.Length == 0)
            return true; // Can't read — assume OK

        return expectedSigs.Any(sig =>
            actual.Length >= sig.Length &&
            actual.Take(sig.Length).SequenceEqual(sig));
    }

    // -------------------------------------------------------------------------
    // SHA-256 hash
    // -------------------------------------------------------------------------

    private static string ComputeSHA256(string filePath)
    {
        try
        {
            using var sha = System.Security.Cryptography.SHA256.Create();
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var hash = sha.ComputeHash(fs);
            return BitConverter.ToString(hash).Replace("-", "").ToLower();
        }
        catch
        {
            return string.Empty;
        }
    }

    public void Dispose()
    {
        _deviceWatcher?.Stop();
        _deviceWatcher?.Dispose();
    }

    // -------------------------------------------------------------------------
    // Supporting types for JSON deserialization of YARA results
    // -------------------------------------------------------------------------

    private record YaraMatch(
        string FilePath,
        string RuleName,
        string Severity,
        string Description);
}
