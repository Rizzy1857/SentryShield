namespace SentryShield.Core.Interfaces;

/// <summary>
/// Plugin contract — all detection engines implement this.
/// v2.0: IDS, Behavioral, Firmware plugins will implement this interface.
/// </summary>
public interface IDetectionPlugin
{
    string Name { get; }
    void Initialize(Dictionary<string, string> config);
    Task<List<Models.Finding>> ScanAsync(CancellationToken ct = default);
    void OnAlert(Models.Finding finding);
}

/// <summary>
/// Vulnerability matching against CVE database.
/// </summary>
public interface IVulnerabilityMatcher
{
    List<Models.VulnerabilityMatch> FindVulnerabilities(
        string productName,
        string installedVersion,
        string installPath);
}

/// <summary>
/// USB device monitoring and scanning.
/// </summary>
public interface IUSBMonitor
{
    void Start();
    void Stop();
    event EventHandler<Models.USBThreat> ThreatDetected;
}

/// <summary>
/// Supplier file gateway validation pipeline.
/// </summary>
public interface IValidator
{
    Task<Models.ValidationResult> ValidateAsync(
        string filePath,
        string supplierName,
        string? signatureFilePath = null);
}

/// <summary>
/// Detection engine orchestration contract.
/// </summary>
public interface IDetectionEngine
{
    Task<Models.ScanResult> RunFullScanAsync(CancellationToken ct = default);
}
