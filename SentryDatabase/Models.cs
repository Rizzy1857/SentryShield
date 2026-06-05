namespace SentryShield.Core.Models;

// Models are defined here in SentryDatabase.dll but under the SentryShield.Core.Models
// namespace so that SentryCore (which references SentryDatabase) can use them with
// the same `using SentryShield.Core.Models;` statement — no circular reference needed.

/// <summary>
/// A security detection event — the fundamental unit of output.
/// Persisted to the `findings` table.
/// </summary>
public class Finding
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public string MachineName { get; set; } = Environment.MachineName;
    /// <summary>"vulnerability" | "usb_threat" | "driver" | "hardening"</summary>
    public string FindingType { get; set; } = string.Empty;
    /// <summary>"CRITICAL" | "HIGH" | "MEDIUM" | "LOW"</summary>
    public string Severity { get; set; } = "MEDIUM";
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string AffectedComponent { get; set; } = string.Empty;
    public string Remediation { get; set; } = string.Empty;
    public DateTime DetectionTimestamp { get; set; } = DateTime.UtcNow;
    public bool Acknowledged { get; set; } = false;
    public string? Notes { get; set; }
    
    // Transient property for UI state
    public bool IsReviewing { get; set; } = false;
}

/// <summary>Result of a vulnerability database lookup.</summary>
public class VulnerabilityMatch
{
    public string CVEId { get; set; } = string.Empty;
    public string ProductName { get; set; } = string.Empty;
    public string InstalledVersion { get; set; } = string.Empty;
    public string AffectedVersionRange { get; set; } = string.Empty;
    public double CvssScore { get; set; }
    public string Severity { get; set; } = "MEDIUM";
    public string Description { get; set; } = string.Empty;
    public string Remediation { get; set; } = string.Empty;
    public string InstallPath { get; set; } = string.Empty;
}

/// <summary>A detected threat on a USB device.</summary>
public class USBThreat
{
    /// <summary>"Malware" | "Entropy" | "Suspicious" | "IOC"</summary>
    public string ThreatType { get; set; } = string.Empty;
    public string DevicePath { get; set; } = string.Empty;
    public string FilePath { get; set; } = string.Empty;
    public string FileName { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Remediation { get; set; } = string.Empty;
    public string RuleName { get; set; } = string.Empty;
    /// <summary>0–100 confidence score</summary>
    public double Confidence { get; set; }
    /// <summary>"CRITICAL" | "HIGH" | "MEDIUM" | "LOW"</summary>
    public string Severity { get; set; } = "HIGH";
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>Aggregated result of a full scan run.</summary>
public class ScanResult
{
    public string ScanType { get; set; } = string.Empty;
    public DateTime StartTime { get; set; }
    public DateTime EndTime { get; set; }
    public int FindingsCount { get; set; }
    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public int MediumCount { get; set; }
    public int LowCount { get; set; }
    public List<Finding> Findings { get; set; } = new();
    public int DurationSeconds => (int)(EndTime - StartTime).TotalSeconds;
    public bool Success { get; set; } = true;
    public string? ErrorMessage { get; set; }
}

/// <summary>Result of supplier file gateway validation.</summary>
public class ValidationResult
{
    public bool IsValid { get; set; }
    /// <summary>"ALLOW" | "BLOCK" | "WARN"</summary>
    public string Decision { get; set; } = "PENDING";
    public string Reason { get; set; } = string.Empty;
    public string Remediation { get; set; } = string.Empty;
    public List<string> Details { get; set; } = new();
    public DateTime ValidationTime { get; set; } = DateTime.UtcNow;
    public string FileHash { get; set; } = string.Empty;
    public double Entropy { get; set; }
}

/// <summary>Installed software entry from WMI/Registry enumeration.</summary>
public class InstalledSoftware
{
    public string Name { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public string InstallPath { get; set; } = string.Empty;
    public string Publisher { get; set; } = string.Empty;
    public string InstallDate { get; set; } = string.Empty;
}

/// <summary>Driver inventory entry from WMI enumeration.</summary>
public class DriverEntry
{
    public string Name { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public string Manufacturer { get; set; } = string.Empty;
    public bool IsSigned { get; set; }
    public bool IsEnabled { get; set; }
    public DateTime? DriverDate { get; set; }
    public string InfName { get; set; } = string.Empty;
}

/// <summary>Hardening check result for a single control.</summary>
public class HardeningCheck
{
    public string ControlName { get; set; } = string.Empty;
    public bool Passed { get; set; }
    public string Status { get; set; } = string.Empty;
    public string Recommendation { get; set; } = string.Empty;
    public string Severity { get; set; } = "HIGH";
}

/// <summary>Gateway file tracking record.</summary>
public class GatewayFile
{
    public int Id { get; set; }
    public string Filename { get; set; } = string.Empty;
    public string SupplierName { get; set; } = string.Empty;
    public string FileHash { get; set; } = string.Empty;
    public long FileSize { get; set; }
    public DateTime ReceivedTimestamp { get; set; }
    public string ValidationStatus { get; set; } = "PENDING";
    public string? BlockReason { get; set; }
    public string? Remediation { get; set; }
    public DateTime? ValidationTimestamp { get; set; }
    public bool TransferredToOT { get; set; }
}
