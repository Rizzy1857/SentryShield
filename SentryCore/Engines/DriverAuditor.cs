using System.Management;
using Microsoft.Extensions.Logging;
using SentryShield.Core.Models;

namespace SentryShield.Core.Engines;

/// <summary>
/// Audits installed device drivers via WMI Win32_PnPSignedDriver.
/// Flags:
///   - Unsigned drivers (missing Authenticode signature)
///   - Drivers with no known version (could indicate tampered/injected drivers)
///   - Drivers from unknown manufacturers
/// </summary>
public class DriverAuditor
{
    private readonly ILogger _logger;

    // Known-safe driver manufacturer patterns (whitelist)
    private static readonly HashSet<string> TrustedManufacturers = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft", "Intel", "NVIDIA", "AMD", "Realtek", "Qualcomm",
        "Broadcom", "Marvell", "VIA Technologies", "Silicon Laboratories"
    };

    // OT/ICS vendors whose drivers are intentionally old due to hardware certification
    // cycles (IEC 61511, IEC 62443, ISA-99). Flagging these as "outdated" creates noise
    // and undermines operator trust. They are still checked for unsigned status.
    private static readonly HashSet<string> OtCertifiedManufacturers = new(StringComparer.OrdinalIgnoreCase)
    {
        "Siemens",
        "Rockwell Automation",
        "Allen-Bradley",            // Rockwell brand
        "Schneider Electric",
        "Modicon",                  // Schneider brand
        "ABB",
        "Emerson",
        "Emerson Electric",
        "Yokogawa",
        "Honeywell",
        "Beckhoff",
        "Mitsubishi Electric",
        "OMRON",
        "Phoenix Contact",
        "Advantech",
        "Moxa",
    };

    public DriverAuditor(ILogger logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Enumerates all signed drivers and returns findings for suspicious entries.
    /// </summary>
    public async Task<List<Finding>> AuditAsync()
    {
        var findings = new List<Finding>();
        var drivers = EnumerateDrivers();

        _logger.LogInformation("[DriverAudit] Found {Count} drivers", drivers.Count);

        foreach (var driver in drivers)
        {
            // Flag unsigned drivers
            if (!driver.IsSigned)
            {
                findings.Add(new Finding
                {
                    FindingType = "driver",
                    Severity = "HIGH",
                    Title = $"Unsigned Driver: {driver.Name}",
                    Description = $"Driver '{driver.Name}' ({driver.InfName}) is not Authenticode signed. " +
                                  "Unsigned drivers may indicate a malicious or outdated driver.",
                    AffectedComponent = driver.Name,
                    Remediation = "Verify driver legitimacy, update from official manufacturer source, or remove if unnecessary.",
                    DetectionTimestamp = DateTime.UtcNow
                });
            }

            // Flag unknown manufacturers (not in trusted list)
            if (!string.IsNullOrWhiteSpace(driver.Manufacturer) &&
                !TrustedManufacturers.Any(t =>
                    driver.Manufacturer.Contains(t, StringComparison.OrdinalIgnoreCase)))
            {
                findings.Add(new Finding
                {
                    FindingType = "driver",
                    Severity = "MEDIUM",
                    Title = $"Unknown Manufacturer Driver: {driver.Name}",
                    Description = $"Driver '{driver.Name}' is from '{driver.Manufacturer}', " +
                                  "which is not in the trusted manufacturer list.",
                    AffectedComponent = driver.Name,
                    Remediation = "Verify this manufacturer is an approved hardware/software vendor.",
                    DetectionTimestamp = DateTime.UtcNow
                });
            }

            // Flag very old drivers (> 3 years without update — potential stability risk)
            // Exempt OT/ICS certified vendors: their drivers are intentionally old due to
            // hardware certification cycles and must not be updated without re-certification.
            bool isOtCertifiedDriver = !string.IsNullOrWhiteSpace(driver.Manufacturer) &&
                OtCertifiedManufacturers.Any(v =>
                    driver.Manufacturer.Contains(v, StringComparison.OrdinalIgnoreCase));

            if (!isOtCertifiedDriver &&
                driver.DriverDate.HasValue &&
                (DateTime.Now - driver.DriverDate.Value).TotalDays > 1095)
            {
                findings.Add(new Finding
                {
                    FindingType = "driver",
                    Severity = "LOW",
                    Title = $"Outdated Driver: {driver.Name}",
                    Description = $"Driver '{driver.Name}' was last updated on " +
                                  $"{driver.DriverDate:yyyy-MM-dd} (over 3 years ago). " +
                                  "Outdated non-OT drivers may contain known vulnerabilities.",
                    AffectedComponent = driver.Name,
                    Remediation = "Check manufacturer website for driver updates. " +
                                  "For OT hardware, consult the vendor's certified driver list before updating.",
                    DetectionTimestamp = DateTime.UtcNow
                });
            }
        }

        return findings;
    }

    // -------------------------------------------------------------------------
    // WMI enumeration
    // -------------------------------------------------------------------------

    private List<DriverEntry> EnumerateDrivers()
    {
        var drivers = new List<DriverEntry>();

        try
        {
            // Win32_PnPSignedDriver: includes signature status, driver date, manufacturer
            var query = new ObjectQuery(
                "SELECT DeviceName, DriverVersion, Manufacturer, IsSigned, " +
                "DriverDate, InfName FROM Win32_PnPSignedDriver");

            using var searcher = new ManagementObjectSearcher(query);

            foreach (ManagementObject obj in searcher.Get())
            {
                try
                {
                    // DriverDate is in WMI CIM_DATETIME format: "20230615000000.000000+000"
                    DateTime? driverDate = null;
                    var dateStr = obj["DriverDate"]?.ToString();
                    if (!string.IsNullOrEmpty(dateStr) && dateStr.Length >= 8)
                    {
                        if (DateTime.TryParseExact(dateStr[..8], "yyyyMMdd",
                            null, System.Globalization.DateTimeStyles.None, out var parsedDate))
                        {
                            driverDate = parsedDate;
                        }
                    }

                    drivers.Add(new DriverEntry
                    {
                        Name = obj["DeviceName"]?.ToString() ?? "Unknown",
                        Version = obj["DriverVersion"]?.ToString() ?? "Unknown",
                        Manufacturer = obj["Manufacturer"]?.ToString() ?? "Unknown",
                        IsSigned = bool.TryParse(obj["IsSigned"]?.ToString(), out var signed) && signed,
                        InfName = obj["InfName"]?.ToString() ?? "Unknown",
                        DriverDate = driverDate
                    });
                }
                catch
                {
                    // Skip malformed driver entries
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[DriverAudit] WMI query failed");
        }

        return drivers;
    }
}
