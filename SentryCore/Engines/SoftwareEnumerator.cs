using System.Management;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using SentryShield.Core.Models;

namespace SentryShield.Core.Engines;

/// <summary>
/// Enumerates installed software via WMI Win32_Product and Windows Registry.
///
/// Strategy:
///   Primary:  Registry (HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall)
///             Fast, complete, includes most installed software.
///
///   Secondary: WMI Win32_Product
///             Slower (triggers MSI reconfiguration), but catches MSI-only installs.
///             Only run if Registry query returns fewer than expected entries.
///
/// Legacy HMI note: Win32_Product can be very slow on machines with many MSI
/// installs. Registry is preferred for production HMI scanning.
/// </summary>
public class SoftwareEnumerator
{
    private readonly ILogger _logger;

    // Registry paths to scan for installed software
    private static readonly string[] RegistryPaths = new[]
    {
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    };

    public SoftwareEnumerator(ILogger logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Returns the union of Registry + WMI software entries, deduplicated by name+version.
    /// </summary>
    public List<InstalledSoftware> EnumerateInstalledSoftware()
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var result = new List<InstalledSoftware>();

        // 1. Registry scan (fast, preferred)
        var registryEntries = ScanRegistry();
        foreach (var entry in registryEntries)
        {
            var key = $"{entry.Name}|{entry.Version}";
            if (seen.Add(key))
                result.Add(entry);
        }

        _logger.LogInformation("Registry scan: {Count} software entries", result.Count);

        // 2. WMI scan (slower — can be disabled in config for air-gapped HMIs)
        try
        {
            var wmiEntries = ScanWMI();
            foreach (var entry in wmiEntries)
            {
                var key = $"{entry.Name}|{entry.Version}";
                if (seen.Add(key))
                    result.Add(entry);
            }
            _logger.LogInformation("WMI scan added {Count} additional entries",
                wmiEntries.Count - (result.Count - registryEntries.Count));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "WMI software scan failed — using Registry results only");
        }

        return result;
    }

    // -------------------------------------------------------------------------
    // Registry enumeration
    // -------------------------------------------------------------------------

    private List<InstalledSoftware> ScanRegistry()
    {
        var result = new List<InstalledSoftware>();

        foreach (var path in RegistryPaths)
        {
            foreach (var hive in new[] { Registry.LocalMachine, Registry.CurrentUser })
            {
                try
                {
                    using var key = hive.OpenSubKey(path);
                    if (key == null) continue;

                    foreach (var subKeyName in key.GetSubKeyNames())
                    {
                        try
                        {
                            using var subKey = key.OpenSubKey(subKeyName);
                            if (subKey == null) continue;

                            var name = subKey.GetValue("DisplayName")?.ToString();
                            if (string.IsNullOrWhiteSpace(name)) continue;

                            result.Add(new InstalledSoftware
                            {
                                Name = name,
                                Version = subKey.GetValue("DisplayVersion")?.ToString() ?? "Unknown",
                                Publisher = subKey.GetValue("Publisher")?.ToString() ?? "Unknown",
                                InstallPath = subKey.GetValue("InstallLocation")?.ToString() ?? "Unknown",
                                InstallDate = subKey.GetValue("InstallDate")?.ToString() ?? "Unknown"
                            });
                        }
                        catch
                        {
                            // Skip malformed registry entries silently
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Error reading registry path: {Path}", path);
                }
            }
        }

        return result;
    }

    // -------------------------------------------------------------------------
    // WMI enumeration (fallback)
    // -------------------------------------------------------------------------

    private List<InstalledSoftware> ScanWMI()
    {
        var result = new List<InstalledSoftware>();

        var query = new SelectQuery("Win32_Product",
            condition: null,
            selectedProperties: new[] { "Name", "Version", "InstallLocation", "Vendor" });

        using var searcher = new ManagementObjectSearcher(query);

        foreach (ManagementObject obj in searcher.Get())
        {
            try
            {
                var name = obj["Name"]?.ToString();
                if (string.IsNullOrWhiteSpace(name)) continue;

                result.Add(new InstalledSoftware
                {
                    Name = name,
                    Version = obj["Version"]?.ToString() ?? "Unknown",
                    InstallPath = obj["InstallLocation"]?.ToString() ?? "Unknown",
                    Publisher = obj["Vendor"]?.ToString() ?? "Unknown"
                });
            }
            catch
            {
                // Skip malformed WMI entries
            }
        }

        return result;
    }
}
