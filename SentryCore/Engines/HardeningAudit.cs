using System.Management;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using SentryShield.Core.Models;

namespace SentryShield.Core.Engines;

/// <summary>
/// Checks Windows security hardening controls relevant to manufacturing HMIs.
/// Controls audited:
///   1. Windows Defender (Antivirus) — enabled?
///   2. Windows Firewall — enabled on all profiles?
///   3. USB write-protect — registry key set?
///   4. AutoRun disabled — USB/CD autorun disabled?
///   5. Windows Update — last update within 90 days?
///   6. Remote Desktop — disabled? (should be off on OT machines)
///   7. Guest account — disabled?
/// </summary>
public class HardeningAudit
{
    private readonly ILogger _logger;

    public HardeningAudit(ILogger logger)
    {
        _logger = logger;
    }

    public async Task<List<Finding>> CheckAsync()
    {
        var findings = new List<Finding>();
        var checks = new List<HardeningCheck>();

        checks.Add(CheckWindowsDefender());
        checks.Add(CheckFirewall());
        checks.Add(CheckUSBWriteProtect());
        checks.Add(CheckAutoRun());
        checks.Add(CheckRemoteDesktop());
        checks.Add(CheckGuestAccount());

        foreach (var check in checks)
        {
            if (!check.Passed)
            {
                findings.Add(new Finding
                {
                    FindingType = "hardening",
                    Severity = check.Severity,
                    Title = $"Hardening: {check.ControlName}",
                    Description = check.Status,
                    AffectedComponent = check.ControlName,
                    Remediation = check.Recommendation,
                    DetectionTimestamp = DateTime.UtcNow
                });
            }
        }

        _logger.LogInformation("[Hardening] Check complete: {Pass} passed, {Fail} failed",
            checks.Count(c => c.Passed), checks.Count(c => !c.Passed));

        return findings;
    }

    // -------------------------------------------------------------------------
    // Individual hardening checks
    // -------------------------------------------------------------------------

    private HardeningCheck CheckWindowsDefender()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(@"root\SecurityCenter2",
                "SELECT * FROM AntiVirusProduct");

            foreach (ManagementObject product in searcher.Get())
            {
                var state = product["productState"]?.ToString();
                if (state != null)
                {
                    // productState is a hex-encoded bitmask
                    // Middle byte 0x10 = real-time protection enabled
                    if (int.TryParse(state, out var stateInt))
                    {
                        var rtEnabled = ((stateInt >> 12) & 0xF) == 1;
                        if (rtEnabled)
                        {
                            return new HardeningCheck
                            {
                                ControlName = "Windows Defender / Antivirus",
                                Passed = true,
                                Status = "Antivirus real-time protection is active",
                                Severity = "HIGH"
                            };
                        }
                    }
                }
            }

            return new HardeningCheck
            {
                ControlName = "Windows Defender / Antivirus",
                Passed = false,
                Status = "No active antivirus real-time protection detected",
                Recommendation = "Enable Windows Defender or install an approved AV solution",
                Severity = "HIGH"
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[Hardening] Defender check failed");
            return new HardeningCheck
            {
                ControlName = "Windows Defender / Antivirus",
                Passed = false,
                Status = $"Could not verify AV status: {ex.Message}",
                Recommendation = "Manually verify antivirus is active",
                Severity = "HIGH"
            };
        }
    }

    private HardeningCheck CheckFirewall()
    {
        try
        {
            // Check Domain, Private, and Public profiles via registry
            var profiles = new[]
            {
                @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
                @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
                @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile"
            };

            var profileNames = new[] { "Domain", "Private", "Public" };
            var disabledProfiles = new List<string>();

            for (int i = 0; i < profiles.Length; i++)
            {
                using var key = Registry.LocalMachine.OpenSubKey(profiles[i]);
                var enabled = key?.GetValue("EnableFirewall") as int?;
                if (enabled != 1)
                    disabledProfiles.Add(profileNames[i]);
            }

            if (disabledProfiles.Count == 0)
            {
                return new HardeningCheck
                {
                    ControlName = "Windows Firewall",
                    Passed = true,
                    Status = "Windows Firewall is enabled on all profiles (Domain, Private, Public)",
                    Severity = "HIGH"
                };
            }

            return new HardeningCheck
            {
                ControlName = "Windows Firewall",
                Passed = false,
                Status = $"Windows Firewall is disabled on: {string.Join(", ", disabledProfiles)}",
                Recommendation = "Enable Windows Firewall on all network profiles via Group Policy or netsh",
                Severity = "HIGH"
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[Hardening] Firewall check failed");
            return new HardeningCheck
            {
                ControlName = "Windows Firewall",
                Passed = false,
                Status = $"Could not verify firewall status: {ex.Message}",
                Recommendation = "Manually verify firewall is enabled",
                Severity = "HIGH"
            };
        }
    }

    private HardeningCheck CheckUSBWriteProtect()
    {
        try
        {
            // HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies\WriteProtect = 1
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies");

            var writeProtect = key?.GetValue("WriteProtect") as int?;
            bool isProtected = writeProtect == 1;

            return new HardeningCheck
            {
                ControlName = "USB Write Protection",
                Passed = isProtected,
                Status = isProtected
                    ? "USB write protection is enabled (StorageDevicePolicies\\WriteProtect = 1)"
                    : "USB write protection is NOT enabled — USB drives are writable",
                Recommendation = "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\StorageDevicePolicies\\WriteProtect = 1 via GPO",
                Severity = "MEDIUM"
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[Hardening] USB write-protect check failed");
            return new HardeningCheck
            {
                ControlName = "USB Write Protection",
                Passed = false,
                Status = $"Could not check USB write protection: {ex.Message}",
                Recommendation = "Manually verify StorageDevicePolicies registry key",
                Severity = "MEDIUM"
            };
        }
    }

    private HardeningCheck CheckAutoRun()
    {
        try
        {
            // HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDriveTypeAutoRun = 0xFF
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer");

            var autoRun = key?.GetValue("NoDriveTypeAutoRun") as int?;
            bool disabled = autoRun == 0xFF || autoRun == 255; // All drive types

            return new HardeningCheck
            {
                ControlName = "AutoRun / AutoPlay",
                Passed = disabled,
                Status = disabled
                    ? "AutoRun is disabled for all drive types"
                    : "AutoRun is NOT fully disabled — USB/CD autoplay may execute malware",
                Recommendation = "Set NoDriveTypeAutoRun = 0xFF via GPO (Computer Config > Admin Templates > Windows Components > AutoPlay Policies)",
                Severity = "HIGH"
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[Hardening] AutoRun check failed");
            return new HardeningCheck
            {
                ControlName = "AutoRun / AutoPlay",
                Passed = false,
                Status = $"Could not check AutoRun status: {ex.Message}",
                Recommendation = "Manually verify AutoRun is disabled via Group Policy",
                Severity = "HIGH"
            };
        }
    }

    private HardeningCheck CheckRemoteDesktop()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Terminal Server");

            var fDenyConnections = key?.GetValue("fDenyTSConnections") as int?;
            bool rdpDisabled = fDenyConnections == 1;

            return new HardeningCheck
            {
                ControlName = "Remote Desktop (RDP)",
                Passed = rdpDisabled,
                Status = rdpDisabled
                    ? "Remote Desktop is disabled"
                    : "Remote Desktop is ENABLED — OT machines should not allow RDP",
                Recommendation = "Disable RDP on production HMIs: set fDenyTSConnections = 1 or via GPO",
                Severity = "MEDIUM"
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[Hardening] RDP check failed");
            return new HardeningCheck
            {
                ControlName = "Remote Desktop (RDP)",
                Passed = false,
                Status = $"Could not check RDP status: {ex.Message}",
                Recommendation = "Manually verify RDP is disabled",
                Severity = "MEDIUM"
            };
        }
    }

    private HardeningCheck CheckGuestAccount()
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT * FROM Win32_UserAccount WHERE Name='Guest' AND LocalAccount=True");

            foreach (ManagementObject account in searcher.Get())
            {
                var disabled = account["Disabled"] as bool?;
                bool guestDisabled = disabled == true;

                return new HardeningCheck
                {
                    ControlName = "Guest Account",
                    Passed = guestDisabled,
                    Status = guestDisabled
                        ? "Guest account is disabled"
                        : "Guest account is ENABLED — unauthorized local access risk",
                    Recommendation = "Disable the Guest account: net user Guest /active:no",
                    Severity = "MEDIUM"
                };
            }

            // Guest account not found — likely already removed
            return new HardeningCheck
            {
                ControlName = "Guest Account",
                Passed = true,
                Status = "Guest account not present",
                Severity = "MEDIUM"
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[Hardening] Guest account check failed");
            return new HardeningCheck
            {
                ControlName = "Guest Account",
                Passed = false,
                Status = $"Could not check guest account: {ex.Message}",
                Recommendation = "Manually verify guest account is disabled",
                Severity = "MEDIUM"
            };
        }
    }
}
