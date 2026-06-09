using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SentryShield.Core.Engines;
using SentryShield.Database;
using SentryShield.Service.IPC;
using SentryShield.Service.Watchers;
using SentryShield.Core;
using SentryShield.Plugin.Abstractions;

namespace SentryShield.Service;

/// <summary>
/// Main background worker for SentryShield.
/// Orchestrates: vulnerability scanning, driver audit, hardening checks,
/// USB monitoring, and gateway watching on configurable intervals.
/// </summary>
public class SentryWorker : BackgroundService
{
    private readonly ILogger<SentryWorker> _logger;
    private readonly ScanningOptions _scanOptions;
    private readonly GatewayFolderWatcher _gatewayWatcher;
    private readonly ScanHistoryDb _historyDb;
    private readonly PluginLoader _pluginLoader;
    private readonly PathOptions _pathOptions;
    private readonly DatabaseIntegrityValidator _dbValidator;

    // Last run timestamps for interval management
    private DateTime _lastVulnScan = DateTime.MinValue;
    private DateTime _lastDriverAudit = DateTime.MinValue;
    private DateTime _lastHardeningCheck = DateTime.MinValue;

    public SentryWorker(
        ILogger<SentryWorker> logger,
        IOptions<ScanningOptions> scanOptions,
        IOptions<PathOptions> pathOptions,
        GatewayFolderWatcher gatewayWatcher,
        ScanHistoryDb historyDb,
        PluginLoader pluginLoader)
    {
        _logger = logger;
        _scanOptions = scanOptions.Value;
        _pathOptions = pathOptions.Value;
        _gatewayWatcher = gatewayWatcher;
        _historyDb = historyDb;
        _pluginLoader = pluginLoader;
        _dbValidator = new DatabaseIntegrityValidator(logger);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("SentryShield service started at {Time}", DateTimeOffset.Now);

        // P1 Security Hardening: DB Integrity Check
        string appData = Environment.GetEnvironmentVariable("SENTRYSHIELD_DATA") ?? @"C:\ProgramData\SentryShield";
        if (!_dbValidator.ValidateDatabases(
            Path.Combine(appData, "ioc.db"), 
            Path.Combine(appData, "vulnerability.db")))
        {
            _logger.LogCritical("Shutting down due to database integrity failure.");
            Environment.Exit(1);
        }

        // P1 Security Hardening: Enforce YARA rules folder ACLs
        EnforceYaraAcls();

        // Start file system watcher for gateway folder
        _gatewayWatcher.Start();

        // Main orchestration loop — runs every minute, checks intervals
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var now = DateTime.UtcNow;

                // Dynamic Plugin execution (replaces VulnScan/SoftwareEnum)
                if ((now - _lastVulnScan).TotalHours >= _scanOptions.VulnerabilityScanIntervalHours)
                {
                    _logger.LogInformation("Starting dynamic plugin execution...");
                    await RunPluginsAsync(stoppingToken);
                    _lastVulnScan = now;
                }

                // Driver audit
                if ((now - _lastDriverAudit).TotalHours >= _scanOptions.DriverAuditIntervalHours)
                {
                    _logger.LogInformation("Starting driver audit...");
                    await RunDriverAuditAsync(stoppingToken);
                    _lastDriverAudit = now;
                }

                // Hardening check
                if ((now - _lastHardeningCheck).TotalHours >= _scanOptions.HardeningCheckIntervalHours)
                {
                    _logger.LogInformation("Starting hardening check...");
                    await RunHardeningCheckAsync(stoppingToken);
                    _lastHardeningCheck = now;
                }
            }
            catch (Exception ex) when (!stoppingToken.IsCancellationRequested)
            {
                _logger.LogError(ex, "Error in SentryWorker main loop");
            }

            // Poll every 60 seconds
            await Task.Delay(TimeSpan.FromSeconds(60), stoppingToken);
        }

        _gatewayWatcher.Stop();
        _logger.LogInformation("SentryShield service stopped at {Time}", DateTimeOffset.Now);
    }

    // -------------------------------------------------------------------------
    // Scan orchestrators
    // -------------------------------------------------------------------------

    private async Task RunPluginsAsync(CancellationToken ct)
    {
        var startTime = DateTime.UtcNow;
        int findingsCount = 0;

        try
        {
            var findings = new List<SentryShield.Core.Models.Finding>();

            foreach (var plugin in _pluginLoader.GetPlugins())
            {
                _logger.LogInformation("Executing plugin: {PluginName} v{Version}", plugin.Name, plugin.Version);
                try
                {
                    using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    timeoutCts.CancelAfter(TimeSpan.FromMinutes(5));

                    var parameters = new Dictionary<string, object>
                    {
                        { "cancellationToken", timeoutCts.Token }
                    };

                    var results = await plugin.ExecuteAsync(parameters);
                    foreach (var result in results)
                    {
                        findings.Add(new Core.Models.Finding
                        {
                            Id = Guid.NewGuid().ToString(),
                            MachineName = Environment.MachineName,
                            FindingType = plugin.Name.ToLower().Contains("usb") ? "usb" : "vulnerability",
                            Severity = result.Severity,
                            Title = result.Title,
                            Description = result.Description,
                            AffectedComponent = result.Target,
                            Remediation = result.Remediation,
                            DetectionTimestamp = DateTime.UtcNow
                        });
                    }
                    findingsCount += results.Count;
                }
                catch (OperationCanceledException)
                {
                    _logger.LogError("Plugin {PluginName} timed out and was killed to prevent orchestration deadlock.", plugin.Name);
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Plugin {PluginName} failed during execution.", plugin.Name);
                }
            }

            bool criticalFound = findings.Any(f => f.Severity == "CRITICAL");
            if (criticalFound)
            {
                var remediationPlugin = _pluginLoader.GetPlugins().FirstOrDefault(p => p.Name == "RemediationPlugin");
                if (remediationPlugin != null)
                {
                    _logger.LogWarning("CRITICAL finding detected. Triggering RemediationPlugin for immediate quarantine.");
                    try
                    {
                        var remParams = new Dictionary<string, object>
                        {
                            { "Action", "IsolateNetwork" },
                            { "cancellationToken", ct }
                        };
                        var remResults = await remediationPlugin.ExecuteAsync(remParams);
                        foreach (var result in remResults)
                        {
                            findings.Add(new Core.Models.Finding
                            {
                                Id = Guid.NewGuid().ToString(),
                                MachineName = Environment.MachineName,
                                FindingType = "remediation",
                                Severity = result.Severity,
                                Title = result.Title,
                                Description = result.Description,
                                AffectedComponent = result.Target,
                                Remediation = result.Remediation,
                                DetectionTimestamp = DateTime.UtcNow
                            });
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "RemediationPlugin failed during isolation attempt.");
                    }
                }
            }

            if (findings.Count > 0)
            {
                await _historyDb.SaveFindingsAsync(findings);
            }

            var elapsed = (int)(DateTime.UtcNow - startTime).TotalSeconds;
            await _historyDb.RecordScanAsync("dynamic_plugins", findings.Count,
                findings.Count(f => f.Severity == "CRITICAL"),
                findings.Count(f => f.Severity == "HIGH"),
                findings.Count(f => f.Severity == "MEDIUM"),
                elapsed);

            _logger.LogInformation("Dynamic plugin execution complete: {Findings} findings in {Elapsed}s",
                findingsCount, elapsed);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Dynamic plugin execution failed");
        }
    }

    private async Task RunDriverAuditAsync(CancellationToken ct)
    {
        try
        {
            var auditor = new DriverAuditor(_logger);
            var findings = await auditor.AuditAsync();
            await _historyDb.SaveFindingsAsync(findings);
            _logger.LogInformation("Driver audit complete: {Count} findings", findings.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Driver audit failed");
        }
    }

    private async Task RunHardeningCheckAsync(CancellationToken ct)
    {
        try
        {
            var audit = new HardeningAudit(_logger);
            var findings = await audit.CheckAsync();
            await _historyDb.SaveFindingsAsync(findings);
            _logger.LogInformation("Hardening check complete: {Count} findings", findings.Count);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Hardening check failed");
        }
    }

    private void EnforceYaraAcls()
    {
        if (!OperatingSystem.IsWindows()) return;

        try
        {
            var rulesDir = _pathOptions.YaraRulesPath;
            if (string.IsNullOrWhiteSpace(rulesDir)) return;
            if (!Path.IsPathRooted(rulesDir))
                rulesDir = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, rulesDir));

            if (!Directory.Exists(rulesDir)) return;

            var dInfo = new DirectoryInfo(rulesDir);
            var security = dInfo.GetAccessControl();

            // Strip inherited permissions
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

            // Add SYSTEM and built-in Administrators
            var systemSid = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.LocalSystemSid, null);
            var adminSid = new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.BuiltinAdministratorsSid, null);
            
            security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                systemSid, System.Security.AccessControl.FileSystemRights.FullControl, 
                System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit, 
                System.Security.AccessControl.PropagationFlags.None, 
                System.Security.AccessControl.AccessControlType.Allow));

            security.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                adminSid, System.Security.AccessControl.FileSystemRights.FullControl, 
                System.Security.AccessControl.InheritanceFlags.ContainerInherit | System.Security.AccessControl.InheritanceFlags.ObjectInherit, 
                System.Security.AccessControl.PropagationFlags.None, 
                System.Security.AccessControl.AccessControlType.Allow));

            dInfo.SetAccessControl(security);
            _logger.LogInformation("[Security] YARA rules folder locked down to SYSTEM/Administrators.");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[Security] Could not enforce ACLs on YARA rules directory. (Run as Administrator required)");
        }
    }
}
