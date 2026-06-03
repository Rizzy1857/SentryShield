using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SentryShield.Core.Engines;
using SentryShield.Database;
using SentryShield.Service.IPC;
using SentryShield.Service.Watchers;

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
    private readonly ProcessRunner _processRunner;
    private readonly GatewayFolderWatcher _gatewayWatcher;
    private readonly VulnerabilityDb _vulnDb;
    private readonly ScanHistoryDb _historyDb;

    // Last run timestamps for interval management
    private DateTime _lastVulnScan = DateTime.MinValue;
    private DateTime _lastDriverAudit = DateTime.MinValue;
    private DateTime _lastHardeningCheck = DateTime.MinValue;

    public SentryWorker(
        ILogger<SentryWorker> logger,
        IOptions<ScanningOptions> scanOptions,
        ProcessRunner processRunner,
        GatewayFolderWatcher gatewayWatcher,
        VulnerabilityDb vulnDb,
        ScanHistoryDb historyDb)
    {
        _logger = logger;
        _scanOptions = scanOptions.Value;
        _processRunner = processRunner;
        _gatewayWatcher = gatewayWatcher;
        _vulnDb = vulnDb;
        _historyDb = historyDb;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("SentryShield service started at {Time}", DateTimeOffset.Now);

        // Start file system watcher for gateway folder
        _gatewayWatcher.Start();

        // Main orchestration loop — runs every minute, checks intervals
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var now = DateTime.UtcNow;

                // Vulnerability + software scan
                if ((now - _lastVulnScan).TotalHours >= _scanOptions.VulnerabilityScanIntervalHours)
                {
                    _logger.LogInformation("Starting vulnerability scan...");
                    await RunVulnerabilityScanAsync(stoppingToken);
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

    private async Task RunVulnerabilityScanAsync(CancellationToken ct)
    {
        var startTime = DateTime.UtcNow;
        int findingsCount = 0;

        try
        {
            // 1. Enumerate installed software via WMI (C# side)
            var enumerator = new SoftwareEnumerator(_logger);
            var installedSoftware = enumerator.EnumerateInstalledSoftware();
            _logger.LogInformation("Found {Count} installed software entries", installedSoftware.Count);

            // 2. Match against vulnerability DB
            var matcher = new VulnerabilityMatcher(_vulnDb, _logger);
            var findings = new List<SentryShield.Core.Models.Finding>();

            foreach (var sw in installedSoftware)
            {
                var matches = matcher.FindVulnerabilities(sw.Name, sw.Version, sw.InstallPath);
                foreach (var match in matches)
                {
                    findings.Add(new Core.Models.Finding
                    {
                        Id = Guid.NewGuid().ToString(),
                        MachineName = Environment.MachineName,
                        FindingType = "vulnerability",
                        Severity = match.Severity,
                        Title = $"{match.CVEId}: {match.ProductName}",
                        Description = match.Description,
                        AffectedComponent = match.InstallPath,
                        Remediation = match.Remediation,
                        DetectionTimestamp = DateTime.UtcNow
                    });
                }
                findingsCount += matches.Count;
            }

            // 3. Persist findings
            await _historyDb.SaveFindingsAsync(findings);

            var elapsed = (int)(DateTime.UtcNow - startTime).TotalSeconds;
            await _historyDb.RecordScanAsync("vulnerability", findings.Count,
                findings.Count(f => f.Severity == "CRITICAL"),
                findings.Count(f => f.Severity == "HIGH"),
                findings.Count(f => f.Severity == "MEDIUM"),
                elapsed);

            _logger.LogInformation("Vulnerability scan complete: {Findings} findings in {Elapsed}s",
                findingsCount, elapsed);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Vulnerability scan failed");
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
}
