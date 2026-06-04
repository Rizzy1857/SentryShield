using System.ServiceProcess;
using System.Threading;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using SentryShield.Core.Engines;
using SentryShield.Core.Logging;
using SentryShield.Database;

namespace SentryShield.LegacyService;

/// <summary>
/// Windows Service host for SentryShield on legacy .NET 4.8 targets (Win7 / WES7 / WE8.1).
///
/// Architecture differences from SentryService (net8):
///   - Inherits ServiceBase instead of BackgroundService.
///   - Uses System.Threading.Timer instead of async host lifetime.
///   - Fully headless — no tray icon, no console UI.
///   - YARA scanning is optional (LegacyYaraGuard probes Python at startup).
///
/// Scan loop: a single System.Threading.Timer fires every 60 seconds.
/// Each tick checks elapsed time since last run against the configured interval,
/// then dispatches the relevant scan on a ThreadPool thread (fire-and-forget
/// with exception logging — a single scan failure never kills the service).
/// </summary>
internal sealed class LegacyServiceHost : ServiceBase
{
    private readonly ILogger         _logger;
    private readonly LegacyConfig    _config;
    private readonly ScanHistoryDb   _historyDb;
    private readonly VulnerabilityDb _vulnDb;
    private readonly EventLogWriter  _eventLog;
    private readonly LegacyYaraGuard _yaraGuard;

    private Timer?   _timer;
    private DateTime _lastVulnScan      = DateTime.MinValue;
    private DateTime _lastDriverAudit   = DateTime.MinValue;
    private DateTime _lastHardening     = DateTime.MinValue;

    public LegacyServiceHost(
        ILogger logger,
        LegacyConfig config,
        ScanHistoryDb historyDb,
        VulnerabilityDb vulnDb,
        EventLogWriter eventLog,
        LegacyYaraGuard yaraGuard)
    {
        ServiceName = "SentryShield";
        CanStop     = true;
        CanPauseAndContinue = false;
        AutoLog     = false;     // We write to Event Log manually for better control

        _logger    = logger;
        _config    = config;
        _historyDb = historyDb;
        _vulnDb    = vulnDb;
        _eventLog  = eventLog;
        _yaraGuard = yaraGuard;
    }

    // -------------------------------------------------------------------------
    // ServiceBase lifecycle
    // -------------------------------------------------------------------------

    protected override void OnStart(string[] args)
    {
        _eventLog.WriteInfo("SentryShield legacy service starting.", eventId: 1000);
        _logger.LogInformation("SentryShield legacy service starting at {Time}", DateTime.Now);

        // Probe Python availability once before starting the timer
        _yaraGuard.Probe();

        // Fire immediately (dueTime=0), then every 60 seconds
        _timer = new Timer(OnTick, null, TimeSpan.Zero, TimeSpan.FromSeconds(60));
    }

    protected override void OnStop()
    {
        _timer?.Change(Timeout.Infinite, Timeout.Infinite);
        _timer?.Dispose();
        _timer = null;

        _eventLog.WriteInfo("SentryShield legacy service stopped.", eventId: 1001);
        _logger.LogInformation("SentryShield legacy service stopped at {Time}", DateTime.Now);
    }

    // -------------------------------------------------------------------------
    // Scan orchestration timer callback
    // -------------------------------------------------------------------------

    private void OnTick(object? state)
    {
        var now = DateTime.UtcNow;

        if ((now - _lastVulnScan).TotalHours >= _config.Scanning.VulnerabilityScanIntervalHours)
        {
            _lastVulnScan = now;
            ThreadPool.QueueUserWorkItem(_ => RunSafe("VulnerabilityScan", RunVulnerabilityScanAsync));
        }

        if ((now - _lastDriverAudit).TotalHours >= _config.Scanning.DriverAuditIntervalHours)
        {
            _lastDriverAudit = now;
            ThreadPool.QueueUserWorkItem(_ => RunSafe("DriverAudit", RunDriverAuditAsync));
        }

        if ((now - _lastHardening).TotalHours >= _config.Scanning.HardeningCheckIntervalHours)
        {
            _lastHardening = now;
            ThreadPool.QueueUserWorkItem(_ => RunSafe("HardeningCheck", RunHardeningCheckAsync));
        }
    }

    /// <summary>
    /// Fire-and-forget wrapper: logs any exception so a scan failure
    /// never propagates back to OnTick or kills the timer.
    /// </summary>
    private void RunSafe(string scanName, Func<System.Threading.Tasks.Task> action)
    {
        try
        {
            action().GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[LegacyServiceHost] {Scan} failed", scanName);
            _eventLog.WriteError($"[SentryShield] {scanName} failed: {ex.Message}", eventId: 9000);
        }
    }

    // -------------------------------------------------------------------------
    // Individual scan runners (mirror SentryWorker logic)
    // -------------------------------------------------------------------------

    private async System.Threading.Tasks.Task RunVulnerabilityScanAsync()
    {
        var start = DateTime.UtcNow;
        _logger.LogInformation("Starting vulnerability scan...");

        var enumerator = new SoftwareEnumerator(_logger);
        var installed  = enumerator.EnumerateInstalledSoftware();

        var matcher  = new VulnerabilityMatcher(_vulnDb, _logger);
        var findings = new List<Core.Models.Finding>();

        foreach (var sw in installed)
        {
            var matches = matcher.FindVulnerabilities(sw.Name, sw.Version, sw.InstallPath);
            foreach (var m in matches)
            {
                findings.Add(new Core.Models.Finding
                {
                    FindingType        = "vulnerability",
                    Severity           = m.Severity,
                    Title              = $"{m.CVEId}: {m.ProductName}",
                    Description        = m.Description,
                    AffectedComponent  = m.InstallPath,
                    Remediation        = m.Remediation,
                    DetectionTimestamp = DateTime.UtcNow
                });
            }
        }

        await _historyDb.SaveFindingsAsync(findings);
        var elapsed = (int)(DateTime.UtcNow - start).TotalSeconds;
        await _historyDb.RecordScanAsync("vulnerability", findings.Count,
            findings.Count(f => f.Severity == "CRITICAL"),
            findings.Count(f => f.Severity == "HIGH"),
            findings.Count(f => f.Severity == "MEDIUM"),
            elapsed);

        _logger.LogInformation("Vulnerability scan complete: {Count} findings in {Elapsed}s",
            findings.Count, elapsed);
    }

    private async System.Threading.Tasks.Task RunDriverAuditAsync()
    {
        _logger.LogInformation("Starting driver audit...");
        var auditor  = new DriverAuditor(_logger);
        var findings = await auditor.AuditAsync();
        await _historyDb.SaveFindingsAsync(findings);
        _logger.LogInformation("Driver audit complete: {Count} findings", findings.Count);
    }

    private async System.Threading.Tasks.Task RunHardeningCheckAsync()
    {
        _logger.LogInformation("Starting hardening check...");
        var audit    = new HardeningAudit(_logger);
        var findings = await audit.CheckAsync();
        await _historyDb.SaveFindingsAsync(findings);
        _logger.LogInformation("Hardening check complete: {Count} findings", findings.Count);
    }
}
