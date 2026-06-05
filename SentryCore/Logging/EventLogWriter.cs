using System.Diagnostics;
using Microsoft.Extensions.Logging;

namespace SentryShield.Core.Logging;

/// <summary>
/// Writes structured entries to the Windows Application Event Log.
/// Source must be registered before first use (done during service install).
/// </summary>
public class EventLogWriter
{
    private readonly string _source;
    private readonly string _log;
    private readonly ILogger? _logger;

    /// <summary>Used by SentryService (net8) — full logger available.</summary>
    public EventLogWriter(ILogger logger, string source = "SentryShield", string log = "Application")
    {
        _logger = logger;
        _source = source;
        _log    = log;
        EnsureSourceExists();
    }

    /// <summary>Used by SentryLegacyService (net48) — no DI logger available at startup.</summary>
    public EventLogWriter(string source, string log = "Application")
    {
        _logger = null;
        _source = source;
        _log    = log;
        EnsureSourceExists();
    }

    private void EnsureSourceExists()
    {
        try
        {
            if (!EventLog.SourceExists(_source))
                EventLog.CreateEventSource(_source, _log);
        }
        catch (Exception)
        {
            // Requires admin rights to create source — ignore if already exists
        }
    }

    public void WriteInfo(string message, int eventId = 1000)
        => Write(message, EventLogEntryType.Information, eventId);

    public void WriteWarning(string message, int eventId = 2000)
        => Write(message, EventLogEntryType.Warning, eventId);

    public void WriteError(string message, int eventId = 3000)
        => Write(message, EventLogEntryType.Error, eventId);

    public void WriteFinding(Models.Finding finding)
    {
        var severity = finding.Severity switch
        {
            "CRITICAL" => EventLogEntryType.Error,
            "HIGH" => EventLogEntryType.Warning,
            _ => EventLogEntryType.Information
        };

        var msg = $"[SentryShield] {finding.Severity} | {finding.FindingType} | {finding.Title}\n" +
                  $"Component: {finding.AffectedComponent}\n" +
                  $"Remediation: {finding.Remediation}\n" +
                  $"ID: {finding.Id}";

        Write(msg, severity, 4000);
    }

    private void Write(string message, EventLogEntryType type, int eventId)
    {
        try
        {
            EventLog.WriteEntry(_source, message, type, eventId);
        }
        catch (Exception ex)
        {
            // Fall back to ILogger if Event Log write fails
            _logger?.LogError(ex, "Failed to write to Event Log: {Message}", message);
        }
    }
}
