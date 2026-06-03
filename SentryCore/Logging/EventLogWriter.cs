using System.Diagnostics;
using Microsoft.Extensions.Logging;

namespace SentryShield.Core.Logging;

/// <summary>
/// Writes structured entries to the Windows Application Event Log.
/// Source must be registered before first use (done during service install).
/// </summary>
public class EventLogWriter
{
    private const string Source = "SentryShield";
    private const string Log = "Application";
    private readonly ILogger _logger;

    public EventLogWriter(ILogger logger)
    {
        _logger = logger;
        EnsureSourceExists();
    }

    private static void EnsureSourceExists()
    {
        try
        {
            if (!EventLog.SourceExists(Source))
                EventLog.CreateEventSource(Source, Log);
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
            EventLog.WriteEntry(Source, message, type, eventId);
        }
        catch (Exception ex)
        {
            // Fall back to ILogger if Event Log write fails
            _logger.LogError(ex, "Failed to write to Event Log: {Message}", message);
        }
    }
}
