using System;
using System.ServiceProcess;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SentryShield.Core.Logging;
using SentryShield.Database;
using SentryShield.Core;
using System.IO;

namespace SentryShield.LegacyService;

/// <summary>
/// Entry point for SentryLegacyService.exe.
///
/// Deployment (Windows 7 / WES7):
///   sc create SentryShield binPath= "C:\Program Files\SentryShield\SentryLegacyService.exe"
///   sc description SentryShield "SentryShield ICS/OT Security Monitor"
///   sc start SentryShield
/// </summary>
internal static class Program
{
    [STAThread]
    private static void Main()
    {
        // ── Configuration ─────────────────────────────────────────────────────
        var configRoot = new ConfigurationBuilder()
            .SetBasePath(AppDomain.CurrentDomain.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: false)
            .Build();

        var config = new LegacyConfig();
        configRoot.GetSection("SentryShield").Bind(config);

        // ── Logging: write to Windows Event Log ───────────────────────────────
        // Ensure the Event Log source exists (requires admin on first run).
        try
        {
            if (!System.Diagnostics.EventLog.SourceExists(config.EventLog.Source))
                System.Diagnostics.EventLog.CreateEventSource(config.EventLog.Source, config.EventLog.Log);
        }
        catch (Exception)
        {
            // If source creation fails (non-admin context), continue anyway.
            // EventLogWriter will catch individual write failures silently.
        }

        // Use a minimal console logger + EventLogWriter combination.
        // On Windows 7 services there is no console, but the logger is still
        // used internally so we wire up a NullLogger fallback.
        ILogger logger = new Microsoft.Extensions.Logging.Abstractions.NullLogger<LegacyServiceHost>();

        // ── Infrastructure ────────────────────────────────────────────────────
        var eventLog  = new EventLogWriter(config.EventLog.Source);
        var historyDb = new ScanHistoryDb(logger, config.Paths.DatabasePath);
        
        var pluginLoader = new PluginLoader(logger, config.Paths.DatabasePath);
        var pluginsDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Plugins");
        if (Directory.Exists(pluginsDir)) pluginLoader.LoadPlugins(pluginsDir);

        var yaraGuard = new LegacyYaraGuard(logger, config);

        // Ensure DB schema is initialised before first scan
        var dbLogger = new Microsoft.Extensions.Logging.Abstractions.NullLogger<DatabaseInitializer>();
        var dbInit = new DatabaseInitializer(dbLogger, config.Paths.DatabasePath);
        dbInit.InitializeAsync().GetAwaiter().GetResult();

        // ── Service ───────────────────────────────────────────────────────────
        var host = new LegacyServiceHost(logger, config, historyDb, pluginLoader, eventLog, yaraGuard);

        ServiceBase.Run(host);
    }
}
