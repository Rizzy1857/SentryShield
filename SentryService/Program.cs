using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SentryShield.Database;
using SentryShield.Service.IPC;
using SentryShield.Service.Watchers;

namespace SentryShield.Service;

/// <summary>
/// Entry point for the SentryShield Windows Service.
/// Wires up DI, configuration, and hosted services.
/// </summary>
internal class Program
{
    public static async Task Main(string[] args)
    {
        var host = Host.CreateDefaultBuilder(args)
            .UseWindowsService(options =>
            {
                options.ServiceName = "SentryShield";
            })
            .ConfigureServices((context, services) =>
            {
                var config = context.Configuration;

                // Configuration
                services.Configure<SentryOptions>(config.GetSection("Service"));
                services.Configure<ScanningOptions>(config.GetSection("Scanning"));
                services.Configure<DatabaseOptions>(config.GetSection("Database"));
                services.Configure<PathOptions>(config.GetSection("Paths"));
                services.Configure<SupplierOptions>(config.GetSection("Supplier"));

                // Database
                services.AddSingleton<DatabaseInitializer>();
                services.AddSingleton<VulnerabilityDb>();
                services.AddSingleton<IOCDb>();
                services.AddSingleton<ScanHistoryDb>();

                // Python process runner (IPC bridge)
                services.AddSingleton<ProcessRunner>();

                // Watchers
                services.AddSingleton<GatewayFolderWatcher>();

                // Background service (main scan orchestrator)
                services.AddHostedService<SentryWorker>();
            })
            .ConfigureLogging((context, logging) =>
            {
                logging.ClearProviders();
                logging.AddEventLog(settings =>
                {
                    settings.SourceName = "SentryShield";
                });
                logging.AddConsole();
            })
            .Build();

        // Ensure DB is initialized before starting
        using (var scope = host.Services.CreateScope())
        {
            var dbInit = scope.ServiceProvider.GetRequiredService<DatabaseInitializer>();
            await dbInit.InitializeAsync();
        }

        await host.RunAsync();
    }
}
