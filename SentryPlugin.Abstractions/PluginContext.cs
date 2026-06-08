using Microsoft.Extensions.Logging;

namespace SentryShield.Plugin.Abstractions
{
    /// <summary>
    /// Context injected into each plugin during initialization.
    /// Provides access to core services like logging and global paths.
    /// </summary>
    public class PluginContext
    {
        public ILogger Logger { get; }
        public string GlobalDatabasePath { get; }

        public PluginContext(ILogger logger, string globalDatabasePath)
        {
            Logger = logger;
            GlobalDatabasePath = globalDatabasePath;
        }
    }
}
