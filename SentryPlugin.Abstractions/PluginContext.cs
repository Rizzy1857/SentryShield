using Microsoft.Extensions.Logging;

namespace SentryShield.Plugin.Abstractions
{
    /// <summary>
    /// The host-provided context object injected into every plugin via
    /// <see cref="IDetectionPlugin.Initialize"/>. Cache this instance in your
    /// plugin's constructor or <c>Initialize</c> method.
    /// <para>
    /// <see cref="PluginContext"/> is the plugin's only bridge to shared host resources.
    /// Do not take dependencies on any other Core or Service assembly — doing so breaks
    /// plugin isolation and will cause <see cref="System.Reflection.ReflectionTypeLoadException"/>
    /// when the plugin DLL is loaded into its isolated <c>AssemblyLoadContext</c>.
    /// </para>
    /// </summary>
    public class PluginContext
    {
        /// <summary>
        /// The shared <see cref="ILogger"/> instance scoped to this plugin.
        /// All log messages written through this logger are prefixed with the plugin's
        /// category name in the Windows Event Log and console output.
        /// <para>Usage: <c>_context.Logger.LogInformation("[MyPlugin] Scan complete.")</c></para>
        /// </summary>
        public ILogger Logger { get; }

        /// <summary>
        /// The absolute path to the shared SentryShield SQLite database file.
        /// Plugins that need to look up IOC hashes, CVEs, or write findings should
        /// open a connection to this path using <c>Microsoft.Data.Sqlite</c>.
        /// <para>Default production path: <c>C:\ProgramData\SentryShield\sentryshield.db</c></para>
        /// <para>
        /// Tip: Open connections with <c>FileShare.ReadWrite</c> to allow concurrent access
        /// from multiple plugins without exclusive locking conflicts.
        /// </para>
        /// </summary>
        public string GlobalDatabasePath { get; }

        /// <summary>
        /// Initializes a new <see cref="PluginContext"/> with required services.
        /// This constructor is called by the Core <c>PluginLoader</c> — you do not call it directly.
        /// </summary>
        /// <param name="logger">The logger instance scoped to the plugin category.</param>
        /// <param name="globalDatabasePath">The absolute path to the shared SQLite database.</param>
        public PluginContext(ILogger logger, string globalDatabasePath)
        {
            Logger = logger;
            GlobalDatabasePath = globalDatabasePath;
        }
    }
}
