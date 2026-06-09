using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace SentryShield.Plugin.Abstractions
{
    /// <summary>
    /// The core interface that all SentryShield detection plugins must implement.
    /// This interface is frozen — do not add new members without a versioning discussion.
    /// <para>
    /// To create a new plugin, copy the <c>Templates/SentryPlugin.Template</c> folder,
    /// rename it, and implement <see cref="ExecuteAsync"/>.
    /// </para>
    /// </summary>
    public interface IDetectionPlugin
    {
        /// <summary>
        /// The human-readable display name of the plugin.
        /// This name is used as a key by the <see cref="SentryShield.Core.PluginLoader"/>
        /// and appears in all log messages and the UI findings view.
        /// <para>Example: <c>"Vulnerability Scanner"</c>, <c>"USB Monitor"</c></para>
        /// </summary>
        string Name { get; }

        /// <summary>
        /// The semantic version string of the plugin.
        /// Used for diagnostics and compatibility checks.
        /// <para>Example: <c>"1.0.0"</c></para>
        /// </summary>
        string Version { get; }

        /// <summary>
        /// Called exactly once when the plugin is loaded by the Core engine at startup.
        /// Use this method to cache the <paramref name="context"/> reference, open
        /// database connections, or perform any one-time setup.
        /// </summary>
        /// <param name="context">
        /// The host-provided context containing the shared logger, database path,
        /// and configuration. Store this reference for use in <see cref="ExecuteAsync"/>.
        /// </param>
        void Initialize(PluginContext context);

        /// <summary>
        /// The main execution method. The Core engine calls this on its scan interval.
        /// Perform all detection logic here and return a list of findings.
        /// </summary>
        /// <param name="parameters">
        /// A dictionary of dynamic parameters passed from the engine or UI at call time.
        /// Common keys include:
        /// <list type="bullet">
        ///   <item><description><c>"cancellationToken"</c> — a <see cref="System.Threading.CancellationToken"/> for cooperative cancellation. Always check this when performing long-running I/O.</description></item>
        ///   <item><description><c>"TargetSoftware"</c> / <c>"TargetVersion"</c> — passed when invoked by <c>SupplierFileValidator</c> for SBOM checks.</description></item>
        ///   <item><description><c>"Action"</c> — passed to <c>RemediationPlugin</c> (e.g., <c>"IsolateNetwork"</c>).</description></item>
        /// </list>
        /// Not all keys will be present on every call. Always use <c>TryGetValue</c>.
        /// </param>
        /// <returns>
        /// A list of <see cref="DetectionResult"/> objects. Return an empty list if no
        /// findings are detected. Never return <c>null</c>.
        /// </returns>
        Task<List<DetectionResult>> ExecuteAsync(Dictionary<string, object> parameters);
    }
}
