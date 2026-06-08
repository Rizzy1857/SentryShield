using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace SentryShield.Plugin.Abstractions
{
    /// <summary>
    /// The core interface that all SentryShield detection plugins must implement.
    /// </summary>
    public interface IDetectionPlugin
    {
        /// <summary>
        /// The name of the plugin (e.g., "Vulnerability Scanner").
        /// </summary>
        string Name { get; }

        /// <summary>
        /// The version of the plugin.
        /// </summary>
        string Version { get; }

        /// <summary>
        /// Called once when the plugin is loaded by the Core engine.
        /// </summary>
        void Initialize(PluginContext context);

        /// <summary>
        /// The main execution method. The plugin performs its logic and returns results.
        /// </summary>
        /// <param name="parameters">Dynamic parameters passed from the engine or UI.</param>
        Task<List<DetectionResult>> ExecuteAsync(Dictionary<string, object> parameters);
    }
}
