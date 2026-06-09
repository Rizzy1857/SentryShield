using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SentryShield.Plugin.Abstractions;

namespace SentryShield.Plugin.Template
{
    /// <summary>
    /// STEP 1: Rename this class to match your plugin (e.g., MeshPlugin, MemoryScanPlugin).
    /// STEP 2: Rename the namespace to match your plugin project.
    /// STEP 3: Implement the logic inside ExecuteAsync.
    ///
    /// That's it. The PluginLoader discovers this automatically from the Plugins/ folder.
    /// </summary>
    public class TemplatePlugin : IDetectionPlugin
    {
        // -----------------------------------------------------------------------
        // IDetectionPlugin contract — Name and Version are read-only identifiers
        // -----------------------------------------------------------------------

        /// <inheritdoc/>
        /// STEP 4: Change this to your plugin's display name.
        /// This string is used as the primary key in the UI and log messages.
        public string Name => "Template Plugin";

        /// <inheritdoc/>
        /// STEP 5: Set your semantic version.
        public string Version => "1.0.0";

        // -----------------------------------------------------------------------
        // Private state — populated during Initialize, used during ExecuteAsync
        // -----------------------------------------------------------------------

        private ILogger? _logger;
        private string? _dbPath;

        // -----------------------------------------------------------------------
        // Initialization — called once at plugin load time
        // -----------------------------------------------------------------------

        /// <inheritdoc/>
        public void Initialize(PluginContext context)
        {
            // Cache everything you need from the context here.
            // This is the ONLY time you receive it.
            _logger = context.Logger;
            _dbPath = context.GlobalDatabasePath;

            _logger.LogInformation("[{Plugin}] Initialized. DB path: {DbPath}", Name, _dbPath);
        }

        // -----------------------------------------------------------------------
        // Main execution — called on each scan interval by the SentryWorker
        // -----------------------------------------------------------------------

        /// <inheritdoc/>
        public async Task<List<DetectionResult>> ExecuteAsync(Dictionary<string, object> parameters)
        {
            // Always try to extract a cancellation token first.
            // The engine enforces a hard 5-minute timeout via this token.
            var ct = parameters.TryGetValue("cancellationToken", out var ctObj) && ctObj is CancellationToken token
                ? token
                : CancellationToken.None;

            _logger?.LogInformation("[{Plugin}] Executing scan...", Name);

            var results = new List<DetectionResult>();

            // ---------------------------------------------------------------
            // STEP 6: Replace this stub with your detection logic.
            // ---------------------------------------------------------------

            // Example: yield a single finding
            // results.Add(new DetectionResult
            // {
            //     Title        = "Example Finding",
            //     Severity     = "HIGH",
            //     Description  = "Something suspicious was detected.",
            //     Remediation  = "1. Investigate. 2. Remediate.",
            //     Target       = "affected-component-name",
            //     AdditionalData = new Dictionary<string, string>
            //     {
            //         { "CVE", "CVE-2024-12345" },
            //         { "CVSS", "9.8" }
            //     }
            // });

            await Task.CompletedTask; // Remove this when you add real async I/O

            _logger?.LogInformation("[{Plugin}] Scan complete. {Count} finding(s).", Name, results.Count);
            return results;
        }
    }
}
