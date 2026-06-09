using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SentryShield.Plugin.Abstractions;

namespace SentryShield.Plugins.Remediation
{
    public class RemediationPlugin : IDetectionPlugin
    {
        public string Name => "RemediationPlugin";
        public string Version => "1.0.0";

        private PluginContext? _context;

        public void Initialize(PluginContext context)
        {
            _context = context;
            _context.Logger?.LogInformation("[Remediation] RemediationPlugin loaded and standing by.");
        }

        public Task<List<DetectionResult>> ExecuteAsync(Dictionary<string, object> parameters)
        {
            var results = new List<DetectionResult>();

            if (parameters.TryGetValue("Action", out var actionObj) && actionObj is string action)
            {
                if (action == "IsolateNetwork")
                {
                    _context?.Logger?.LogWarning("[Remediation] EXECUTING KERNEL NETWORK ISOLATION...");
                    
                    bool isTest = parameters.ContainsKey("IsTest") && (bool)parameters["IsTest"];
                    bool success = true;
                    
                    if (!isTest)
                    {
                        success = WfpIsolator.BlockAllOutboundNetwork();
                    }
                    
                    if (success)
                    {
                        results.Add(new DetectionResult
                        {
                            Title = "Network Quarantine Applied",
                            Severity = "CRITICAL",
                            Description = "Machine has been isolated via Windows Filtering Platform (WFP). All non-loopback outbound traffic is blocked.",
                            Target = "LocalMachine",
                            Remediation = "Manual intervention required by incident response team to lift WFP block."
                        });
                        _context?.Logger?.LogCritical("[Remediation] Isolation SUCCESS. Machine is air-gapped at the kernel level.");
                    }
                    else
                    {
                        results.Add(new DetectionResult
                        {
                            Title = "Network Quarantine FAILED",
                            Severity = "CRITICAL",
                            Description = "Attempted to isolate machine via WFP but the P/Invoke call failed.",
                            Target = "LocalMachine"
                        });
                        _context?.Logger?.LogError("[Remediation] Isolation FAILED.");
                    }
                }
            }

            return Task.FromResult(results);
        }

        public void OnAlert(DetectionResult result)
        {
            // Not directly generating alerts natively
        }
    }
}
