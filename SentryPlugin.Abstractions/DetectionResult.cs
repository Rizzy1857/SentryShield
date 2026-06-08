using System.Collections.Generic;

namespace SentryShield.Plugin.Abstractions
{
    /// <summary>
    /// A unified data structure that all plugins return.
    /// The host application translates these into its internal models.
    /// </summary>
    public class DetectionResult
    {
        public string Title { get; set; } = string.Empty;
        public string Severity { get; set; } = "MEDIUM";
        public string Description { get; set; } = string.Empty;
        public string Remediation { get; set; } = string.Empty;
        public string Target { get; set; } = string.Empty;
        public Dictionary<string, string> AdditionalData { get; set; } = new Dictionary<string, string>();
    }
}
