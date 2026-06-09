using System.Collections.Generic;

namespace SentryShield.Plugin.Abstractions
{
    /// <summary>
    /// A unified result object returned by every <see cref="IDetectionPlugin.ExecuteAsync"/> call.
    /// The Core engine maps these directly into <c>Finding</c> records persisted to the database
    /// and displayed in the SentryUI findings grid.
    /// <para>
    /// All properties have safe non-null defaults. You do not need to set every field — only
    /// set what is meaningful for your plugin's findings.
    /// </para>
    /// </summary>
    public class DetectionResult
    {
        /// <summary>
        /// A short, human-readable title for the finding.
        /// This is the primary display string shown in the SentryUI findings grid.
        /// <para>Example: <c>"CVE-2023-4863 — libwebp Critical RCE"</c></para>
        /// </summary>
        public string Title { get; set; } = string.Empty;

        /// <summary>
        /// The severity level of the finding.
        /// Must be one of: <c>"CRITICAL"</c>, <c>"HIGH"</c>, <c>"MEDIUM"</c>, <c>"LOW"</c>, or <c>"INFO"</c>.
        /// The Core engine auto-triggers <c>RemediationPlugin</c> for any <c>CRITICAL</c> finding.
        /// Defaults to <c>"MEDIUM"</c>.
        /// </summary>
        public string Severity { get; set; } = "MEDIUM";

        /// <summary>
        /// A full description of the finding, explaining what was detected and why it is significant.
        /// <para>Example: <c>"Component libwebp 1.3.1 is affected by CVE-2023-4863. CVSS 10.0."</c></para>
        /// </summary>
        public string Description { get; set; } = string.Empty;

        /// <summary>
        /// Human-readable remediation steps for the operator to follow.
        /// Write these as numbered steps. They are displayed verbatim in the UI and Event Log.
        /// <para>Example: <c>"1. Update libwebp to v1.3.2 or later. 2. Reboot the affected service."</c></para>
        /// </summary>
        public string Remediation { get; set; } = string.Empty;

        /// <summary>
        /// The component, file, process, or device that the finding relates to.
        /// Used as the "Affected Component" column in the findings view.
        /// <para>Example: <c>"libwebp v1.3.1"</c>, <c>"D:\autorun.inf"</c>, <c>"svchost.exe (PID 1234)"</c></para>
        /// </summary>
        public string Target { get; set; } = string.Empty;

        /// <summary>
        /// A flexible dictionary for plugin-specific metadata that doesn't fit the standard fields.
        /// The Core engine stores this as serialized JSON in the database.
        /// <para>
        /// Common conventions used by existing plugins:
        /// <list type="bullet">
        ///   <item><description><c>"CVE"</c> — the CVE identifier (e.g., <c>"CVE-2023-4863"</c>)</description></item>
        ///   <item><description><c>"CVSS"</c> — the CVSS score as a string (e.g., <c>"10.0"</c>)</description></item>
        ///   <item><description><c>"RuleMatch"</c> — the YARA rule name that matched</description></item>
        ///   <item><description><c>"FileHash"</c> — the SHA-256 of an offending file</description></item>
        /// </list>
        /// </para>
        /// </summary>
        public Dictionary<string, string> AdditionalData { get; set; } = new Dictionary<string, string>();
    }
}
