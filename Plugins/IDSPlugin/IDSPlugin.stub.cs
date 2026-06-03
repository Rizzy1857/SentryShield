// ============================================================================
// SentryShield v2.0 — IDS Plugin Stub
// STATUS: NOT IMPLEMENTED — Deferred from v1.0 scope
//
// Per idea.md: "IDS/IPS not applicable to air-gapped networks" in v1.0.
// This file exists to demonstrate the IDetectionPlugin architecture.
// Implement in v2.0 for networks with external connectivity.
//
// To activate: Implement ScanAsync(), register in DI container,
// configure PLCSubnetRange in appsettings.json.
// ============================================================================

using SentryShield.Core.Interfaces;
using SentryShield.Core.Models;
using Microsoft.Extensions.Logging;

namespace SentryShield.Plugins.IDS;

/// <summary>
/// IDS Plugin — Network anomaly detection for OT/ICS networks.
///
/// v2.0 planned features:
///   - Monitor traffic to/from PLC subnet (192.168.100.0/24 by default)
///   - Alert on unexpected protocols (non-Modbus/EtherNet-IP traffic to PLC range)
///   - Alert on scanning patterns (sequential port probing)
///   - Alert on traffic volume anomalies (baseline deviation)
///   - Suricata rule integration for signature-based detection
///
/// Implementation guide for v2.0:
///   1. Use SharpPcap or Npcap for packet capture on Windows
///   2. Load Suricata-compatible rules from rules/ids/
///   3. Maintain a 24-hour baseline of normal traffic patterns
///   4. Alert when deviation > 2 standard deviations from baseline
/// </summary>
public class IDSPlugin : IDetectionPlugin
{
    public string Name => "IDSPlugin";

    private readonly ILogger _logger;

    public IDSPlugin(ILogger logger)
    {
        _logger = logger;
    }

    public void Initialize(Dictionary<string, string> config)
    {
        _logger.LogInformation("[IDS] Plugin initialized (STUB — not active in v1.0)");
        // v2.0: Parse PLCSubnetRange, load Suricata rules, start Pcap listener
    }

    public Task<List<Finding>> ScanAsync(CancellationToken ct = default)
    {
        _logger.LogInformation("[IDS] ScanAsync called — not implemented in v1.0");
        // v2.0: Return network anomaly findings
        return Task.FromResult(new List<Finding>());
    }

    public void OnAlert(Finding finding)
    {
        _logger.LogWarning("[IDS] Alert: {Title}", finding.Title);
        // v2.0: Send alert to SIEM, trigger response playbook
    }
}
