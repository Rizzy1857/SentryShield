using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SharpPcap;
using PacketDotNet;
using SentryShield.Plugin.Abstractions;
using Microsoft.Data.Sqlite;
using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("SentryCore.Tests")]

namespace SentryShield.Plugin.IDS
{
    public class IDSPlugin : IDetectionPlugin
    {
        public string Name => "IDSPlugin";
        public string Version => "1.0.0";

        private PluginContext _context;
        private readonly int[] _allowedPorts = { 102, 502, 44818, 80, 443 };
        private readonly ConcurrentQueue<DetectionResult> _findings = new ConcurrentQueue<DetectionResult>();
        private readonly ConcurrentDictionary<IPAddress, int> _packetCounts = new ConcurrentDictionary<IPAddress, int>();
        private DateTime _lastCountReset = DateTime.UtcNow;
        private HashSet<string> _badIps = new HashSet<string>();
        // Keep track of reported alerts to prevent spamming
        private ConcurrentDictionary<string, bool> _reportedAlerts = new ConcurrentDictionary<string, bool>();

        public void Initialize(PluginContext context)
        {
            _context = context;
            LoadBadIps();
        }

        private void LoadBadIps()
        {
            // IOCDb stores file hashes only — IP IOC table is a v3.0 addition
            // Bad IP detection currently uses hardcoded list only
            _context.Logger?.LogInformation("[IDS] IP IOC lookup not yet available — skipping.");
        }

        public Task<List<DetectionResult>> ExecuteAsync(Dictionary<string, object> parameters)
        {
            var ct = parameters.ContainsKey("cancellationToken")
                ? (CancellationToken)parameters["cancellationToken"]
                : CancellationToken.None;
            return ScanAsync(ct);
        }

        public async Task<List<DetectionResult>> ScanAsync(CancellationToken ct = default)
        {
            var results = new List<DetectionResult>();
            _packetCounts.Clear();
            _reportedAlerts.Clear();
            _lastCountReset = DateTime.UtcNow;

            try
            {
                var devices = CaptureDeviceList.Instance;
                if (devices.Count == 0)
                {
                    _context.Logger?.LogWarning("[IDS] No network capture devices found. Falling back gracefully.");
                    return results;
                }

                foreach (var device in devices)
                {
                    device.OnPacketArrival += Device_OnPacketArrival;
                    try
                    {
                        device.Open(DeviceModes.Promiscuous, 1000);
                        device.StartCapture();
                    }
                    catch (Exception ex)
                    {
                        _context.Logger?.LogWarning(ex, $"[IDS] Could not open device {device.Name}");
                    }
                }

                _context.Logger?.LogInformation("[IDS] Capture started. Monitoring traffic...");

                // Run for a fixed 15 second monitoring window for the test/scan interval
                await Task.Delay(TimeSpan.FromSeconds(15), ct);

                foreach (var device in devices)
                {
                    try
                    {
                        device.StopCapture();
                        device.Close();
                        device.OnPacketArrival -= Device_OnPacketArrival;
                    }
                    catch { /* ignore cleanup errors */ }
                }
            }
            catch (Exception ex)
            {
                _context.Logger?.LogError(ex, "[IDS] Fatal error during packet capture.");
            }

            while (_findings.TryDequeue(out var finding))
            {
                results.Add(finding);
            }

            return results;
        }

        public void OnAlert(DetectionResult result)
        {
            _context.Logger?.LogWarning($"[IDS ALERT] {result.Title}: {result.Description}");
        }

        private void Device_OnPacketArrival(object sender, PacketCapture e)
        {
            var rawPacket = e.GetPacket();
            ProcessRawPacket(rawPacket);
        }

        internal void ProcessRawPacket(RawCapture rawPacket)
        {
            try
            {
                var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
                
                var ipPacket = packet.Extract<IPPacket>();
                if (ipPacket == null) return;

                var srcIp = ipPacket.SourceAddress;
                var dstIp = ipPacket.DestinationAddress;

                // 1. High Packet Rate (>1000/min baseline)
                var count = _packetCounts.AddOrUpdate(srcIp, 1, (_, c) => c + 1);
                
                if ((DateTime.UtcNow - _lastCountReset).TotalMinutes >= 1.0)
                {
                    _packetCounts.Clear();
                    _lastCountReset = DateTime.UtcNow;
                }
                else if (count == 1000) 
                {
                    AddFinding("High Packet Rate", "HIGH", $"IP {srcIp} exceeded 1000 packets/minute.", srcIp.ToString(), dstIp.ToString(), "PacketFlood");
                }

                // 2. Known Bad IP
                string srcIpStr = srcIp.ToString();
                string dstIpStr = dstIp.ToString();
                if (_badIps.Contains(srcIpStr) || _badIps.Contains(dstIpStr))
                {
                    var badIp = _badIps.Contains(srcIpStr) ? srcIpStr : dstIpStr;
                    AddFinding("Known Bad IP Contact", "CRITICAL", $"Traffic detected involving known malicious IP: {badIp}", srcIpStr, dstIpStr, "IOCMatch");
                }

                // 3. Unusual outbound ports
                var tcpPacket = packet.Extract<TcpPacket>();
                var udpPacket = packet.Extract<UdpPacket>();
                
                int dstPort = -1;
                if (tcpPacket != null) dstPort = tcpPacket.DestinationPort;
                else if (udpPacket != null) dstPort = udpPacket.DestinationPort;

                if (dstPort != -1 && !_allowedPorts.Contains(dstPort))
                {
                    // Filter known ephemeral/broadcast ports to reduce noise if needed, but per requirements we just check exact list.
                    AddFinding("Unusual Port Usage", "MEDIUM", $"Traffic detected to non-OT port: {dstPort}", srcIpStr, dstIpStr, "UnusualPort");
                }
            }
            catch
            {
                // Ignore parse errors on individual packets
            }
        }

        private void AddFinding(string title, string severity, string desc, string src, string dst, string rule)
        {
            var key = $"{title}_{src}_{dst}_{rule}";
            if (!_reportedAlerts.TryAdd(key, true)) return; // Already reported this specific flow

            var res = new DetectionResult
            {
                Title = title,
                Severity = severity,
                Description = desc,
                Target = dst,
                AdditionalData = new Dictionary<string, string>
                {
                    { "SourceIP", src },
                    { "DestinationIP", dst },
                    { "RuleName", rule }
                }
            };
            
            _findings.Enqueue(res);
            OnAlert(res);
        }
    }
}
