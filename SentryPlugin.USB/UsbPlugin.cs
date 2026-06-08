using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SentryShield.Plugin.Abstractions;

namespace SentryShield.Plugin.USB
{
    public class UsbPlugin : IDetectionPlugin
    {
        public string Name => "USB Threat Detector";
        public string Version => "2.0.0";

        private PluginContext? _context;
        private USBMonitor? _monitor;

        public void Initialize(PluginContext context)
        {
            _context = context;
            _monitor = new USBMonitor(context.Logger, context.GlobalDatabasePath);
        }

        public async Task<List<DetectionResult>> ExecuteAsync(Dictionary<string, object> parameters)
        {
            if (_context == null || _monitor == null)
                throw new InvalidOperationException("Plugin not initialized.");

            var results = new List<DetectionResult>();

            // If a specific drive path is passed, scan just that drive
            if (parameters.TryGetValue("DrivePath", out var pathObj) && pathObj is string drivePath)
            {
                var threats = await _monitor.ScanUSBDriveAsync(drivePath);
                results.AddRange(threats.Select(MapToResult));
            }
            else
            {
                // Otherwise scan all currently attached removable drives
                var removableDrives = DriveInfo.GetDrives()
                    .Where(d => d.DriveType == DriveType.Removable && d.IsReady)
                    .ToList();

                if (!removableDrives.Any())
                {
                    _context.Logger.LogInformation("UsbPlugin: No removable drives found.");
                    return results;
                }

                foreach (var drive in removableDrives)
                {
                    var threats = await _monitor.ScanUSBDriveAsync(drive.RootDirectory.FullName);
                    results.AddRange(threats.Select(MapToResult));
                }
            }

            return results;
        }

        private DetectionResult MapToResult(USBThreat t)
        {
            return new DetectionResult
            {
                Title = $"USB Threat: {t.ThreatType}",
                Severity = t.Severity,
                Description = t.Description,
                Remediation = t.Remediation,
                Target = t.FilePath,
                AdditionalData = new Dictionary<string, string>
                {
                    { "DevicePath", t.DevicePath },
                    { "FileName", t.FileName }
                }
            };
        }
    }
}
