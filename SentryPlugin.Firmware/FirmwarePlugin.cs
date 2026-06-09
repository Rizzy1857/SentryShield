using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using SentryShield.Plugin.Abstractions;

namespace SentryShield.Plugin.Firmware
{
    public class FirmwarePlugin : IDetectionPlugin
    {
        private PluginContext? _context;
        private ILogger? _logger;

        public string Name => "Firmware Integrity Scanner";
        public string Version => "2.5.0-alpha";

        public void Initialize(PluginContext context)
        {
            _context = context;
            _logger = context.Logger;
            _logger?.LogInformation("[FirmwarePlugin] Initialized RSMB Scanner.");
        }

        public Task<List<DetectionResult>> ExecuteAsync(Dictionary<string, object> parameters)
        {
            var results = new List<DetectionResult>();
            if (_logger == null) return Task.FromResult(results);

            try
            {
                // The provider signature for Raw SMBIOS is "RSMB" -> 0x424D5352
                const uint rsmbSignature = 0x424D5352;
                
                // 1. EnumSystemFirmwareTables to verify RSMB is available and get required buffer size
                uint enumBufferSize = NativeMethods.EnumSystemFirmwareTables(rsmbSignature, IntPtr.Zero, 0);
                if (enumBufferSize == 0)
                {
                    _logger.LogWarning("[FirmwarePlugin] EnumSystemFirmwareTables returned 0. Raw SMBIOS tables may not be supported or access is denied (Admin rights may be required).");
                    return Task.FromResult(results);
                }

                IntPtr pEnumBuffer = IntPtr.Zero;
                try
                {
                    // Allocate unmanaged memory based on the exact size required
                    pEnumBuffer = Marshal.AllocHGlobal((int)enumBufferSize);
                    uint actualEnumSize = NativeMethods.EnumSystemFirmwareTables(rsmbSignature, pEnumBuffer, enumBufferSize);
                    
                    if (actualEnumSize == 0 || actualEnumSize > enumBufferSize)
                    {
                        _logger.LogWarning("[FirmwarePlugin] Failed to enumerate RSMB tables.");
                        return Task.FromResult(results);
                    }
                }
                finally
                {
                    if (pEnumBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(pEnumBuffer);
                    }
                }

                // 2. GetSystemFirmwareTable to read the actual SMBIOS table (TableID = 0x00000000)
                uint tableId = 0x00000000;
                
                // First call with size 0 to get the exact required buffer size
                uint requiredSize = NativeMethods.GetSystemFirmwareTable(rsmbSignature, tableId, IntPtr.Zero, 0);

                if (requiredSize == 0)
                {
                    _logger.LogWarning("[FirmwarePlugin] GetSystemFirmwareTable returned 0. Access denied or table not found.");
                    return Task.FromResult(results);
                }

                IntPtr pTableBuffer = IntPtr.Zero;
                byte[] rawSmbiosData;

                try
                {
                    // Allocate unmanaged memory securely
                    pTableBuffer = Marshal.AllocHGlobal((int)requiredSize);
                    uint actualSize = NativeMethods.GetSystemFirmwareTable(rsmbSignature, tableId, pTableBuffer, requiredSize);

                    if (actualSize == 0 || actualSize > requiredSize)
                    {
                        _logger.LogWarning("[FirmwarePlugin] Failed to read the RSMB firmware table.");
                        return Task.FromResult(results);
                    }

                    // Securely copy unmanaged memory to managed byte array without unsafe code
                    rawSmbiosData = new byte[actualSize];
                    Marshal.Copy(pTableBuffer, rawSmbiosData, 0, (int)actualSize);
                }
                finally
                {
                    if (pTableBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(pTableBuffer);
                    }
                }

                // 3. Compute SHA-256 Hash
                using var sha256 = SHA256.Create();
                byte[] hashBytes = sha256.ComputeHash(rawSmbiosData);
                string hashString = BitConverter.ToString(hashBytes).Replace("-", "").ToLowerInvariant();

                _logger.LogInformation("[FirmwarePlugin] Successfully read {Bytes} bytes of raw SMBIOS data. Hash: {Hash}", rawSmbiosData.Length, hashString);

                // 4. Return INFO detection result
                var result = new DetectionResult
                {
                    Title = "Raw SMBIOS Integrity Hash",
                    Description = $"RSMB Table SHA-256 Hash: {hashString}. Validated {rawSmbiosData.Length} bytes via GetSystemFirmwareTable.",
                    Severity = "INFO",
                    Remediation = "N/A - Alpha Phase Baseline",
                    Target = "Hardware/BIOS"
                };
                result.AdditionalData["PluginName"] = this.Name;
                results.Add(result);
            }
            catch (Exception ex)
            {
                // Graceful fallback without crashing the orchestrator
                _logger?.LogWarning(ex, "[FirmwarePlugin] Unexpected error while querying system firmware tables.");
            }

            return Task.FromResult(results);
        }
    }
}
