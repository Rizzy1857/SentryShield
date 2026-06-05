using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using SentryShield.Core.Engines;
using SentryShield.Database;


namespace SentryShield.LegacyService;

/// <summary>
/// YARA scan guard for the legacy service.
///
/// Wraps subprocess invocation with a startup probe and per-scan fallback.
/// Design decisions:
///   - Probes Python availability once at startup via `python --version`.
///   - If probe fails or EnableYaraScanning = false: _available = false,
///     all scan requests return an empty list immediately.
///   - If a live scan subprocess throws mid-flight: logs WARNING, returns
///     empty list. YARA being broken NEVER crashes or stalls the service.
/// </summary>
internal sealed class LegacyYaraGuard
{
    private readonly ILogger _logger;
    private readonly bool _enabled;
    private readonly string _pythonExe;
    private volatile bool _available;

    public LegacyYaraGuard(ILogger logger, LegacyConfig config)
    {
        _logger  = logger;
        _enabled = config.Yara.EnableYaraScanning;
        _pythonExe = config.Yara.PythonExe;
        _available = false;
    }

    // Called once during OnStart before the scan timer starts.
    public void Probe()
    {
        if (!_enabled)
        {
            _logger.LogWarning(
                "[LegacyYaraGuard] YARA scanning is disabled in appsettings.json. " +
                "Only IOC hash and entropy checks will run.");
            return;
        }

        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName               = _pythonExe,
                Arguments              = "--version",
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false,
                CreateNoWindow         = true
            };

            using var proc = System.Diagnostics.Process.Start(psi);
            if (proc == null)
                throw new InvalidOperationException("Process.Start returned null");

            proc.WaitForExit(5000); // 5-second timeout
            if (proc.ExitCode == 0)
            {
                _available = true;
                var ver = proc.StandardOutput.ReadToEnd().Trim();
                if (string.IsNullOrWhiteSpace(ver))
                    ver = proc.StandardError.ReadToEnd().Trim();
                _logger.LogInformation(
                    "[LegacyYaraGuard] Python available: {Version}. YARA scanning enabled.", ver);
            }
            else
            {
                _logger.LogWarning(
                    "[LegacyYaraGuard] Python probe returned exit code {Code}. " +
                    "YARA scanning will be skipped — IOC hash and entropy checks still active.",
                    proc.ExitCode);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(
                "[LegacyYaraGuard] Python probe failed: {Message}. " +
                "YARA scanning will be skipped — IOC hash and entropy checks still active.",
                ex.Message);
        }
    }

    /// <summary>
    /// Returns true when YARA should be attempted for a given drive or file scan.
    /// </summary>
    public bool IsAvailable => _available;

    /// <summary>
    /// Wraps a YARA scan call with graceful error handling.
    /// Returns null (caller should skip YARA result) if scan fails.
    /// </summary>
    public async System.Threading.Tasks.Task<string?> RunScanSafeAsync(
        System.Func<System.Threading.Tasks.Task<string>> scanFunc)
    {
        if (!_available)
            return null;

        try
        {
            return await scanFunc();
        }
        catch (Exception ex)
        {
            _logger.LogWarning(
                "[LegacyYaraGuard] YARA scan failed: {Message}. " +
                "Continuing without YARA result for this scan cycle.",
                ex.Message);
            // Mark unavailable temporarily — will retry on next service restart
            _available = false;
            return null;
        }
    }
}
