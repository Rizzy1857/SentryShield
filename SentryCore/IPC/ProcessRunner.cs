using System.Diagnostics;
using System.Text;
using Microsoft.Extensions.Logging;

namespace SentryShield.Core.IPC;

/// <summary>
/// Runs Python scripts as subprocesses and captures their JSON stdout output.
///
/// Lives in SentryCore so that detection engines (USBMonitor, SupplierFileValidator)
/// can use it directly without depending on SentryService.
///
/// Architecture note: v1.0 uses subprocess IPC (simpler than Named Pipes).
/// For v2.0: Replace with persistent Named Pipe server if continuous
/// communication (streaming results) is needed.
/// </summary>
public class ProcessRunner
{
    private readonly ILogger _logger;
    private readonly string _pythonExe;
    private readonly string _pythonScriptsPath;
    private readonly string _yaraRulesPath;

    public ProcessRunner(
        ILogger logger,
        string pythonExe,
        string pythonScriptsPath,
        string yaraRulesPath)
    {
        _logger           = logger;
        _pythonExe        = pythonExe;
        _pythonScriptsPath = pythonScriptsPath;
        _yaraRulesPath    = yaraRulesPath;
    }

    // -------------------------------------------------------------------------
    // Public API — Python script invocations
    // -------------------------------------------------------------------------

    /// <summary>
    /// Runs yara_scanner.py on a directory and returns JSON match results.
    /// </summary>
    public virtual async Task<string> RunYaraScanAsync(string scanPath)
    {
        var script = Path.Combine(_pythonScriptsPath, "yara_scanner.py");
        var args   = $"\"{script}\" --scan-dir \"{scanPath}\" --rules \"{_yaraRulesPath}\" --json";
        return await RunPythonAsync(args);
    }

    /// <summary>
    /// Runs yara_scanner.py on a single file and returns JSON match results.
    /// </summary>
    public virtual async Task<string> RunYaraScanFileAsync(string filePath)
    {
        var script = Path.Combine(_pythonScriptsPath, "yara_scanner.py");
        var args   = $"\"{script}\" --scan-file \"{filePath}\" --rules \"{_yaraRulesPath}\" --json";
        return await RunPythonAsync(args);
    }

    /// <summary>
    /// Triggers the NVD feed sync. Returns sync status JSON.
    /// </summary>
    public async Task<string> RunDBSyncAsync(string dbPath)
    {
        var script = Path.Combine(_pythonScriptsPath, "db_sync.py");
        var args   = $"\"{script}\" --db \"{dbPath}\" --json";
        return await RunPythonAsync(args);
    }

    /// <summary>
    /// Triggers the init_db.py script to pull live NVD data. Returns JSON or text log.
    /// </summary>
    public async Task<string> RunInitDbAsync(string dbPath, string nvdKey, Action<string>? onOutputData = null)
    {
        var script = Path.Combine(_pythonScriptsPath, "init_db.py");
        // Use -u to force unbuffered stdout/stderr so the WPF UI receives logs in real-time
        var args = $"-u \"{script}\" --db \"{dbPath}\" --days-back 30";
        // Always pass --nvd-key to override any system environment variables if the user cleared it in the UI
        args += $" --nvd-key \"{nvdKey ?? ""}\"";
        return await RunPythonAsync(args, 300_000, onOutputData); // Allow 5 minutes for massive NVD sync
    }

    // -------------------------------------------------------------------------
    // Core subprocess runner
    // -------------------------------------------------------------------------

    /// <summary>
    /// Spawns a Python process, waits for completion (max 120s), returns stdout.
    /// Logs stderr as warnings.
    /// </summary>
    private async Task<string> RunPythonAsync(string arguments, int timeoutMs = 120_000, Action<string>? onOutputData = null)
    {
        var psi = new ProcessStartInfo
        {
            FileName               = _pythonExe,
            Arguments              = arguments,
            UseShellExecute        = false,
            RedirectStandardOutput = true,
            RedirectStandardError  = true,
            CreateNoWindow         = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding  = Encoding.UTF8
        };

        _logger.LogDebug("[IPC] Running: {Python} {Args}", _pythonExe, arguments);

        using var process = new Process { StartInfo = psi };
        var stdoutBuilder = new StringBuilder();
        var stderrBuilder = new StringBuilder();

        process.OutputDataReceived += (_, e) => { 
            if (e.Data != null) {
                stdoutBuilder.AppendLine(e.Data);
                onOutputData?.Invoke(e.Data);
            }
        };
        process.ErrorDataReceived  += (_, e) => { 
            if (e.Data != null) {
                stderrBuilder.AppendLine(e.Data); 
                onOutputData?.Invoke(e.Data);
            }
        };

        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        using var cts = new CancellationTokenSource(timeoutMs);
        try
        {
#if NET48
            // Task.WaitForExitAsync not available on .NET 4.8 — use thread-pool wait
            await Task.Run(() => process.WaitForExit(timeoutMs), cts.Token);
            if (!process.HasExited)
            {
                process.Kill();
                _logger.LogError("[IPC] Python process timed out after {Timeout}ms — killed", timeoutMs);
                return string.Empty;
            }
#else
            await process.WaitForExitAsync(cts.Token);
#endif
        }
        catch (OperationCanceledException)
        {
#if NET48
            process.Kill();
#else
            process.Kill(entireProcessTree: true);
#endif
            _logger.LogError("[IPC] Python process timed out after {Timeout}ms — killed", timeoutMs);
            return string.Empty;
        }

        if (process.ExitCode != 0)
        {
            _logger.LogWarning("[IPC] Python exited with code {Code}: {Stderr}",
                process.ExitCode, stderrBuilder.ToString().Trim());
        }
        else if (stderrBuilder.Length > 0)
        {
            _logger.LogDebug("[IPC] Python stderr: {Stderr}", stderrBuilder.ToString().Trim());
        }

        return stdoutBuilder.ToString().Trim();
    }
}
