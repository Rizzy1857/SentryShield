using System.Diagnostics;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace SentryShield.Service.IPC;

/// <summary>
/// Runs Python scripts as subprocesses and captures their JSON stdout output.
///
/// Architecture decision: v1.0 uses subprocess IPC (simpler than Named Pipes).
/// C# service spawns Python scripts on-demand, reads JSON from stdout, and
/// handles stderr/exit codes for error reporting.
///
/// For v2.0: Replace with persistent Named Pipe server if continuous
/// communication (streaming results) is needed.
/// </summary>
public class ProcessRunner
{
    private readonly ILogger<ProcessRunner> _logger;
    private readonly PathOptions _pathOptions;

    public ProcessRunner(ILogger<ProcessRunner> logger, IOptions<PathOptions> pathOptions)
    {
        _logger = logger;
        _pathOptions = pathOptions.Value;
    }

    // -------------------------------------------------------------------------
    // Public API — Python script invocations
    // -------------------------------------------------------------------------

    /// <summary>
    /// Runs yara_scanner.py on a directory and returns JSON match results.
    /// </summary>
    public async Task<string> RunYaraScanAsync(string scanPath)
    {
        var script = Path.Combine(_pathOptions.PythonScriptsPath, "yara_scanner.py");
        var args = $"\"{script}\" --scan-dir \"{scanPath}\" --rules \"{_pathOptions.YaraRulesPath}\" --json";
        return await RunPythonAsync(args);
    }

    /// <summary>
    /// Runs yara_scanner.py on a single file and returns JSON match results.
    /// </summary>
    public async Task<string> RunYaraScanFileAsync(string filePath)
    {
        var script = Path.Combine(_pathOptions.PythonScriptsPath, "yara_scanner.py");
        var args = $"\"{script}\" --scan-file \"{filePath}\" --rules \"{_pathOptions.YaraRulesPath}\" --json";
        return await RunPythonAsync(args);
    }

    /// <summary>
    /// Triggers the NVD feed sync. Returns sync status JSON.
    /// </summary>
    public async Task<string> RunDBSyncAsync(string dbPath)
    {
        var script = Path.Combine(_pathOptions.PythonScriptsPath, "db_sync.py");
        var args = $"\"{script}\" --db \"{dbPath}\" --json";
        return await RunPythonAsync(args);
    }

    // -------------------------------------------------------------------------
    // Core subprocess runner
    // -------------------------------------------------------------------------

    /// <summary>
    /// Spawns a Python process, waits for completion (max 120s), returns stdout.
    /// Logs stderr as warnings.
    /// </summary>
    private async Task<string> RunPythonAsync(string arguments, int timeoutMs = 120_000)
    {
        var psi = new ProcessStartInfo
        {
            FileName = _pathOptions.PythonExe,
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };

        _logger.LogDebug("[IPC] Running: {Python} {Args}", _pathOptions.PythonExe, arguments);

        using var process = new Process { StartInfo = psi };
        var stdoutBuilder = new StringBuilder();
        var stderrBuilder = new StringBuilder();

        process.OutputDataReceived += (_, e) =>
        {
            if (e.Data != null) stdoutBuilder.AppendLine(e.Data);
        };
        process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data != null) stderrBuilder.AppendLine(e.Data);
        };

        process.Start();
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        using var cts = new CancellationTokenSource(timeoutMs);
        try
        {
            await process.WaitForExitAsync(cts.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
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
