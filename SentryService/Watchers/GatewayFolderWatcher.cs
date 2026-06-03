using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using SentryShield.Core.Engines;
using SentryShield.Database;

namespace SentryShield.Service.Watchers;

/// <summary>
/// Watches the gateway download folder for new supplier files.
/// On file creation: triggers the full validation pipeline,
/// writes result to DB, logs to Windows Event Log.
///
/// Thread-safety: FileSystemWatcher events fire on a ThreadPool thread.
/// ValidateFileAsync is async-safe.
/// </summary>
public class GatewayFolderWatcher : IDisposable
{
    private readonly ILogger<GatewayFolderWatcher> _logger;
    private readonly PathOptions _pathOptions;
    private readonly SupplierOptions _supplierOptions;
    private readonly SupplierFileValidator _validator;
    private readonly ScanHistoryDb _db;
    private readonly Core.Logging.EventLogWriter _eventLog;

    private FileSystemWatcher? _watcher;

    // Debounce: prevent duplicate events when file is still being copied
    private readonly Dictionary<string, DateTime> _recentlyProcessed = new();
    private readonly TimeSpan _debounceWindow = TimeSpan.FromSeconds(5);

    public GatewayFolderWatcher(
        ILogger<GatewayFolderWatcher> logger,
        IOptions<PathOptions> pathOptions,
        IOptions<SupplierOptions> supplierOptions,
        SupplierFileValidator validator,
        ScanHistoryDb db,
        Core.Logging.EventLogWriter eventLog)
    {
        _logger = logger;
        _pathOptions = pathOptions.Value;
        _supplierOptions = supplierOptions.Value;
        _validator = validator;
        _db = db;
        _eventLog = eventLog;
    }

    public void Start()
    {
        if (!_supplierOptions.EnableGatewayValidation)
        {
            _logger.LogInformation("[Gateway] Validation disabled in config — watcher not started");
            return;
        }

        var folder = _pathOptions.GatewayDownloadFolder;

        if (!Directory.Exists(folder))
        {
            Directory.CreateDirectory(folder);
            _logger.LogInformation("[Gateway] Created gateway folder: {Folder}", folder);
        }

        _watcher = new FileSystemWatcher(folder)
        {
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite,
            Filter = "*.*",
            IncludeSubdirectories = false,
            EnableRaisingEvents = true
        };

        // Listen for new files (Created) and renamed files (copied via rename)
        _watcher.Created += OnFileCreated;
        _watcher.Renamed += OnFileRenamed;
        _watcher.Error += OnWatcherError;

        _logger.LogInformation("[Gateway] Watching: {Folder}", folder);
    }

    public void Stop()
    {
        _watcher?.Dispose();
        _logger.LogInformation("[Gateway] Watcher stopped");
    }

    // -------------------------------------------------------------------------
    // Event handlers
    // -------------------------------------------------------------------------

    private void OnFileCreated(object sender, FileSystemEventArgs e)
        => Task.Run(() => ValidateFileAsync(e.FullPath));

    private void OnFileRenamed(object sender, RenamedEventArgs e)
        => Task.Run(() => ValidateFileAsync(e.FullPath));

    private void OnWatcherError(object sender, ErrorEventArgs e)
        => _logger.LogError(e.GetException(), "[Gateway] FileSystemWatcher error");

    // -------------------------------------------------------------------------
    // Validation
    // -------------------------------------------------------------------------

    private async Task ValidateFileAsync(string filePath)
    {
        // Debounce — skip if processed within the last 5 seconds
        lock (_recentlyProcessed)
        {
            if (_recentlyProcessed.TryGetValue(filePath, out var lastProcessed) &&
                (DateTime.UtcNow - lastProcessed) < _debounceWindow)
            {
                return;
            }
            _recentlyProcessed[filePath] = DateTime.UtcNow;
        }

        // Wait briefly for file copy to complete before scanning
        await Task.Delay(2000);

        if (!File.Exists(filePath)) return;

        // Infer supplier name from folder structure: Downloads\<SupplierName>\file.ext
        var supplierName = InferSupplierName(filePath);
        var fileName = Path.GetFileName(filePath);

        _logger.LogInformation("[Gateway] New file detected: {File} from '{Supplier}'",
            fileName, supplierName);

        try
        {
            var result = await _validator.ValidateAsync(filePath, supplierName);

            // Persist to gateway_files table
            await _db.RecordGatewayFileAsync(new Core.Models.GatewayFile
            {
                Filename = fileName,
                SupplierName = supplierName,
                FileHash = result.FileHash,
                FileSize = new FileInfo(filePath).Length,
                ReceivedTimestamp = DateTime.UtcNow,
                ValidationStatus = result.Decision,
                BlockReason = result.Decision == "BLOCK" ? result.Reason : null,
                ValidationTimestamp = DateTime.UtcNow,
                TransferredToOT = false
            });

            // Log to Windows Event Log
            switch (result.Decision)
            {
                case "BLOCK":
                    _eventLog.WriteError(
                        $"[Gateway] BLOCKED: {fileName} from {supplierName}\nReason: {result.Reason}",
                        eventId: 5001);
                    _logger.LogWarning("[Gateway] BLOCKED: {File} — {Reason}", fileName, result.Reason);

                    // Quarantine: move to Quarantine subfolder
                    QuarantineFile(filePath);
                    break;

                case "WARN":
                    _eventLog.WriteWarning(
                        $"[Gateway] WARNING: {fileName} from {supplierName}\nReason: {result.Reason}",
                        eventId: 5002);
                    _logger.LogWarning("[Gateway] WARN: {File} — {Reason}", fileName, result.Reason);
                    break;

                case "ALLOW":
                    _eventLog.WriteInfo(
                        $"[Gateway] ALLOWED: {fileName} from {supplierName}",
                        eventId: 5000);
                    _logger.LogInformation("[Gateway] ALLOWED: {File}", fileName);
                    break;
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[Gateway] Validation error for {File}", filePath);
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private string InferSupplierName(string filePath)
    {
        // Expect structure: GatewayDownloadFolder\<SupplierName>\file.ext
        // or: GatewayDownloadFolder\file.ext (direct drop → "Unknown")
        var dir = Path.GetDirectoryName(filePath);
        if (dir == null) return "Unknown";

        if (string.Equals(dir, _pathOptions.GatewayDownloadFolder.TrimEnd('\\'),
            StringComparison.OrdinalIgnoreCase))
        {
            return "Unknown";
        }

        return Path.GetFileName(dir) ?? "Unknown";
    }

    private void QuarantineFile(string filePath)
    {
        try
        {
            var quarantineDir = Path.Combine(_pathOptions.GatewayDownloadFolder, "Quarantine");
            Directory.CreateDirectory(quarantineDir);

            var dest = Path.Combine(quarantineDir,
                $"{DateTime.UtcNow:yyyyMMddHHmmss}_{Path.GetFileName(filePath)}");

            File.Move(filePath, dest, overwrite: true);
            _logger.LogInformation("[Gateway] Quarantined: {File} → {Dest}", filePath, dest);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "[Gateway] Failed to quarantine {File}", filePath);
        }
    }

    public void Dispose() => _watcher?.Dispose();
}
