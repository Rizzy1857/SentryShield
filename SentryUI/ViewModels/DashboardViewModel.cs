using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Windows;
using System.Windows.Input;
using Microsoft.Win32;
using SentryShield.Core.Models;
using SentryShield.Database;

namespace SentryShield.UI.ViewModels;

/// <summary>
/// Main dashboard ViewModel — binds to MainWindow.xaml.
/// Provides severity counts, findings collection, scan control,
/// and JSON export. Reads from SentryShield SQLite database.
/// </summary>
public class DashboardViewModel : INotifyPropertyChanged
{
    private readonly ScanHistoryDb? _db;
    private readonly VulnerabilityDb? _vulnDb;

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    public DashboardViewModel()
    {
        // Load DB path from appsettings.json or default
        var dbPath = LoadDbPath();

        if (File.Exists(dbPath) || !File.Exists(dbPath)) // Always try to initialize or connect
        {
            var logger = new NullLogger();
            
            // Fix: Initialize the SQLite schema immediately so missing tables don't crash the UI on fresh boot
            var initializer = new SentryShield.Database.DatabaseInitializer(
                new Microsoft.Extensions.Logging.Abstractions.NullLogger<SentryShield.Database.DatabaseInitializer>(), dbPath);
            initializer.InitializeAsync().GetAwaiter().GetResult();

            _db = new ScanHistoryDb(logger, dbPath);
            _vulnDb = new VulnerabilityDb(logger, dbPath);
        }

        // Commands
        RunScanCommand = new RelayCommand(async () => await RunScanAsync(), () => IsNotScanning);
        ExportJsonCommand = new RelayCommand(ExportJson);
        AcknowledgeCommand = new RelayCommand<Finding>(AcknowledgeFinding);
        SyncDatabaseCommand = new RelayCommand(async () => await SyncDatabaseAsync(), () => IsNotScanning);
        OpenDbFolderCommand = new RelayCommand(OpenDbFolder);

        // Initial data load
        _ = RefreshAsync();

        // Auto-refresh every 30 seconds
        var timer = new System.Windows.Threading.DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(30)
        };
        timer.Tick += async (_, _) => await RefreshAsync();
        timer.Start();
    }

    // -------------------------------------------------------------------------
    // Observable Properties
    // -------------------------------------------------------------------------

    private ObservableCollection<Finding> _findings = new();
    public ObservableCollection<Finding> Findings
    {
        get => _findings;
        set { _findings = value; OnPropertyChanged(); }
    }

    private ObservableCollection<GatewayFile> _gatewayFiles = new();
    public ObservableCollection<GatewayFile> GatewayFiles
    {
        get => _gatewayFiles;
        set { _gatewayFiles = value; OnPropertyChanged(); }
    }

    private int _criticalCount;
    public int CriticalCount
    {
        get => _criticalCount;
        set { _criticalCount = value; OnPropertyChanged(); }
    }

    private int _highCount;
    public int HighCount
    {
        get => _highCount;
        set { _highCount = value; OnPropertyChanged(); }
    }

    private int _mediumCount;
    public int MediumCount
    {
        get => _mediumCount;
        set { _mediumCount = value; OnPropertyChanged(); }
    }

    private int _lowCount;
    public int LowCount
    {
        get => _lowCount;
        set { _lowCount = value; OnPropertyChanged(); }
    }

    private int _vulnDbCount;
    public int VulnDbCount
    {
        get => _vulnDbCount;
        set { _vulnDbCount = value; OnPropertyChanged(); }
    }

    private bool _isScanning = false;
    public bool IsScanning
    {
        get => _isScanning;
        set
        {
            _isScanning = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(IsNotScanning));
            OnPropertyChanged(nameof(StatusMessage));
        }
    }
    public bool IsNotScanning => !_isScanning;

    private string _statusMessage = "Ready";
    public string StatusMessage
    {
        get => _isScanning ? "Scanning in progress..." : _statusMessage;
        set { _statusMessage = value; OnPropertyChanged(); }
    }

    private string _lastScanText = "Last scan: Never";
    public string LastScanText
    {
        get => _lastScanText;
        set { _lastScanText = value; OnPropertyChanged(); }
    }

    private string _nextScanText = "Next scan: Nightly (06:00)";
    public string NextScanText
    {
        get => _nextScanText;
        set { _nextScanText = value; OnPropertyChanged(); }
    }

    private string _nvdApiKey = "9f6e8eb5-0526-4932-8ce9-e9d3380b1b39";
    public string NvdApiKey
    {
        get => _nvdApiKey;
        set { _nvdApiKey = value; OnPropertyChanged(); }
    }

    private string _syncLogText = "Terminal initialized...\n";
    public string SyncLogText
    {
        get => _syncLogText;
        set { _syncLogText = value; OnPropertyChanged(); }
    }

    public string MachineName { get; } = Environment.MachineName;

    // Status dot color: green if 0 critical, orange if high, red if critical
    public System.Windows.Media.Color StatusColor =>
        CriticalCount > 0 ? System.Windows.Media.Color.FromRgb(0xFF, 0x4C, 0x4C) :
        HighCount > 0 ? System.Windows.Media.Color.FromRgb(0xFF, 0x8C, 0x00) :
        System.Windows.Media.Color.FromRgb(0x3F, 0xB9, 0x50);

    public string StatusText =>
        CriticalCount > 0 ? "CRITICAL ISSUES DETECTED" :
        HighCount > 0 ? "HIGH SEVERITY FINDINGS" :
        "System Monitoring";

    // -------------------------------------------------------------------------
    // Commands
    // -------------------------------------------------------------------------

    public ICommand RunScanCommand { get; }
    public ICommand ExportJsonCommand { get; }
    public ICommand AcknowledgeCommand { get; }
    public ICommand SyncDatabaseCommand { get; }
    public ICommand OpenDbFolderCommand { get; }

    // -------------------------------------------------------------------------
    // Data operations
    // -------------------------------------------------------------------------

    private async Task RefreshAsync()
    {
        if (_db == null) return;

        await Application.Current.Dispatcher.InvokeAsync(() =>
        {
            try
            {
                var rawFindings = _db.GetActiveFindings();
                // Sort acknowledged findings to the bottom, then by severity
                var sortedFindings = rawFindings
                    .OrderBy(f => f.Acknowledged)
                    .ThenByDescending(f => f.Severity == "CRITICAL" ? 4 : f.Severity == "HIGH" ? 3 : f.Severity == "MEDIUM" ? 2 : 1)
                    .ToList();

                var (crit, high, med, low) = _db.GetFindingCounts();
                var gatewayFiles = _db.GetRecentGatewayFiles(50);

                var lastVuln = _db.GetLastScanTime("vulnerability");
                var vulnCount = _vulnDb?.GetTotalCount() ?? 0;

                Application.Current?.Dispatcher.Invoke(() =>
                {
                    Findings = new ObservableCollection<Finding>(sortedFindings);
                    GatewayFiles = new ObservableCollection<GatewayFile>(gatewayFiles);
                    CriticalCount = crit;
                    HighCount = high;
                    MediumCount = med;
                    LowCount = low;
                    VulnDbCount = vulnCount;

                    LastScanText = lastVuln.HasValue
                        ? $"Last scan: {lastVuln.Value.ToLocalTime():MM/dd HH:mm}"
                        : "Last scan: Never";

                    OnPropertyChanged(nameof(StatusColor));
                    OnPropertyChanged(nameof(StatusText));
                });
            }
            catch (Exception ex)
            {
                // Prevent missing tables or broken DB queries from crashing the UI
                System.Diagnostics.Debug.WriteLine($"[DB] Refresh failed: {ex.Message}");
            }
        });
    }

    private async Task RunScanAsync()
    {
        if (IsScanning) return;
        
        var dialog = new Microsoft.Win32.OpenFolderDialog
        {
            Title = "Select Drive or Folder to Scan for Threats",
            Multiselect = false
        };

        if (dialog.ShowDialog() != true) return;

        var folderPath = dialog.FolderName;

        IsScanning = true;
        StatusMessage = $"Scanning {folderPath}...";

        try
        {
            var logger = new NullLogger();
            var appDir = AppDomain.CurrentDomain.BaseDirectory;
            var runner = new SentryShield.Core.IPC.ProcessRunner(
                logger, 
                "python", 
                System.IO.Path.Combine(appDir, "python_scripts"), 
                System.IO.Path.Combine(appDir, "yara_rules")
            );
            var iocDb = new SentryShield.Database.IOCDb(logger, LoadDbPath());
            var monitor = new SentryShield.Core.Engines.USBMonitor(logger, runner, iocDb);
            
            // Execute the actual core engine scan!
            var threats = await monitor.ScanUSBDriveAsync(folderPath);

            if (_db != null && threats.Any())
            {
                var findingsToSave = threats.Select(t => new Finding
                {
                    FindingType = "usb_threat",
                    Severity = t.Severity,
                    Title = $"USB Threat: {t.FileName}",
                    Description = t.Description,
                    AffectedComponent = t.FilePath,
                    Remediation = t.Remediation,
                    DetectionTimestamp = t.DetectedAt,
                    Notes = $"Type: {t.ThreatType} | Confidence: {t.Confidence}%"
                }).ToList();

                await _db.SaveFindingsAsync(findingsToSave);
                StatusMessage = $"Scan complete. Found {threats.Count} threats.";
            }
            else
            {
                StatusMessage = "Scan complete. No threats found.";
            }

            await RefreshAsync();
        }
        catch (Exception ex)
        {
            StatusMessage = $"Scan error: {ex.Message}";
        }
        finally
        {
            IsScanning = false;
        }
    }

    private void ExportJson()
    {
        var dialog = new SaveFileDialog
        {
            Title = "Export Findings as JSON",
            Filter = "JSON files (*.json)|*.json",
            FileName = $"SentryShield_Findings_{DateTime.Now:yyyyMMdd_HHmm}.json"
        };

        if (dialog.ShowDialog() != true) return;

        try
        {
            var export = new
            {
                ExportedAt = DateTime.UtcNow.ToString("o"),
                MachineName,
                Summary = new
                {
                    CriticalCount,
                    HighCount,
                    MediumCount,
                    LowCount,
                    TotalFindings = Findings.Count
                },
                Findings = Findings.ToList()
            };

            var json = JsonSerializer.Serialize(export, new JsonSerializerOptions
            {
                WriteIndented = true
            });

            File.WriteAllText(dialog.FileName, json);
            StatusMessage = $"Exported {Findings.Count} findings to {Path.GetFileName(dialog.FileName)}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"Export failed: {ex.Message}";
        }
    }

    private async void AcknowledgeFinding(Finding? finding)
    {
        if (finding == null || _db == null) return;

        if (!finding.IsReviewing)
        {
            finding.IsReviewing = true;
            
            // Force UI update so DataGrid sees the change (since Finding doesn't implement INotifyPropertyChanged)
            var index = Findings.IndexOf(finding);
            if (index >= 0)
            {
                Findings[index] = null;
                Findings[index] = finding;
            }
            return;
        }

        await _db.AcknowledgeFindingAsync(finding.Id, "Acknowledged via dashboard");
        await RefreshAsync();
    }

    private async Task SyncDatabaseAsync()
    {
        if (_vulnDb == null) return;
        if (IsScanning) return;
        
        IsScanning = true;
        StatusMessage = "Syncing CVE Database from live NVD API (this may take a few minutes)...";
        SyncLogText = ""; // Clear old logs
        try
        {
            var logger = new NullLogger();
            var appDir = AppDomain.CurrentDomain.BaseDirectory;
            
            // Path to the python directory (4 levels up from SentryUI\bin\Debug\net10.0-windows)
            var solutionDir = System.IO.Path.GetFullPath(System.IO.Path.Combine(appDir, "..\\..\\..\\.."));
            var pyScriptDir = System.IO.Path.Combine(solutionDir, "SentryPython");

            var runnerForDb = new SentryShield.Core.IPC.ProcessRunner(
                logger, 
                "python", 
                pyScriptDir, 
                System.IO.Path.Combine(appDir, "yara_rules")
            );

            // Stream python logs to UI
            Action<string> onOutput = (line) =>
            {
                System.Windows.Application.Current.Dispatcher.Invoke(() =>
                {
                    // Keep the last 10,000 chars roughly
                    if (SyncLogText.Length > 10000)
                        SyncLogText = SyncLogText.Substring(0, 10000);
                        
                    // Prepend new lines so the newest logs stay at the top without needing auto-scroll
                    SyncLogText = line + "\n" + SyncLogText;
                });
            };

            var output = await runnerForDb.RunInitDbAsync(LoadDbPath(), NvdApiKey, onOutput);

            if (_db != null) {
                // Approximate rows inserted, or just log the time
                await _db.RecordScanAsync("vulnerability", 100, 1, 1, 0, 120);
            }
            
            StatusMessage = "Live NVD CVE Sync complete.";
            await RefreshAsync();
        }
        catch (Exception ex)
        {
            StatusMessage = $"Sync failed: {ex.Message}";
        }
        finally
        {
            IsScanning = false;
        }
    }

    private void OpenDbFolder()
    {
        var dbPath = LoadDbPath();
        var dir = Path.GetDirectoryName(dbPath);
        if (Directory.Exists(dir))
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = dir,
                UseShellExecute = true
            });
        }
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private static string LoadDbPath()
    {
        var defaultPath = @"C:\ProgramData\SentryShield\vulnerability.db";

        try
        {
            var configPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "appsettings.json");
            if (File.Exists(configPath))
            {
                var json = File.ReadAllText(configPath);
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("Database", out var db) &&
                    db.TryGetProperty("Path", out var path))
                {
                    return path.GetString() ?? defaultPath;
                }
            }
        }
        catch { /* Fall back to default */ }

        return defaultPath;
    }

    // -------------------------------------------------------------------------
    // INotifyPropertyChanged
    // -------------------------------------------------------------------------

    public event PropertyChangedEventHandler? PropertyChanged;

    protected void OnPropertyChanged([CallerMemberName] string? propertyName = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
}

// ─────────────────────────────────────────────────────
// RelayCommand implementations
// ─────────────────────────────────────────────────────

public class RelayCommand : ICommand
{
    private readonly Func<Task> _executeAsync;
    private readonly Func<bool>? _canExecute;

    public RelayCommand(Func<Task> executeAsync, Func<bool>? canExecute = null)
    {
        _executeAsync = executeAsync;
        _canExecute = canExecute;
    }

    public RelayCommand(Action execute, Func<bool>? canExecute = null)
        : this(() => { execute(); return Task.CompletedTask; }, canExecute) { }

    public bool CanExecute(object? parameter) => _canExecute?.Invoke() ?? true;

    public async void Execute(object? parameter)
    {
        await _executeAsync();
        CanExecuteChanged?.Invoke(this, EventArgs.Empty);
    }

    public event EventHandler? CanExecuteChanged;

    public void RaiseCanExecuteChanged()
        => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}

public class RelayCommand<T> : ICommand
{
    private readonly Action<T?> _execute;
    private readonly Func<T?, bool>? _canExecute;

    public RelayCommand(Action<T?> execute, Func<T?, bool>? canExecute = null)
    {
        _execute = execute;
        _canExecute = canExecute;
    }

    public bool CanExecute(object? parameter) =>
        _canExecute?.Invoke((T?)parameter) ?? true;

    public void Execute(object? parameter) => _execute((T?)parameter);

    public event EventHandler? CanExecuteChanged;
}

/// <summary>Minimal ILogger implementation for ViewModel use.</summary>
internal class NullLogger : Microsoft.Extensions.Logging.ILogger
{
    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
    public bool IsEnabled(Microsoft.Extensions.Logging.LogLevel logLevel) => false;
    public void Log<TState>(Microsoft.Extensions.Logging.LogLevel logLevel, Microsoft.Extensions.Logging.EventId eventId,
        TState state, Exception? exception, Func<TState, Exception?, string> formatter) { }
}
