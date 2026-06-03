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

        if (File.Exists(dbPath))
        {
            var logger = new NullLogger();
            _db = new ScanHistoryDb(logger, dbPath);
            _vulnDb = new VulnerabilityDb(logger, dbPath);
        }

        // Commands
        RunScanCommand = new RelayCommand(async () => await RunScanAsync(), () => IsNotScanning);
        ExportJsonCommand = new RelayCommand(ExportJson);
        AcknowledgeCommand = new RelayCommand<Finding>(AcknowledgeFinding);

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

    // -------------------------------------------------------------------------
    // Data operations
    // -------------------------------------------------------------------------

    public async Task RefreshAsync()
    {
        if (_db == null) return;

        await Task.Run(() =>
        {
            var findings = _db.GetActiveFindings();
            var (crit, high, med, low) = _db.GetFindingCounts();
            var gatewayFiles = _db.GetRecentGatewayFiles(50);

            var lastVuln = _db.GetLastScanTime("vulnerability");
            var vulnCount = _vulnDb?.GetTotalCount() ?? 0;

            Application.Current?.Dispatcher.Invoke(() =>
            {
                Findings = new ObservableCollection<Finding>(findings);
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
        });
    }

    private async Task RunScanAsync()
    {
        if (IsScanning) return;
        IsScanning = true;

        try
        {
            // Trigger scan via Windows Service control (or direct engine call for dashboard)
            // For v1.0: Show message asking user to trigger via service
            // In v2.0: Named Pipe message to service
            await Task.Delay(500); // Simulate scan start

            StatusMessage = "Scan triggered. Results will appear within 30 seconds.";
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

        await _db.AcknowledgeFindingAsync(finding.Id, "Acknowledged via dashboard");
        await RefreshAsync();
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
