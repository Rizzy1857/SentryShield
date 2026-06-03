namespace SentryShield.Service;

// ─────────────────────────────────────────────────────
//  Configuration option records (mapped from appsettings.json)
// ─────────────────────────────────────────────────────

public class SentryOptions
{
    public string Name { get; set; } = "SentryShield";
    public string DisplayName { get; set; } = "SentryShield Security Agent";
    public string Description { get; set; } = "Manufacturing security monitoring with supplier validation";
}

public class ScanningOptions
{
    public int VulnerabilityScanIntervalHours { get; set; } = 24;
    public int GatewayScanIntervalMinutes { get; set; } = 60;
    public int DriverAuditIntervalHours { get; set; } = 24;
    public int HardeningCheckIntervalHours { get; set; } = 24;
}

public class DatabaseOptions
{
    public string Path { get; set; } = @"C:\ProgramData\SentryShield\vulnerability.db";
    public string BackupPath { get; set; } = @"C:\ProgramData\SentryShield\backups\";
    public int MaxDbSizeMB { get; set; } = 500;
}

public class PathOptions
{
    public string GatewayDownloadFolder { get; set; } = @"C:\SentryShield\Downloads\";
    public string YaraRulesPath { get; set; } = @"C:\SentryShield\rules\";
    public string LogPath { get; set; } = @"C:\ProgramData\SentryShield\logs\";
    public string PythonExe { get; set; } = @"C:\Python311\python.exe";
    public string PythonScriptsPath { get; set; } = @"C:\SentryShield\scripts\";
}

public class SupplierOptions
{
    public bool EnableGatewayValidation { get; set; } = true;
    public bool RequireSignature { get; set; } = true;
    public bool BlockOnMalwareDetection { get; set; } = true;
}
