namespace SentryShield.LegacyService;

/// <summary>
/// Strongly-typed config model for SentryLegacyService appsettings.json.
/// Read once at startup via Microsoft.Extensions.Configuration.
/// </summary>
internal sealed class LegacyConfig
{
    public ScanningSection  Scanning { get; set; } = new();
    public PathsSection     Paths    { get; set; } = new();
    public SupplierSection  Supplier { get; set; } = new();
    public YaraSection      Yara     { get; set; } = new();
    public EventLogSection  EventLog { get; set; } = new();

    internal sealed class ScanningSection
    {
        public int VulnerabilityScanIntervalHours { get; set; } = 24;
        public int DriverAuditIntervalHours       { get; set; } = 24;
        public int HardeningCheckIntervalHours    { get; set; } = 6;
    }

    internal sealed class PathsSection
    {
        public string DatabasePath          { get; set; } = @"C:\ProgramData\SentryShield\sentry.db";
        public string GatewayDownloadFolder { get; set; } = @"C:\SentryShield\Downloads";
    }

    internal sealed class SupplierSection
    {
        public bool   EnableGatewayValidation { get; set; } = true;
        public string TrustedSuppliersPath    { get; set; } = @"C:\ProgramData\SentryShield\trusted_suppliers.json";
    }

    internal sealed class YaraSection
    {
        /// <summary>
        /// Controlled by SentrySetup.ps1 (auto-detected) or edited manually.
        /// When false, YARA subprocess is never called — safe on machines without Python.
        /// When true but Python is missing/broken, LegacyYaraGuard degrades gracefully.
        /// </summary>
        public bool   EnableYaraScanning { get; set; } = true;
        public string PythonExe          { get; set; } = "python";
        public string YaraScriptPath     { get; set; } = @"C:\ProgramData\SentryShield\yara_scanner.py";
        public string YaraRulesPath      { get; set; } = @"C:\ProgramData\SentryShield\rules";
    }

    internal sealed class EventLogSection
    {
        public string Source { get; set; } = "SentryShield";
        public string Log    { get; set; } = "Application";
    }
}
