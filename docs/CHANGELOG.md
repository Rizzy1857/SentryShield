# SentryShield — Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [v2.6.0] — 2026-06-11

### Added
- **Centralized Versioning** — Introduced `Directory.Build.props` at the repository root to globally manage MSBuild `Version` (v2.6.0) and `Product` properties across all `.csproj` files seamlessly.
- **Hardware Telemetry on UI** — Physical SMBIOS Hardware Hash is now generated securely via WMI (`Win32_BIOS`) and surfaced dynamically in the `SentryUI` Dashboard under the Machine Name to instantly verify hardware identity.
- **Dynamic Plugin Telemetry** — The Settings UI now actively reflects the loaded plugins, providing users an instant view of all active architectural extensions.

### Changed
- **Unified Architecture Target** — Fully migrated the entire `.sln` and all related plugins/services from `.NET 8` to `.NET 10.0-windows` (`net10.0-windows`).
- **Build System Fixes** — Overhauled `build_and_run.ps1` to natively compile the entire `SentryShield.sln` to correctly build detached plugins with `<ReferenceOutputAssembly>false</ReferenceOutputAssembly>`.

### Fixed
- **C# 12 Strict Compliance** — Resolved all final nullable reference type (`?`) compiler warnings in `VulnerabilityMatcher.cs` and `IDSPluginTests.cs` to ensure absolute strict C# compliance.
- **Legacy Framework Target Fix** — Fixed the `net48` legacy target build error for `SentryPlugin.Abstractions` by forcing `<LangVersion>latest</LangVersion>` to permit C# 12 features on the older framework target.
- **UI Version Binding** — Patched `SettingsView.xaml` and `MainWindow.xaml` to dynamically bind to the Reflection-generated `AppVersion` and `AppName` rather than containing hardcoded version text.

---

## [v2.5-stable] — 2026-06-09

### Added — Deep System Integrity
- **`SentryPlugin.Firmware`** — New plugin utilizing raw kernel API calls (`GetSystemFirmwareTable`) to read the raw SMBIOS (`RSMB`) table, completely bypassing user-space WMI to thwart Ring-0 rootkits.
- **Hardware Baselining** — Generates a SHA-256 hash of the physical firmware configuration to alert administrators of unauthorized hardware/BIOS flashes.
- **Access Violation Safety** — Advanced `P/Invoke` implementation featuring two-pass buffer sizing and strict memory allocation safeguards (`Marshal.AllocHGlobal`) with guaranteed memory cleanup.

### USB Auto-Block-Then-Scan (Zero Trust)
- **Global Write-Protect** — Automatically manipulates `HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies` to strictly write-protect all USB mass storage devices during active scans, neutralizing data exfiltration vectors.
- **ACL Execution Lock** — Dynamically strips `ExecuteFile` permissions from the `Everyone` group at the root of the USB drive while scanning to prevent premature malware execution.
- **Toast Notifications** — Integrated native Windows 10/11 Toast Notifications to alert users to lock-downs ("Scanning before use") and scan results ("USB Cleared" or "USB Blocked").

### Security Hardening (P0 Fixes)
- **Strict Plugin Signatures** — Removed the `SENTRYSHIELD_REQUIRE_SIGNED_PLUGINS` environment variable bypass. Authenticode signature validation is now unconditionally enforced for all dynamically loaded plugins, mitigating arbitrary code execution risks from the `Plugins/` drop folder.
- **Dual-Hash TOCTOU Mitigation** — Replaced the single-file-lock check in `GatewayFolderWatcher.cs` with a dual-hashing architecture (pre-scan and post-scan) to detect and instantly quarantine files maliciously modified during the validation window.

### Security Hardening (P1 Fixes)
- **Python IPC Command Injection Mitigation** — Refactored `ProcessRunner.cs` to execute Python subprocesses using `ProcessStartInfo.ArgumentList`, completely encapsulating parameters and neutralizing shell metacharacter injection.
- **Database Integrity Validation** — Implemented a boot-time `DatabaseIntegrityValidator` that hashes `vulnerability.db` and `ioc.db` and verifies them against a secured `HKEY_LOCAL_MACHINE` registry baseline. Boot fails securely if tampering is detected.
- **YARA Rule Directory ACLs** — `SentryWorker` now proactively enforces strict `DirectorySecurity` on the YARA rules folder upon startup, stripping inherited permissions and exclusively granting `FullControl` to `SYSTEM` and `Administrators`.

---

## [v2.1-stable] — 2026-06-08

### Security & Reliability Lockdown
- **Gateway TOCTOU Fix** — Replaced `Task.Delay(2000)` with `WaitForFileAccessAsync` (exponential backoff) and enforced `FileShare.Read` in `SupplierFileValidator` to prevent Time-Of-Check to Time-Of-Use malware injections.
- **Arbitrary Code Execution Block** — Hardened `PluginLoader.cs` by enforcing Authenticode Signature validation (`X509CertificateLoader`) on all dynamically loaded `.dll` plugins. Unsigned plugins will not load unless explicitly bypassed in dev environments.
- **Orchestration Deadlock Prevention** — Injected `CancellationTokenSource` with a hard 5-minute timeout on all `IDetectionPlugin.ExecuteAsync()` invocations to prevent hanging sockets or DB connections from freezing the primary SentryWorker loop.
- **IDS Thread Safety** — Resolved a concurrent dictionary aggregation race condition in `IDSPlugin.cs` using `Interlocked.CompareExchange` on raw clock ticks instead of a naive DateTime block.

---

## [v2.1-alpha] — 2026-06-08

### Added — The Sensors (IDS Integration)
- **`SentryPlugin.IDS`** — Successfully built the first "v2.5" sensor plugin. Fully autonomous network traffic monitoring via `SharpPcap` and `PacketDotNet`.
- **Egress Monitoring** — Enforces strict OT subnet egress rules. Flags any traffic destined for ports other than `102` (S7), `502` (Modbus), `44818` (EtherNet/IP), `80`, or `443`.
- **Packet Flood Detection** — Tracks baseline packet velocity and triggers a `HIGH` severity alert if any single IP exceeds 1,000 packets per minute.
- **Malicious IP Blocks** — Live-matches incoming/outgoing packets against known-bad IPs from `IOCDb`.
- **Mock Testing** — Added `IDSPluginTests.cs` using mock `EthernetPacket` > `IPv4Packet` > `TcpPacket` byte arrays to test port and flood anomalies without physical network interfaces.

---

## [v2.0] — 2026-06-08

### Added — The Great Shift (Dynamic Plugin Architecture)
- **`SentryPlugin.Abstractions`** — Extracted core plugin interfaces (`IDetectionPlugin`, `PluginContext`, `PluginConfig`) into a standalone, lightweight shared library.
- **Dynamic Loading Engine** — `SentryWorker` now uses reflection to hot-load isolated plugin DLLs from the `Plugins/` directory at runtime. This completes the shift from a monolithic hardcoded service to a fully modular architecture.
- **`SentryPlugin.Vulnerability`** — Migrated the `VulnerabilityMatcher` engine into its own autonomous plugin.
- **`SentryPlugin.USB`** — Migrated the `USBMonitor` engine into its own autonomous plugin.
- **Build Pipeline Upgrades** — The `SentryLegacyService.csproj` and `SentryService.csproj` now automatically copy compiled plugin DLLs to the central `Plugins` output directory.

### Fixed — Undocumented NIST API Zero-Day & PowerShell Bugs
- **NVD API Firewall Bypass** — Discovered and patched an undocumented change in NIST's Web Application Firewall that was blindly returning `404 Not Found` for the officially documented `apiKey` header. The Python `cert_parser.py` was updated to use the undocumented `api_key` casing, successfully restoring the 50-req/30s sync capability.
- **API Key Fallback Strategy** — Added self-healing logic to `cert_parser.py`: If NVD servers reject an API key (HTTP 404/403), the parser instantly drops the key, logs a warning, and gracefully downgrades to unauthenticated requests without crashing the sync.
- **PowerShell Legacy Parser Crashes** — Fixed an extremely elusive parsing bug in older versions of PowerShell (v5.1) where inline backticks (`` `n ``) and Unicode block characters (`▄▖`) over Parallels UNC paths caused catastrophic "missing terminator" and "ampersand" syntax crashes. Completely sanitized `build_and_run.ps1` to raw ASCII.
- **MSBuild Caching Bug** — Added `dotnet clean` step for `SentryLegacyService` in `build_and_run.ps1` to prevent aggressive MSBuild caching from skipping the deployment of updated Python scripts.

## [v1.2] — 2026-06-05

### Added — UI Engine Integration & Build Automation

- **`SentryUI` Live Core Integration** — Replaced the mock dashboard UI actions with live invocations of the `SentryCore` engines directly within the WPF application.
  - **Scan USB/Folder**: The "Scan" button now launches a native Folder Picker and executes an immediate, deep file analysis using `USBMonitor.ScanUSBDriveAsync()`. Results are saved to `ScanHistoryDb` and instantly refresh the findings grid.
  - **Sync Database**: Wired the "Sync CVE Database" button to inject sample NVD CVE records (`BatchUpsertAsync`), preparing the UI architecture for a live API integration.
  - **Open DB Folder**: Added a quick-access button to open the SQLite database storage location (`C:\ProgramData\SentryShield`) in Windows Explorer.
- **Smart Build Automation** — Added `build_and_run.bat` and `build_and_run.ps1` which cleanly resolve `.NET 4.8` vs `.NET 10.0-windows` MSBuild conflicts, seamlessly compiling the legacy and modern pipelines respectively, while properly handling UNC path boundaries in Parallels VMs.

### Fixed
- **UI Crash on Startup**: Fixed a `XamlParseException` in `FindingsView.xaml` caused by a `StaticResource` referencing the `CellStyle` before it was declared in the markup.
- **SQLite Versioning Conflicts**: Bumped `Microsoft.Data.Sqlite` to `8.0.0` globally across `SentryService` and `SentryCore` to eliminate `NU1605` package downgrade errors and resolve missing `hostfxr.dll` runtime issues.
- **WPF Native Property Translation**: Removed WinUI 3 properties (`LetterSpacing`, `TextTransform`, `Spacing`) from WPF views and replaced them with functional `Margin` native equivalents.

---

## [v1.1] — 2026-06-04

### Added — Live Vulnerability Intelligence Pipeline & Remaining Stubs

- **`SentryPython/cert_in_parser.py`** — New CERT-In advisory parser
  - Fetches live RSS feed from `cert-in.org.in`
  - Scrapes each advisory HTML page to extract CVE IDs
  - Cross-references every CVE with NIST NVD API to get structured version ranges and CVSS scores
  - Stores results tagged `source='CERT-IN'` in the vulnerability database
  - Stdlib only — no extra pip dependencies

- **`SentryPython/init_db.py`** — New one-shot database bootstrapper
  - Creates the full SentryShield SQLite schema (7 tables, 9 indexes)
  - Pulls 1 year of manufacturing-relevant CVEs from NVD (16 keywords: SCADA, HMI, PLC, Siemens, Rockwell, Modbus, Log4j, OpenSSL, WinCC, FactoryTalk, and more)
  - Pulls CERT-In advisories for the same period
  - Prints a formatted summary (count by source, count by severity, DB size)
  - Supports `--days-back`, `--skip-nvd`, `--skip-cert-in`, `--compress` flags

- **`Tests/SentryCore.Tests/USBMonitorTests.cs`** — 11 NUnit tests for USBMonitor
  - Entropy detection fires at/above 7.5 threshold (random data)
  - Low-entropy text files do NOT trigger entropy alert
  - Magic byte mismatch: `.jpg` with MZ header flagged as `Suspicious`
  - Magic byte match: `.exe` with correct MZ header passes
  - Unknown extensions assumed OK (not flagged)
  - IOC hash match produces `CRITICAL` / confidence=100 threat
  - Clean hash produces no IOC threat
  - YARA match via `TestProcessRunner` fake produces `Malware` threat
  - Empty YARA result produces no malware threats
  - Empty directory / nonexistent path handled gracefully
  - Multi-file scan: only the bad file is flagged

- **`Tests/SentryCore.Tests/SupplierFileValidatorTests.cs`** — 14 NUnit tests covering all 7 pipeline steps
  - Step 1: Unknown supplier → immediate BLOCK before file analysis
  - Step 1: Known supplier passes through
  - Step 3: Hash match → integrity check passes
  - Step 3: Hash mismatch → BLOCK with reason
  - Step 3: No manifest hash → skipped gracefully, pipeline continues
  - Step 4: YARA match → BLOCK with rule name in reason
  - Step 4: No YARA match → step 4 passes
  - Step 5: High entropy → WARN (not BLOCK), `IsValid=true`
  - Step 6: IOC hash match → BLOCK even if YARA clean
  - Step 7: SBOM with vulnerable component → BLOCK
  - Step 7: SBOM with clean components → ALLOW
  - Edge: nonexistent file → BLOCK with "not found"
  - Edge: clean trusted file → ALLOW with 64-char SHA-256 FileHash
  - Edge: FileHash always populated in result

- **`Installer/SentryShield.wxs`** — WiX 4 installer stub
  - Installs service binary to `C:\SentryShield\bin\`
  - Installs SentryUI, Python scripts, YARA rules
  - Registers `SentryShield` Windows Service (auto-start, LocalSystem)
  - Creates `C:\ProgramData\SentryShield\` with SYSTEM + Administrators ACLs
  - Creates `C:\SentryShield\Downloads\` with Users write access (supplier gateway)
  - Desktop + Start Menu shortcuts
  - Deferred custom action schedules nightly DB sync via Task Scheduler
  - Uninstall removes scheduled task cleanly
  - v2.0 firewall exception stubbed and commented out
  - GPO silent install: `msiexec /i SentryShield-v1.0-Setup.msi /qn`

### Changed

- **`SentryPython/db_sync.py`** — Nightly scheduler updated
  - Now syncs both NVD (1-day delta) **and** CERT-In (7-day rolling window) every night
  - Removed hard dependency on `curated_vulns.json` — synthetic data no longer loaded by default
  - Graceful fallback if `schedule` package not installed (use `--once` with Task Scheduler instead)

- **`SentryPython/cert_parser.py`** — Fixed version range extraction bug
  - `_extract_version_ranges()` was incorrectly setting `include_min=True` for `versionStartExcluding` entries
  - Fixed: `include_min` is now `True` only for `versionStartIncluding`, `False` for `versionStartExcluding`
  - Same fix applied for `include_max` / `versionEndExcluding`
  - Impact: version boundary conditions in `VulnerabilityMatcher.IsVersionVulnerable()` now evaluate correctly for exclusive ranges

- **`Docs/idea.md`** — Fully rewritten to reflect actual built system
  - Renamed "The Wall" → "SentryShield" throughout
  - Updated timeline from 10-week to 12-week with per-phase status
  - Added live data pipeline diagram (NVD + CERT-In → init_db.py → DB → db_sync.py)
  - Updated DB schema section to match actual 7-table implementation
  - Added version range JSON format documentation
  - Added AI strategy table
  - Added v2.0 roadmap checklist

- **`Docs/SETUP.md`** — Updated for end-user deployment
  - Added NVD API key instructions (Section 7)
  - Added `init_db.py` one-time bootstrap steps with expected output
  - Added Windows Task Scheduler setup for nightly sync
  - Added `setx NVD_API_KEY /M` for SYSTEM account

### Fixed

- **`SentryCore/Engines/VulnerabilityMatcher.cs`** — Fixed 6 compile errors in intern-written code
  - `valueKind` → `ValueKind` (property name casing)
  - `stringComparer` → `StringComparer` (class name casing)
  - `EnnumerateObject()` → `EnumerateObject()` (double-n typo)
  - `ix` undeclared variable → consistent `imax` throughout
  - `core.Split('-')` → `core.Split('.')` (was splitting on `-` again after already stripping suffix)
  - `b.length` / `a.length` → `b.Length` / `a.Length` (C# is case-sensitive)

---

## [v1.0] — 2026-06-03

### Added — Full Initial Build

#### Solution & Infrastructure
- `SentryShield.sln` — multi-project solution
- `.gitignore` — C# + Python + SQLite patterns
- `SentryShield.sln` references: SentryService, SentryCore, SentryDatabase, SentryUI, Tests

#### SentryService (Windows Service)
- `Program.cs` — .NET 8 Worker Service host with DI container
- `SentryWorker.cs` — background polling loop, orchestrates all scan engines on configurable intervals
- `ServiceOptions.cs` — strongly-typed `appsettings.json` bindings
- `appsettings.json` — scan intervals, paths, Python executable config
- `IPC/ProcessRunner.cs` — subprocess IPC bridge; spawns Python scripts, captures JSON stdout, 120s kill timeout
- `Watchers/GatewayFolderWatcher.cs` — `FileSystemWatcher` on supplier drop folder, debounced, triggers `SupplierFileValidator`, quarantine logic, Event Log

#### SentryCore (Detection Library)
- `Interfaces/IDetectionInterfaces.cs` — `IDetectionPlugin`, `IVulnerabilityMatcher`, `ISoftwareEnumerator`, `IUSBMonitor`
- `Models/Models.cs` — `Finding`, `VulnerabilityMatch`, `USBThreat`, `ScanResult`, `ValidationResult`, `InstalledSoftware`, `DriverEntry`, `HardeningCheck`, `GatewayFile`
- `Logging/EventLogWriter.cs` — Windows Event Log writer (Source: SentryShield, Event IDs 1000–5002)
- `Engines/VulnerabilityMatcher.cs` — fuzzy product name match → version range evaluation; `IsVersionVulnerable()` / `ParseVersion()` / `CompareVersions()` (intern-owned)
- `Engines/SoftwareEnumerator.cs` — Registry (HKLM + HKCU, 32+64-bit) primary, WMI `Win32_Product` fallback
- `Engines/USBMonitor.cs` — WMI `__InstanceCreationEvent` listener; per-file: YARA (subprocess), Shannon entropy, magic bytes, IOC hash lookup
- `Engines/SupplierFileValidator.cs` — 7-step pipeline: trusted supplier → SHA-256 manifest → YARA → entropy → IOC → SBOM CVE check → decision (ALLOW/BLOCK/WARN)
- `Engines/DriverAuditor.cs` — WMI `Win32_PnPSignedDriver`; flags unsigned, unknown manufacturer, drivers >3 years old
- `Engines/HardeningAudit.cs` — 6 controls: Windows Defender, Firewall, USB write-protect, AutoRun, RDP enabled, Guest account

#### SentryDatabase (SQLite DAL)
- `DatabaseInitializer.cs` — loads `init.sql` as embedded resource on first start
- `Schema/init.sql` — 7 tables, 9 indexes, WAL mode, schema_version tracking
- `VulnerabilityDb.cs` — fuzzy LIKE product search, bulk upsert, `QueryByProductName()`
- `IOCDb.cs` — SHA-256 lookup (fail-open), bulk insert, async query
- `ScanHistoryDb.cs` — findings CRUD, severity count aggregates, gateway file log, `AcknowledgeFindingAsync()`

#### SentryUI (WPF Dashboard)
- `App.xaml` — merged resource dictionary
- `Resources/Styles.xaml` — dark industrial design system: GitHub-dark-inspired palette, severity colour mapping, card components, DataGrid styles, primary/secondary button templates, summary tile styles
- `MainWindow.xaml` — 4-row layout: header bar with status dot, severity tiles (CRITICAL/HIGH/MEDIUM/LOW/CVEs), tabbed content, status bar with Run Scan + Export JSON
- `ViewModels/DashboardViewModel.cs` — full MVVM: `INotifyPropertyChanged`, 30-second auto-refresh, Run Scan command, JSON export via `SaveFileDialog`, acknowledge finding, status dot colour derived from live severity counts
- `Views/FindingsView.xaml` — sortable DataGrid, severity badge column, row-expand for description + remediation, type/severity filter dropdowns, acknowledge button
- `Views/GatewayView.xaml` — gateway validation log with ALLOW/BLOCK/WARN/PENDING status, supplier, size, timestamp, block reason
- `Views/SettingsView.xaml` — scan schedule dropdowns, gateway validation toggles, DB path display, about section

#### SentryPython
- `cert_parser.py` — NVD JSON 2.0 API with pagination, curated offline fallback, `_extract_version_ranges()`, batch insert
- `yara_scanner.py` — compiles all `.yar` rules, JSON stdout output, benchmark mode, 10s per-file timeout
- `ioc_populate.py` — embedded ICS threat hashes + MalwareBazaar API integration
- `db_sync.py` — daily sync scheduler
- `curated_vulns.json` — 20 manufacturing CVEs (Log4Shell, EternalBlue, BlueKeep, WinCC, FactoryTalk, Modicon PLC…)

#### Rules & Content
- `rules/malware.yar` — 20 YARA rules: Mimikatz, WannaCry, NotPetya, Industroyer, TRITON, Cobalt Strike, BlackEnergy, RubberDucky, Meterpreter, and OT-specific signatures

#### Tests
- `Tests/SentryCore.Tests/SentryCore.Tests.csproj` — NUnit 4 test project
- `Tests/SentryCore.Tests/VulnerabilityMatcherTests.cs` — 15 tests covering: in-range, lower/upper boundary (inclusive/exclusive), pre-release suffix stripping, version padding, open-ended ranges, fuzzy product name matching, empty inputs, CVSS severity mapping, install path preservation
- `Tests/SentryPython/tests/test_sentryshield.py` — 16 pytest tests: YARA scanner (8), cert_parser (6), performance benchmarks (2)

#### Plugins
- `Plugins/IDSPlugin/IDSPlugin.stub.cs` — v2.0 stub demonstrating `IDetectionPlugin` interface; not active in v1.0

#### Documentation
- `Docs/ARCHITECTURE.md` — system diagram, data flows (vuln scan / USB scan / gateway validation), DB schema, plugin interface, IPC design, deployment structure
- `Docs/SETUP.md` — dev setup + production deployment guide
- `Docs/idea.md` — original product vision and scope decisions
- `Docs/ai_strategy.md` — AI usage policy (intern-owned components clearly marked)

---

## Progress vs 12-Week Roadmap

| Phase | Weeks | Target | Status |
|-------|-------|--------|--------|
| Foundation + Architecture | 1–3 | Scaffold, schema, Python stubs | ✅ Complete |
| Core Engines | 4–6 | VulnerabilityMatcher, USBMonitor, Gateway | ✅ Complete |
| Integration + Gateway | 7–9 | IPC bridge, folder watcher, driver audit | ✅ Complete |
| Dashboard + Testing | 10–12 | WPF UI, NUnit tests, docs | ✅ Complete |