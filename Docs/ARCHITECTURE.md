# SentryShield v2.1-alpha — Architecture

## Overview

SentryShield is an **offline-first, lightweight security monitoring system** for manufacturing plants, ICS/OT workloads, and air-gapped Windows environments. It operates with no cloud dependency after initial database seeding and exposes all findings through a dark-themed WPF admin dashboard.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        SentryShield v1.1                            │
│                                                                     │
│  LIVE DATA SOURCES                                                  │
│  NVD API ──────┐                                                    │
│  CERT-In ──────┼──► init_db.py (one-time) ──► vulnerability.db     │
│                │         db_sync.py (nightly delta)                 │
│                │                    │                               │
│  ┌─────────────┴──────┐  subprocess IPC  ┌───────────────────────┐  │
│  │   SentryService    │◄───────────────►│    SentryPython        │  │
│  │   (.NET 8 Worker)  │  ProcessRunner  │  yara_scanner.py       │  │
│  │                    │  stdout JSON    │  cert_parser.py        │  │
│  │  SentryWorker      │  120s timeout   │  cert_in_parser.py     │  │
│  │  GatewayFolderWatch│                 │  db_sync.py            │  │
│  └──────────┬─────────┘                 └───────────────────────┘  │
│             │                                                       │
│             ▼                                                       │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                        SentryCore                             │   │
│  │  VulnerabilityMatcher   USBMonitor   DriverAuditor            │   │
│  │  SupplierFileValidator  HardeningAudit  SoftwareEnumerator    │   │
│  └───────────────────────────────────┬──────────────────────────┘   │
│                                      │                              │
│  ┌───────────────────┐    ┌───────────┴────────────────────────┐   │
│  │   SentryDatabase  │◄───│            SentryUI                 │   │
│  │   SQLite 3 (WAL)  │    │  WPF Dashboard (MVVM)              │   │
│  │   7 tables        │    │  FindingsView | GatewayView         │   │
│  │   9 indexes       │    │  SettingsView | DashboardViewModel  │   │
│  └───────────────────┘    └────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Component Responsibilities

### SentryService — C# .NET 8 Worker Service
- **Lifecycle**: Registered as a Windows service (`sc create SentryShield`)
- **SentryWorker**: Background polling loop; triggers scans on configurable interval
- **ProcessRunner** (`IPC/ProcessRunner.cs`): Spawns Python subprocesses, captures JSON stdout, kills on 120s timeout
- **GatewayFolderWatcher** (`Watchers/`): `FileSystemWatcher` on `C:\SentryShield\Downloads\<SupplierName>\`; 2-second debounce before validation; quarantines blocked files

### SentryCore — C# Detection Library
| Engine | Key Logic |
|--------|-----------|
| `VulnerabilityMatcher` | Registry fuzzy `LIKE` query → `IsVersionVulnerable()` (intern-owned) → `CalculateSeverity()` |
| `SoftwareEnumerator` | Registry HKLM/HKCU (32+64-bit) primary; WMI `Win32_Product` fallback |
| `USBMonitor` | WMI `__InstanceCreationEvent` listener → YARA batch scan + per-file entropy + magic byte + IOC hash |
| `SupplierFileValidator` | 7-step pipeline: trusted supplier → SHA-256 manifest → YARA → entropy → IOC → SBOM → decision |
| `DriverAuditor` | WMI `Win32_PnPSignedDriver` → flags unsigned, unknown manufacturer, drivers > 3 years old |
| `HardeningAudit` | Registry + WMI: Defender status, Firewall, USB write-protect, AutoRun disabled, RDP, Guest account |

### SentryDatabase — C# SQLite DAL
- SQLite 3 in WAL mode for concurrent read/write
- `DatabaseInitializer.cs` loads `Schema/init.sql` as an embedded resource on first start
- 7 tables, 9 performance indexes (see Schema section below)

### SentryPython — Python 3.11 Scripts
| Script | Purpose |
|--------|---------|
| `init_db.py` | **One-time bootstrapper** — creates schema + pulls 1 year of NVD + CERT-In data |
| `cert_parser.py` | NVD JSON 2.0 API with pagination, 16 manufacturing keywords, batch insert |
| `cert_in_parser.py` | CERT-In RSS + HTML scraping → CVE extraction → NVD cross-reference |
| `db_sync.py` | Nightly: NVD 1-day delta + CERT-In 7-day rolling window |
| `yara_scanner.py` | Compiles `.yar` rules, scans files/dirs, outputs JSON to stdout |
| `ioc_populate.py` | MalwareBazaar API + embedded ICS/OT threat hashes |

### SentryUI — WPF .NET 8 Dashboard
- Dark industrial design system (`Resources/Styles.xaml`)
- MVVM: `DashboardViewModel` with `INotifyPropertyChanged`, 30-second auto-refresh
- **Findings tab**: Sortable `DataGrid`, severity badges, type/severity filters, acknowledge button
- **Gateway tab**: Validation log — ALLOW/BLOCK/WARN/PENDING per file
- **Settings tab**: Scan schedule, gateway toggles, DB path
- **Export**: JSON export via `SaveFileDialog`

---

## Data Flows

### Vulnerability Scan
```
SentryWorker (timer fires)
  → SoftwareEnumerator.EnumerateInstalledSoftware()
      Registry HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall (64-bit)
      Registry HKLM\SOFTWARE\WOW6432Node\...                             (32-bit)
      Registry HKCU\SOFTWARE\...                                         (user installs)
      Fallback: WMI Win32_Product
  → foreach (software):
      VulnerabilityMatcher.FindVulnerabilities(name, version, path)
        VulnerabilityDb.QueryByProductName(name)   ← fuzzy LIKE search
        IsVersionVulnerable(version, affected_versions_json)
          ParseVersion("2.13.0-rc1") → [2, 13, 0]
          CompareVersions([2,13,0], [2,17,0]) → -1
          Boundary check (include_min / include_max)
        CalculateSeverity(cvssScore, rawSeverity)
  → ScanHistoryDb.SaveFindingsAsync(findings)
  → EventLogWriter.WriteFinding()  [Event ID 1001]
```

### USB Threat Detection
```
USB device inserted
  → WMI __InstanceCreationEvent fires (Win32_USBControllerDevice, within 2s)
  → USBMonitor.OnUSBConnected()
  → DriveInfo.GetDrives() → filter DriveType.Removable + IsReady
  → Task.Run(ScanUSBDrive(drivePath))
      ProcessRunner.RunYaraScanAsync(drivePath)
        python yara_scanner.py --scan-dir <path> → stdout JSON
        → Parse YaraMatch[] → USBThreat(ThreatType="Malware", Confidence=95)
      foreach (file):
        CalculateEntropy(file)       → if > 7.5: USBThreat(ThreatType="Entropy")
        ReadMagicBytes + IsMagicByteMatch(ext)
                                     → if mismatch: USBThreat(ThreatType="Suspicious")
        ComputeSHA256(file)
        IOCDb.IsKnownBadHashAsync()  → if match: USBThreat(ThreatType="IOC", CRITICAL)
  → ThreatDetected event
  → ScanHistoryDb.SaveFindingsAsync()
  → EventLogWriter [Event ID 2001]
```

### Supplier File Gateway
```
File dropped to: C:\SentryShield\Downloads\<SupplierName>\file.exe
  → GatewayFolderWatcher.OnFileCreated()
  → await Task.Delay(2000)  (wait for copy to complete)
  → SupplierFileValidator.ValidateAsync(filePath, supplierName)

  Step 1  Trusted supplier check
          _trustedManifests.ContainsKey(supplierName)
          → if false: BLOCK "Supplier not in trusted list"

  Step 2  SHA-256 computation
          ComputeSHA256(filePath) → result.FileHash

  Step 3  Manifest hash check (if entry exists for this filename)
          manifest.ExpectedHashes[fileName] == fileHash
          → if mismatch: BLOCK "Hash does not match manifest"

  Step 4  YARA malware scan
          ProcessRunner.RunYaraScanFileAsync(filePath)
          → python yara_scanner.py --scan-file <path>
          → if any match: BLOCK "Malware detected: <rule_name>"

  Step 5  Shannon entropy
          CalculateEntropy(filePath, sample=8192 bytes)
          → if > 7.8: WARN (not BLOCK — operator must review)

  Step 6  IOC hash lookup
          IOCDb.IsKnownBadHashAsync(fileHash)
          → if match: BLOCK "Hash matches known malware IOC"

  Step 7  SBOM check (if <filename>.sbom.json exists)
          Parse CycloneDX/SPDX components array
          VulnerabilityMatcher.FindVulnerabilities(component.name, version, "")
          → if any CVEs found: BLOCK "SBOM contains vulnerable components"

  Final:  ALLOW | BLOCK | WARN
  → ScanHistoryDb.RecordGatewayFileAsync()
  → if BLOCK: File.Move(filePath, quarantineDir)
  → EventLogWriter [5000=ALLOW, 5001=BLOCK, 5002=WARN]
```

### Live Vulnerability Database Population
```
One-time (init_db.py --days-back 365):
  → Creates SQLite schema (7 tables, 9 indexes)
  → NVDFeedParser.sync_from_nvd(16 keywords, days_back=365)
      GET https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=SCADA&...
      Paginate (results_per_page=200)
      _extract_version_ranges() → [{min, max, include_min, include_max}]
      INSERT OR IGNORE INTO vulnerabilities
  → CERTInParser.sync(days_back=365)
      GET https://www.cert-in.org.in/s2cMainServlet?pageid=PUBVLNOTES01&rss=true
      Parse RSS → advisory list (CIVN IDs)
      Scrape each advisory HTML → extract CVE IDs
      fetch_nvd_cve(cve_id) → full NVD record
      INSERT OR IGNORE (source='CERT-IN')

Nightly (db_sync.py --once via Task Scheduler at 06:00):
  → NVD delta: days_back=1
  → CERT-In: days_back=7 (rolling window)
  → Compress DB to .gz + SHA-256 checksum
```

---

## Database Schema

```sql
-- WAL mode for concurrent read/write
PRAGMA journal_mode=WAL;

vulnerabilities (id PK, product_name, affected_versions JSON, cvss_score,
                 severity, description, remediation, source, first_seen)

iocs            (id PK, file_hash UNIQUE, malware_name, malware_family,
                 confidence 0-100, source, detection_date)

software_inventory (id PK, machine_name, software_name, version,
                    publisher, install_path, is_vulnerable, scan_timestamp)

scan_results    (id PK, scan_type, machine_name, start_time, end_time,
                 findings_count, critical_count, high_count, medium_count,
                 low_count, duration_seconds, success, error_message)

findings        (id TEXT PK UUID, machine_name, finding_type, severity,
                 title, description, affected_component, remediation,
                 detection_timestamp, acknowledged, notes)

gateway_files   (id PK, filename, supplier_name, file_hash, file_size,
                 received_timestamp, validation_status, block_reason,
                 validation_timestamp, transferred_to_ot)

trusted_suppliers (id PK, supplier_name UNIQUE, contact_email,
                   is_active, added_date)

schema_version  (version PK, applied_at, notes)
```

**Indexes** (9 total):
```sql
idx_vuln_product, idx_vuln_severity, idx_vuln_source, idx_vuln_cvss
idx_ioc_hash
idx_sw_machine, idx_sw_name_ver
idx_findings_machine, idx_findings_severity, idx_findings_type, idx_findings_ack
```

### Version Range JSON Format

`affected_versions` column stores arrays consumed by `VulnerabilityMatcher.IsVersionVulnerable()`:

```json
[
  {"min": "2.0.0", "max": "2.17.0", "include_min": true,  "include_max": false},
  {"min": null,    "max": "1.9.9",  "include_min": false, "include_max": true}
]
```

| Field | Meaning | NVD Source Field |
|-------|---------|-----------------|
| `include_min: true` | `>= min` | `versionStartIncluding` |
| `include_min: false` | `> min` | `versionStartExcluding` |
| `include_max: true` | `<= max` | `versionEndIncluding` |
| `include_max: false` | `< max` | `versionEndExcluding` |
| `null` min | no lower bound | (absent) |
| `null` max | no upper bound | (absent) |

---

## IPC Design

**v1.0: Subprocess (C# → Python)**
```
ProcessRunner.RunYaraScanAsync(path)
  → Process.Start("python yara_scanner.py --scan-dir <path>")
  → stdout: JSON array of matches
  → stderr: redirected to ILogger
  → 120-second timeout, process tree kill on timeout
```

**v2.0 option: Named Pipe server**
- Persistent Python worker — no startup overhead
- Streaming results
- Required for real-time monitoring mode

---

## Plugin Architecture (v2.0 Extension Point)

All detection engines implement `IDetectionPlugin`:

```csharp
public interface IDetectionPlugin {
    string Name { get; }
    void Initialize(Dictionary<string, string> config);
    Task<List<Finding>> ScanAsync(CancellationToken ct = default);
    void OnAlert(Finding finding);
}
```

| Plugin | v1.0 Status |
|--------|-------------|
| VulnerabilityEngine | ✅ Active |
| USBMonitor | ✅ Active |
| DriverAuditor | ✅ Active |
| HardeningAudit | ✅ Active |
| SupplierFileValidator | ✅ Active |
| IDSPlugin | ✅ Active (`SentryPlugin.IDS` via SharpPcap) |
| BehavioralPlugin | 🔲 v2.0 |
| FirmwarePlugin | 🔲 v2.0 |

---

## Test Architecture

Tests avoid real WMI, real Python, and real SQLite using purpose-built fakes:

| Fake | Replaces | Used in |
|------|----------|---------|
| `TestIOCDb` | `IOCDb` (SQLite) | `USBMonitorTests` |
| `TestProcessRunner` | `ProcessRunner` (Python subprocess) | `USBMonitorTests` |
| `TestIOCDbV` | `IOCDb` (SQLite) | `SupplierFileValidatorTests` |
| `TestProcessRunnerV` | `ProcessRunner` (Python subprocess) | `SupplierFileValidatorTests` |
| `TestVulnMatcher` | `VulnerabilityMatcher` (DB) | `SupplierFileValidatorTests` |

`VulnerabilityMatcherTests` use only in-memory logic — no fakes required.

---

## Deployment Layout

```
C:\SentryShield\
├── bin\
│   ├── SentryService.exe     (Windows service)
│   ├── SentryUI.exe          (Admin dashboard)
│   └── appsettings.json
├── scripts\                  (Python scripts + venv)
│   ├── venv\
│   ├── init_db.py
│   ├── cert_parser.py
│   ├── cert_in_parser.py
│   ├── db_sync.py
│   ├── yara_scanner.py
│   └── ioc_populate.py
├── rules\
│   └── malware.yar           (20 YARA rules)
└── Downloads\                (Supplier gateway drop folder)
    └── <SupplierName>\
        └── Quarantine\

C:\ProgramData\SentryShield\
├── vulnerability.db          (SQLite — survives upgrades)
├── backups\
└── logs\
```

**Service install:**
```cmd
sc create SentryShield binPath= "C:\SentryShield\bin\SentryService.exe" start= auto DisplayName= "SentryShield Security Agent"
sc start SentryShield
```

**Or use the MSI installer** (handles service + Task Scheduler + ACLs automatically):
```cmd
msiexec /i SentryShield-v1.0-Setup.msi /qn /l*v install.log
```

---

## Windows Event Log IDs

| Event ID | Source | Meaning |
|----------|--------|---------|
| 1000 | SentryShield | Service started |
| 1001 | SentryShield | Vulnerability finding |
| 2001 | SentryShield | USB threat detected |
| 3001 | SentryShield | Driver audit finding |
| 4001 | SentryShield | Hardening check finding |
| 5000 | SentryShield | Gateway: ALLOW |
| 5001 | SentryShield | Gateway: BLOCK |
| 5002 | SentryShield | Gateway: WARN |
