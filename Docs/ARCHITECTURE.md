# SentryShield v1.0 Architecture

## Overview

SentryShield is an **offline-first, lightweight security monitoring system** for manufacturing plants running ICS/OT workloads. It operates fully air-gapped with no external network dependency after initial database seeding.

```
┌──────────────────────────────────────────────────────────────────┐
│                     SentryShield v1.0                            │
│                                                                  │
│  ┌──────────────┐    IPC (subprocess)    ┌─────────────────────┐ │
│  │  SentryService│◄─────────────────────►│   SentryPython       │ │
│  │  (C# .NET 8)  │                       │  cert_parser.py      │ │
│  │               │                       │  yara_scanner.py     │ │
│  │  SentryWorker │                       │  ioc_populate.py     │ │
│  │  (BackgroundSvc)                      │  db_sync.py          │ │
│  └──────┬────────┘                       └─────────────────────┘ │
│         │                                                        │
│         ▼                                                        │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │                     SentryCore                            │    │
│  │  VulnerabilityMatcher  │  USBMonitor  │  DriverAuditor    │    │
│  │  SupplierFileValidator │  HardeningAudit                  │    │
│  └──────────────────────────────────────────────────────────┘    │
│         │                                                        │
│         ▼                                                        │
│  ┌──────────────────┐    ┌──────────────────────────────────┐    │
│  │   SentryDatabase │    │          SentryUI                │    │
│  │   SQLite 3       │◄───│          WPF Dashboard           │    │
│  │   vulnerability.db    │          (DashboardViewModel)    │    │
│  └──────────────────┘    └──────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘
```

---

## Component Responsibilities

### SentryService (C# .NET 8 Windows Service)
- **Lifecycle**: Runs as a Windows service (`sc start SentryShield`)
- **Orchestration**: `SentryWorker` polls every 60 seconds, triggers scans on interval
- **IPC**: `ProcessRunner` spawns Python subprocesses, captures JSON stdout
- **Gateway**: `GatewayFolderWatcher` monitors supplier drop folder via `FileSystemWatcher`

### SentryCore (C# Class Library)
- **VulnerabilityMatcher**: Fuzzy product name match → semantic version range evaluation
- **SoftwareEnumerator**: Registry (primary) + WMI Win32_Product (fallback)
- **USBMonitor**: WMI `__InstanceCreationEvent` listener → YARA + entropy + magic bytes + IOC
- **SupplierFileValidator**: Supplier manifest → YARA → entropy → IOC hash → SBOM check
- **DriverAuditor**: WMI `Win32_PnPSignedDriver` → flags unsigned/unknown/old drivers
- **HardeningAudit**: Registry + WMI checks for Defender, Firewall, USB write-protect, AutoRun, RDP, Guest

### SentryDatabase (C# Class Library)
- **SQLite 3** with WAL mode for concurrent read/write
- **DatabaseInitializer**: Loads `init.sql` as embedded resource on first startup
- Schema: 7 tables + 9 performance indexes

### SentryPython (Python 3.11 scripts)
- **cert_parser.py**: NVD JSON 2.0 API + local curated JSON fallback
- **yara_scanner.py**: Compiles all `.yar` files, outputs JSON matches to stdout
- **ioc_populate.py**: MalwareBazaar + curated embedded ICS threat hashes
- **db_sync.py**: Daily scheduler (NVD + curated sync at 06:00)

### SentryUI (WPF .NET 8)
- **MVVM**: `DashboardViewModel` with `INotifyPropertyChanged`
- **Auto-refresh**: 30-second timer
- **Tabs**: Findings (DataGrid) | Gateway | Settings
- **Export**: JSON export with `SaveFileDialog`

---

## Data Flow

### Vulnerability Scan Flow
```
SentryWorker (timer)
  → SoftwareEnumerator.EnumerateInstalledSoftware()
    [Registry + WMI Win32_Product]
  → VulnerabilityMatcher.FindVulnerabilities(name, version, path)
    [LIKE query → IsVersionVulnerable() → CalculateSeverity()]
  → ScanHistoryDb.SaveFindingsAsync()
  → EventLogWriter.WriteFinding()
```

### USB Scan Flow
```
USB inserted (WMI event)
  → USBMonitor.OnUSBConnected()
  → ProcessRunner.RunYaraScanAsync(drivePath)   [Python subprocess]
    → yara_scanner.py --scan-dir → stdout JSON
  → Per-file: CalculateEntropy() + IsMagicByteMatch() + IOCDb.IsKnownBadHashAsync()
  → ThreatDetected event → ScanHistoryDb.SaveFindingsAsync()
  → EventLogWriter.WriteFinding()
```

### Gateway Validation Flow
```
File dropped in C:\SentryShield\Downloads\<SupplierName>\
  → GatewayFolderWatcher.OnFileCreated()
  → 2s delay (copy completion)
  → SupplierFileValidator.ValidateAsync()
    1. Trusted supplier check
    2. SHA-256 vs manifest
    3. ProcessRunner.RunYaraScanFileAsync() [Python subprocess]
    4. CalculateEntropy()
    5. IOCDb.IsKnownBadHashAsync()
    6. SBOM component CVE check (if .sbom.json exists)
  → Decision: ALLOW | BLOCK | WARN
  → ScanHistoryDb.RecordGatewayFileAsync()
  → If BLOCK: QuarantineFile() → C:\SentryShield\Downloads\Quarantine\
  → EventLogWriter (Event IDs 5000/5001/5002)
```

---

## Database Schema Summary

| Table | Purpose | Key Columns |
|-------|---------|-------------|
| `vulnerabilities` | CVE/curated vuln list | id, product_name, affected_versions (JSON), cvss_score |
| `iocs` | Malware hash lookup | file_hash (SHA-256), malware_name, confidence |
| `software_inventory` | Per-scan software snapshot | machine_name, software_name, version, is_vulnerable |
| `scan_results` | Scan run history | scan_type, findings_count, critical_count, duration_seconds |
| `findings` | All detections | id, severity, finding_type, title, acknowledged |
| `gateway_files` | Gateway validation log | filename, supplier_name, validation_status, block_reason |
| `trusted_suppliers` | Allowed gateway suppliers | supplier_name, is_active |

---

## Version Range JSON Format

The `affected_versions` column stores JSON arrays consumed by `VulnerabilityMatcher.IsVersionVulnerable()`:

```json
[
  {
    "min": "2.0.0",
    "max": "2.17.0",
    "include_min": true,
    "include_max": false
  }
]
```

- `null` min = no lower bound (all versions ≤ max are affected)
- `null` max = no upper bound (all versions ≥ min are affected)
- `include_min`/`include_max` = inclusive/exclusive boundary

---

## Plugin Architecture (v2.0 Extension)

All detection engines implement `IDetectionPlugin`:

```csharp
public interface IDetectionPlugin {
    string Name { get; }
    void Initialize(Dictionary<string, string> config);
    Task<List<Finding>> ScanAsync(CancellationToken ct = default);
    void OnAlert(Finding finding);
}
```

v1.0 implements: VulnerabilityEngine, USBMonitor, DriverAuditor, HardeningAudit, SupplierFileValidator  
v2.0 stub exists: `Plugins/IDSPlugin/IDSPlugin.stub.cs`

---

## IPC Design Decision

**v1.0: Subprocess (C# spawns Python, reads JSON stdout)**
- Simple, no persistent state
- 120s timeout with process tree kill
- stderr → ILogger, stdout → JSON parse

**v2.0 option: Named Pipe server**
- Persistent Python worker
- Streaming results
- Required for real-time YARA monitoring

---

## Deployment

```
SentryShield/
├── SentryService.exe        (Windows service binary)
├── SentryUI.exe             (Admin dashboard)
├── appsettings.json         (Configuration)
├── SentryPython/            (Python scripts + venv)
│   ├── yara_scanner.py
│   ├── cert_parser.py
│   ├── db_sync.py
│   └── curated_vulns.json
├── rules/
│   └── malware.yar          (20 curated YARA rules)
└── vulnerability.db         (SQLite database, pre-seeded)
```

Service install:
```cmd
sc create SentryShield binPath= "C:\SentryShield\SentryService.exe" start= auto
sc start SentryShield
```
