# SentryShield

> **Offline-first security monitoring for ICS/OT and manufacturing environments.**
> No cloud. No agents. No internet required after initial database seeding.

[![Platform](https://img.shields.io/badge/Platform-Windows%2010%2F11-blue)]()
[![.NET](https://img.shields.io/badge/.NET-8.0-purple)]()
[![Python](https://img.shields.io/badge/Python-3.11-yellow)]()
[![Tests](https://img.shields.io/badge/Tests-40%20NUnit%20%7C%2016%20pytest-green)]()
[![Version](https://img.shields.io/badge/Version-v1.1-orange)]()

---

## What is SentryShield?

SentryShield is a Windows security monitoring tool built specifically for manufacturing plants, industrial control systems (ICS), and OT environments. It runs as a lightweight Windows service, operates fully air-gapped, and gives plant operators a single dashboard to track vulnerabilities, USB threats, driver issues, and supplier file integrity.

**Four pillars:**

| Pillar | What it does |
|--------|-------------|
| 🔍 **Vulnerability Scanner** | Enumerates installed software, matches against live NVD + CERT-In CVE data with exact version range evaluation |
| 🔌 **USB Threat Detection** | Intercepts USB insertions via WMI, runs YARA (20 rules), Shannon entropy, magic byte, and IOC hash checks |
| 🚪 **Supplier File Gateway** | 7-step validation pipeline for files dropped by external suppliers — blocks unknowns, YARA hits, and IOC matches |
| 🛡 **Driver & Hardening Audit** | Flags unsigned/outdated drivers and checks 6 Windows security controls (Defender, Firewall, RDP, AutoRun, etc.) |

---

## Repository Layout

```
SentryShield/
├── SentryShield.sln
├── CHANGELOG.md
│
├── SentryService/              # .NET 8 Windows Service (orchestrator)
│   ├── SentryWorker.cs         # Background polling loop
│   ├── IPC/ProcessRunner.cs    # Python subprocess bridge
│   └── Watchers/GatewayFolderWatcher.cs
│
├── SentryCore/                 # Core detection library (C#)
│   ├── Engines/
│   │   ├── VulnerabilityMatcher.cs     # ← intern-owned (version logic)
│   │   ├── USBMonitor.cs
│   │   ├── SupplierFileValidator.cs
│   │   ├── DriverAuditor.cs
│   │   ├── HardeningAudit.cs
│   │   └── SoftwareEnumerator.cs
│   ├── Interfaces/             # IDetectionPlugin, IUSBMonitor, IValidator…
│   ├── Models/                 # Finding, VulnerabilityMatch, USBThreat…
│   └── Logging/EventLogWriter.cs
│
├── SentryDatabase/             # SQLite DAL (C#)
│   ├── Schema/init.sql         # 7 tables, 9 indexes, WAL mode
│   ├── VulnerabilityDb.cs
│   ├── IOCDb.cs
│   └── ScanHistoryDb.cs
│
├── SentryUI/                   # WPF Admin Dashboard (.NET 8)
│   ├── MainWindow.xaml         # Dark industrial layout
│   ├── ViewModels/DashboardViewModel.cs
│   └── Views/                  # FindingsView, GatewayView, SettingsView
│
├── SentryPython/               # Python utilities
│   ├── init_db.py              # ← one-time DB bootstrapper (run first)
│   ├── cert_parser.py          # NVD JSON 2.0 API parser
│   ├── cert_in_parser.py       # CERT-In advisory scraper + NVD cross-ref
│   ├── db_sync.py              # Nightly NVD + CERT-In delta sync
│   ├── yara_scanner.py         # YARA scan → JSON stdout
│   └── ioc_populate.py         # IOC hash database loader
│
├── rules/
│   └── malware.yar             # 20 YARA rules (Mimikatz, WannaCry, TRITON…)
│
├── Installer/
│   └── SentryShield.wxs        # WiX 4 MSI installer definition
│
├── Plugins/
│   └── IDSPlugin/IDSPlugin.stub.cs   # v2.0 placeholder
│
├── Tests/
│   ├── SentryCore.Tests/
│   │   ├── VulnerabilityMatcherTests.cs   # 15 tests
│   │   ├── USBMonitorTests.cs             # 11 tests
│   │   └── SupplierFileValidatorTests.cs  # 14 tests
│   └── SentryPython/tests/
│       └── test_sentryshield.py           # 16 pytest tests
│
└── Docs/
    ├── SETUP.md          # Dev + deployment guide
    ├── ARCHITECTURE.md   # System design + data flows
    ├── idea.md           # Product vision + roadmap
    └── ai_strategy.md    # AI usage policy
```

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Windows | 10 / 11 / Server 2019+ | Admin rights required |
| .NET SDK | 8.0 | https://dotnet.microsoft.com/download |
| Python | 3.11 | https://www.python.org/downloads |
| WiX (optional) | 4.x | Only needed to build the `.msi` installer |

> **Windows 7 / Embedded**: .NET 8 does not support Windows 7. For legacy HMIs, recompile `SentryCore` targeting .NET Framework 4.8 (v2.0 work item).

---

## Quick Start (Developer)

```cmd
git clone https://github.com/Rizzy1857/SentryShield
cd SentryShield

:: Python environment
cd SentryPython
python -m venv venv
venv\Scripts\activate
pip install yara-python requests pytest

:: Build and test
cd ..
dotnet build SentryShield.sln
dotnet test Tests/SentryCore.Tests/ --logger "console;verbosity=normal"
pytest Tests/SentryPython/tests/ -v
```

---

## Vulnerability Database (Live Data)

SentryShield uses **real CVE data** — no synthetic vulnerabilities. The database is populated from two sources:

| Source | What | Script |
|--------|------|--------|
| **NIST NVD** | Manufacturing-relevant CVEs (SCADA, HMI, PLC, Siemens, Log4j, OpenSSL…) | `cert_parser.py` |
| **CERT-In** | India CERT advisory feed, CVE cross-referenced with NVD | `cert_in_parser.py` |

**One-time setup** (run on Windows after deploying):
```cmd
set NVD_API_KEY=your-free-key-here   :: from nvd.nist.gov/developers/request-an-api-key
python SentryPython\init_db.py --db "C:\ProgramData\SentryShield\vulnerability.db" --days-back 365
```

See `Docs/SETUP.md` → Section 7–9 for the full deployment guide.

---

## Test Coverage

| Suite | File | Tests |
|-------|------|-------|
| Vulnerability matching | `VulnerabilityMatcherTests.cs` | 15 |
| USB threat detection | `USBMonitorTests.cs` | 11 |
| Supplier file gateway | `SupplierFileValidatorTests.cs` | 14 |
| **NUnit total** | | **40** |
| Python (YARA + NVD parser) | `test_sentryshield.py` | 16 |
| **Grand total** | | **56** |

```cmd
:: Run all NUnit tests
dotnet test Tests/SentryCore.Tests/ --logger "console;verbosity=normal"

:: Run all pytest tests
pytest Tests/SentryPython/tests/ -v
```

---

## Architecture

```
NVD API ──────┐
CERT-In ───────┤──► init_db.py / db_sync.py ──► vulnerability.db
               │                                       │
               │    SentryService (.NET 8)             │
               │    ├── SentryWorker (polling)  ◄──────┘
               │    ├── GatewayFolderWatcher            │
               │    └── ProcessRunner (IPC)             │
               │              │  subprocess             │
               │    SentryPython (Python)               │
               │    └── yara_scanner.py                 │
               │                                        │
               │    SentryCore                          │
               │    ├── VulnerabilityMatcher ───────────┘
               │    ├── USBMonitor
               │    ├── SupplierFileValidator
               │    ├── DriverAuditor
               │    └── HardeningAudit
               │              │
               └──────► SentryUI (WPF Dashboard)
```

Full architecture: `Docs/ARCHITECTURE.md`

---

## Installer

Build the MSI:
```cmd
:: Publish binaries first
dotnet publish SentryService -c Release -r win-x64 -o publish\SentryService
dotnet publish SentryUI      -c Release -r win-x64 -o publish\SentryUI

:: Build MSI (requires WiX 4)
cd Installer
wix build SentryShield.wxs -o SentryShield-v1.0-Setup.msi
```

Silent GPO install:
```cmd
msiexec /i SentryShield-v1.0-Setup.msi /qn /l*v install.log
```

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the full version history.

| Version | Date | Highlights |
|---------|------|-----------|
| v1.1 | 2026-06-04 | Live CERT-In pipeline, `init_db.py`, WiX installer, 25 new tests |
| v1.0 | 2026-06-03 | Initial full build — all 4 pillars, WPF dashboard, 31 tests |

---

## License

MIT — see `LICENSE` if one applies.
