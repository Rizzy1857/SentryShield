# SentryShield

> **Offline-first security monitoring for ICS/OT and manufacturing environments.**
> No cloud. No agents. No internet required after initial database seeding.

[![Platform](https://img.shields.io/badge/Platform-Windows%207%2F10%2F11-blue)]()
[![.NET](https://img.shields.io/badge/.NET-8.0%20%7C%204.8-purple)]()
[![Python](https://img.shields.io/badge/Python-3.11-yellow)]()
[![Tests](https://img.shields.io/badge/Tests-43%20NUnit%20%7C%2016%20pytest-green)]()
[![Version](https://img.shields.io/badge/Version-v2.5--stable-orange)]()

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
│
├── SentryService/              # .NET 8 Windows Service (modern deployments)
│   ├── SentryWorker.cs         # Background polling loop
│   ├── IPC/ProcessRunner.cs    # Python subprocess bridge
│   └── Watchers/GatewayFolderWatcher.cs
│
├── SentryLegacyService/        # .NET 4.8 Windows Service (Win7 / WES7 HMIs)
│   ├── LegacyServiceHost.cs    # ServiceBase + System.Threading.Timer
│   ├── LegacyYaraGuard.cs      # Optional YARA — graceful fallback if Python absent
│   ├── LegacyConfig.cs         # Typed config model
│   ├── Program.cs              # Headless ServiceBase.Run() entry point
│   └── appsettings.json
│
├── SentryCore/                 # Core detection library — dual-targets net8 + net48
│   ├── Engines/
│   │   ├── VulnerabilityMatcher.cs
│   │   ├── USBMonitor.cs
│   │   ├── SupplierFileValidator.cs
│   │   ├── DriverAuditor.cs
│   │   ├── HardeningAudit.cs
│   │   └── SoftwareEnumerator.cs
│   ├── Interfaces/
│   ├── Models/
│   └── Logging/EventLogWriter.cs
│
├── SentryDatabase/             # SQLite DAL — dual-targets net8 + net48
│   ├── Schema/init.sql
│   ├── VulnerabilityDb.cs
│   ├── IOCDb.cs
│   └── ScanHistoryDb.cs
│
├── SentryUI/                   # WPF Admin Dashboard (.NET 8)
│   ├── MainWindow.xaml
│   ├── ViewModels/DashboardViewModel.cs
│   └── Views/
│
├── SentryPython/               # Python utilities
│   ├── init_db.py
│   ├── cert_parser.py
│   ├── cert_in_parser.py
│   ├── db_sync.py
│   ├── yara_scanner.py
│   └── ioc_populate.py
│
├── rules/
│   └── malware.yar
│
├── Installer/
│   └── SentryShield.wxs
│
├── Plugins/
│   └── IDSPlugin/IDSPlugin.stub.cs
│
├── Tests/
│   ├── SentryCore.Tests/
│   └── SentryPython/tests/
│
└── docs/
    ├── ARCHITECTURE.md
    ├── CHANGELOG.md
    ├── CONTRIBUTING.md
    ├── PRODUCTION_PATHWAYS.md
    ├── ROADMAP.md
    ├── SETUP.md
    ├── WIN7_COMPAT.md    # Legacy HMI deployment guide
    ├── ai_strategy.md
    └── idea.md
```

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Windows | 10 / 11 / Server 2019+ | Admin rights required — for modern deployments |
| .NET SDK | 8.0 | https://dotnet.microsoft.com/download |
| Python | 3.11 | https://www.python.org/downloads |
| WiX (optional) | 4.x | Only needed to build the `.msi` installer |

**Legacy HMI (Windows 7 / Embedded):** Use `SentryLegacyService` instead of `SentryService`. See [`Docs/WIN7_COMPAT.md`](Docs/WIN7_COMPAT.md) for the full deployment guide.

| Requirement | Version | Notes |
|-------------|---------|-------|
| Windows 7 SP1 / WES7 / WE8.1 | — | Admin rights required |
| .NET Framework 4.8 | 4.8.x | [Download](https://dotnet.microsoft.com/download/dotnet-framework/net48) — must be installed manually on Win7 |
| Python (optional) | 3.8–3.11 | Only for YARA scanning — service works without it |

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
| Network IDS | `IDSPluginTests.cs` | 3 |
| **NUnit total** | | **43** |
| Python (YARA + NVD parser) | `test_sentryshield.py` | 16 |
| **Grand total** | | **56** |

```cmd
:: Run all NUnit tests
dotnet test Tests/SentryCore.Tests/ --logger "console;verbosity=normal"

:: Run all pytest tests
pytest Tests/SentryPython/tests/ -v
```

---

## Documentation

Comprehensive guides and strategic documents are located in the [`docs/`](docs/) directory:
- [**Setup Guide**](docs/SETUP.md): Deployment and installation instructions.
- [**Architecture**](docs/ARCHITECTURE.md): Detailed system design and component diagrams.
- [**Production Pathways**](docs/PRODUCTION_PATHWAYS.md): Executive roadmap and future investment strategies for SentryShield.
- [**Roadmap**](docs/ROADMAP.md): Developer roadmap detailing upcoming feature phases.
- [**Contributing**](docs/CONTRIBUTING.md): Guidelines for developing new detection plugins.
- [**Windows 7 Legacy Guide**](docs/WIN7_COMPAT.md): Deploying to older HMI environments.

---

## Architecture

```
NVD API ──────┐
CERT-In ───────┤──► init_db.py / db_sync.py ──► vulnerability.db
               │                                       │
               │    ┌─────────────────────────────────┴──────────┐
               │    │  Modern (Windows 10/11)                     │
               │    │  SentryService (.NET 8)                     │
               │    │  └── SentryWorker / GatewayFolderWatcher   │
               │    └─────────────────────────────────────────────┘
               │    ┌─────────────────────────────────────────────┐
               │    │  Legacy (Windows 7 / WES7)                  │
               │    │  SentryLegacyService (.NET 4.8)             │
               │    │  └── LegacyServiceHost (ServiceBase+Timer)  │
               │    │  └── LegacyYaraGuard (optional YARA)        │
               │    └─────────────────────────────────────────────┘
               │              │  both use identical
               │    SentryCore (dual-target: net8 + net48)
               │    ├── VulnerabilityMatcher
               │    ├── USBMonitor
               │    ├── SupplierFileValidator
               │    ├── DriverAuditor
               │    └── HardeningAudit
               │              │
               └──────► SentryUI (WPF Dashboard — modern only)
```

Full architecture: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

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

See [`docs/CHANGELOG.md`](docs/CHANGELOG.md) for the full version history.

| Version | Date | Highlights |
|---------|------|-----------|
| v2.5-stable | 2026-06-09 | SentryShield v2.5 lockdown: full plugin architecture and security hardening |
| v2.0-dev | 2026-06-08 | "The Great Shift" to `SentryPlugin.Abstractions`, NVD WAF fixes, dual-target support |
| v1.1 | 2026-06-04 | Live CERT-In pipeline, `init_db.py`, WiX installer, 25 new tests |
| v1.0 | 2026-06-03 | Initial full build — all 4 pillars, WPF dashboard, 31 tests |

---

## License

MIT — see `LICENSE` if one applies.

---


