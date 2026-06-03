# SentryShield v1.0 — Setup Guide

## Prerequisites

### Windows Machine (dev / target)
- Windows 10 / 11 (64-bit) — or Windows Server 2019+
- Administrator rights (for service install, WMI, Event Log)
- .NET 8 SDK: https://dotnet.microsoft.com/download/dotnet/8.0
- Python 3.11: https://www.python.org/downloads/
- Visual Studio 2022+ (or VS Code with C# extension)

> ⚠️ **Windows 7 Note**: .NET 8 does not support Windows 7. For Win7 HMIs, the service must be recompiled targeting .NET Framework 4.8. See `Docs/WIN7_COMPAT.md` (v2.0).

---

## 1. Clone / Setup Repository

```cmd
git clone <repo-url> SentryShield
cd SentryShield
```

---

## 2. Python Environment

```cmd
cd SentryPython
python -m venv venv
venv\Scripts\activate

pip install yara-python schedule requests pytest
```

**Verify yara-python:**
```cmd
python -c "import yara; print('YARA OK')"
```

**Compile YARA rules (sanity check):**
```cmd
python -c "import yara; yara.compile(filepaths={'rules': '../rules/malware.yar'}); print('Rules compiled OK')"
```

---

## 3. Build C# Solution

```cmd
cd ..
dotnet build SentryShield.sln
```

**Run tests:**
```cmd
dotnet test Tests/SentryCore.Tests/SentryCore.Tests.csproj --logger "console;verbosity=normal"
```

> ⚠️ `VulnerabilityMatcherTests` will **fail** until you implement `IsVersionVulnerable()`, `ParseVersion()`, and `CompareVersions()` in `SentryCore/Engines/VulnerabilityMatcher.cs`. That's intentional — it's your Week 4 deliverable.

---

## 4. Database Initialization

The database initializes automatically on first service start. To manually seed:

```cmd
cd SentryPython
venv\Scripts\activate

:: Load curated manufacturing vulnerability list (offline)
python cert_parser.py --db "C:\ProgramData\SentryShield\vulnerability.db" --curated-only

:: Populate IOC hashes
python ioc_populate.py --db "C:\ProgramData\SentryShield\vulnerability.db" --curated

:: Optional: Pull from NVD (requires internet)
python cert_parser.py --db "C:\ProgramData\SentryShield\vulnerability.db"

:: Verify DB
python cert_parser.py --db "C:\ProgramData\SentryShield\vulnerability.db" --stats
```

---

## 5. Run Python Tests

```cmd
cd Tests/SentryPython
pip install pytest
pytest tests/ -v
```

Expected output:
```
PASSED tests/test_sentryshield.py::TestYaraScanner::test_rules_compile_successfully
PASSED tests/test_sentryshield.py::TestYaraScanner::test_detects_mimikatz_string
PASSED tests/test_sentryshield.py::TestYaraScanner::test_clean_file_no_matches
...
```

---

## 6. Run as Console App (Development)

```cmd
cd SentryService
dotnet run
```

The service runs as a console app in dev mode (no service registration needed).

---

## 7. Install as Windows Service (Production)

```cmd
:: Build release binary
dotnet publish SentryService -c Release -r win-x64 --self-contained false -o C:\SentryShield\bin

:: Create service
sc create SentryShield binPath= "C:\SentryShield\bin\SentryService.exe" start= auto DisplayName= "SentryShield Security Agent"

:: Start service
sc start SentryShield

:: Verify service is running
sc query SentryShield
```

**Create required directories:**
```cmd
mkdir "C:\ProgramData\SentryShield"
mkdir "C:\ProgramData\SentryShield\backups"
mkdir "C:\ProgramData\SentryShield\logs"
mkdir "C:\SentryShield\Downloads"
mkdir "C:\SentryShield\rules"
```

**Copy YARA rules:**
```cmd
copy rules\malware.yar C:\SentryShield\rules\
```

**Copy Python scripts:**
```cmd
xcopy SentryPython C:\SentryShield\scripts\ /E /I
```

---

## 8. Open Admin Dashboard

```cmd
dotnet run --project SentryUI
```

Or run the published executable:
```cmd
C:\SentryShield\bin\SentryUI.exe
```

---

## 9. Configure Trusted Suppliers

Edit (or create) `C:\ProgramData\SentryShield\trusted_suppliers.json`:

```json
[
  {
    "supplier_name": "Siemens",
    "contact_email": "security@siemens.com",
    "expected_hashes": {
      "firmware_update_v2.3.bin": "abc123..."
    }
  },
  {
    "supplier_name": "Schneider Electric",
    "contact_email": "psirt@schneider-electric.com",
    "expected_hashes": {}
  }
]
```

---

## 10. GPO Deployment (50 machines)

Deploy via Group Policy:
```
Computer Configuration > Preferences > Windows Settings > Files
  Source:      \\FILESERVER\SentryShield\SentryShield-v1.0.msi
  Destination: C:\SentryShield\SentryShield-v1.0.msi
  Action:      Create

Computer Configuration > Software Settings > Software Installation
  Add: \\FILESERVER\SentryShield\SentryShield-v1.0.msi
```

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Service fails to start | Check Windows Event Viewer > Application for SentryShield source |
| YARA scan returns no results | Verify Python path in `appsettings.json` → `Paths.PythonExe` |
| DB not found | Run manual init: `python cert_parser.py --db <path> --curated-only` |
| USB scan doesn't trigger | Verify `__InstanceCreationEvent` WMI subscription is not blocked by AV |
| WMI error on software enum | Run as Administrator; check WMI repository with `winmgmt /verifyrepository` |

---

## Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `NVD_API_KEY` | NVD API key (higher rate limits) | None (anonymous) |
| `SENTRYSHIELD_DB` | Override DB path | `C:\ProgramData\SentryShield\vulnerability.db` |
