# SentryShield v2.7.0 — Setup Guide

> This guide covers two audiences:
> - **Developer / Intern** — Sections 1–6 (build, test, dev mode)
> - **IT Admin / End User** — Sections 7–12 (service install, DB init, deployment)

---

## Prerequisites

### Windows Machine (dev / target)
- Windows 10 / 11 (64-bit) — or Windows Server 2019+
- Administrator rights (for service install, WMI, Event Log)
- .NET 10 SDK: https://dotnet.microsoft.com/download/dotnet/10.0
- Python 3.11: https://www.python.org/downloads/
- Visual Studio 2022+ (or VS Code with C# extension)

> ⚠️ **Windows 7 Note**: .NET 10 does not support Windows 7. For Win7 HMIs, the service must be recompiled targeting .NET Framework 4.8. See `Docs/WIN7_COMPAT.md` (v2.0).

---

# DEVELOPER SETUP

## 1. Clone / Setup Repository

```cmd
git clone https://github.com/Rizzy1857/SentryShield
cd SentryShield
```

---

## 2. Python Environment

```cmd
cd SentryPython
python -m venv venv
venv\Scripts\activate

pip install yara-python pytest
```

> `schedule` is only needed if running `db_sync.py` in daemon mode (not needed in development).

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

> ✅ `VulnerabilityMatcherTests` — `IsVersionVulnerable()`, `ParseVersion()`, and `CompareVersions()` are implemented. All 40 NUnit tests should pass.

---

## 4. Run Python Tests

```cmd
cd Tests/SentryPython
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

## 5. Run as Console App (Development)

```cmd
cd SentryService
dotnet run
```

The service runs as a console app in dev mode (no service registration needed).

---

## 6. Open Admin Dashboard (Development)

```cmd
dotnet run --project SentryUI
```

---

# IT ADMIN / END USER SETUP

## 7. Get an NVD API Key (Required for Live Vulnerability Data)

SentryShield pulls real-time CVE data from NIST NVD. An API key is **free** and gives you 10x the rate limit (much faster initial sync).

1. Go to: **https://nvd.nist.gov/developers/request-an-api-key**
2. Enter your work email address and submit
3. Check your email — the key arrives within a few minutes
4. Save it somewhere safe (you'll need it in Step 9)

> Without an API key, the initial database sync will work but will take 2–3 hours.
> With an API key, it takes about 15–20 minutes.

---

## 8. Create Required Directories

```cmd
mkdir "C:\ProgramData\SentryShield"
mkdir "C:\ProgramData\SentryShield\backups"
mkdir "C:\ProgramData\SentryShield\logs"
mkdir "C:\SentryShield\Downloads"
mkdir "C:\SentryShield\rules"
mkdir "C:\SentryShield\scripts"
```

---

## 9. Initialize the Vulnerability Database

This is a **one-time step** that creates the SQLite database and populates it with live CVE data from NVD and CERT-In.

```cmd
cd SentryShield\SentryPython

:: Activate Python environment
venv\Scripts\activate

:: Set your NVD API key (from Step 7)
set NVD_API_KEY=your-api-key-here

:: Run the bootstrapper — pulls last 1 year of CVEs from NVD + CERT-In
python init_db.py --db "C:\ProgramData\SentryShield\vulnerability.db" --days-back 365
```

**What this does:**
- Creates the full database schema (7 tables)
- Pulls manufacturing-relevant CVEs from NIST NVD (keywords: SCADA, HMI, PLC, Siemens, Rockwell, Log4j, OpenSSL, and more)
- Fetches CERT-In advisories, cross-references each CVE with NVD for version ranges
- Prints a summary when done

**Expected output:**
```
===========================================================
  SentryShield Database Initialized
===========================================================
  Database     : C:\ProgramData\SentryShield\vulnerability.db
  Size         : 8.42 MB

  Vulnerabilities : 1247 total

  By source:
    NVD           1189
    CERT-IN         58

  By severity:
    CRITICAL       312
    HIGH           541
    MEDIUM         338
    LOW             56
===========================================================
```

**Populate IOC hashes:**
```cmd
python ioc_populate.py --db "C:\ProgramData\SentryShield\vulnerability.db" --curated
```

**Verify the database:**
```cmd
python cert_parser.py --db "C:\ProgramData\SentryShield\vulnerability.db" --stats
```

---

## 10. Install as Windows Service

```cmd
:: Build release binary
dotnet publish SentryService -c Release -r win-x64 --self-contained false -o C:\SentryShield\bin

:: Create service
sc create SentryShield binPath= "C:\SentryShield\bin\SentryService.exe" start= auto DisplayName= "SentryShield Security Agent"

:: Start service
sc start SentryShield

:: Verify
sc query SentryShield
```

**Copy YARA rules and Python scripts:**
```cmd
copy rules\malware.yar C:\SentryShield\rules\
xcopy SentryPython C:\SentryShield\scripts\ /E /I
```

---

## 11. Optional: Local Update Server (v2.7.0)

If your endpoints are fully air-gapped, you can run the `SentryUpdate` distribution server in your DMZ.
```cmd
:: Build and install the update server
dotnet publish SentryUpdate -c Release -r win-x64 --self-contained false -o C:\SentryShield\bin
sc create SentryUpdate binPath= "C:\SentryShield\bin\SentryUpdate.exe" start= auto DisplayName= "SentryShield Local Update Server"
sc start SentryUpdate
```

## 12. Optional: Sneakernet Syncing (v2.7.0)

For environments completely disconnected from the DMZ, operators can export and import the database manually via USB.
1. Run `SneakernetExporter.ExportToUsb("E:\")` on the source machine.
2. Run `SneakernetImporter.ImportFromUsb("E:\")` on the target machine.

---

## 13. Set Up Nightly Database Sync (Task Scheduler)

SentryShield updates its vulnerability database nightly by pulling the latest CVEs from NVD and new CERT-In advisories automatically.

**Create the scheduled task:**
```cmd
schtasks /create ^
  /tn "SentryShield DB Sync" ^
  /tr "C:\SentryShield\scripts\venv\Scripts\python.exe C:\SentryShield\scripts\db_sync.py --db C:\ProgramData\SentryShield\vulnerability.db --once" ^
  /sc DAILY ^
  /st 06:00 ^
  /ru SYSTEM ^
  /f
```

**Verify the task was created:**
```cmd
schtasks /query /tn "SentryShield DB Sync"
```

**Run the sync manually to test:**
```cmd
schtasks /run /tn "SentryShield DB Sync"
```

> The sync runs at 06:00 daily. It pulls only the previous 24h of NVD deltas and the last 7 days of CERT-In advisories, so it completes in under 5 minutes and does not affect the NVD API key rate limit.

**Set the NVD API key for the SYSTEM account (so the scheduled task can use it):**
```cmd
:: Add to system-wide environment variables
setx NVD_API_KEY "your-api-key-here" /M
```

---

## 14. Configure Trusted Suppliers

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

Files dropped into `C:\SentryShield\Downloads\<SupplierName>\` are automatically validated.

---

## 15. GPO Deployment (50 machines)

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
| DB empty / not found | Run `python init_db.py --db <path>` (see Step 9) |
| NVD sync very slow | Set `NVD_API_KEY` — without it you're rate-limited to 5 req/30s |
| CERT-In sync returns 0 advisories | CERT-In RSS may be temporarily unavailable — NVD data still loads fine |
| USB scan doesn't trigger | Verify `__InstanceCreationEvent` WMI subscription not blocked by AV |
| WMI error on software enum | Run as Administrator; check `winmgmt /verifyrepository` |

---

## Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------| 
| `NVD_API_KEY` | NVD API key — free from nvd.nist.gov (10x faster sync) | None (anonymous, rate-limited) |
| `SENTRYSHIELD_DB` | Override DB path | `C:\ProgramData\SentryShield\vulnerability.db` |
