# SentryShield — Windows 7 / Legacy HMI Deployment Guide

## Who This Is For

This guide covers deployment of `SentryLegacyService.exe` on machines that **cannot run .NET 8**, specifically:

| Platform | Notes |
|---|---|
| Windows 7 SP1 | Standard or Embedded (WES7) |
| Windows Embedded 8.1 | Industrial / SCADA HMI variant |
| Windows Server 2008 R2 | Legacy HMI server nodes |

> **Windows 10+ / Server 2019+ users:** Use `SentryService.exe` (the standard .NET 8 build) instead. This guide does not apply.

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| .NET Framework 4.8 | 4.8.x | [Download](https://dotnet.microsoft.com/download/dotnet-framework/net48) — included in Win10 1903+, must be installed on Win7 |
| Windows 7 SP1 | SP1 (KB976932) | Required for .NET 4.8 |
| Python (optional) | 3.8–3.11 | Only needed for YARA malware scanning. See [YARA Setup](#yara-setup-optional) |

---

## Installation Steps

### 1. Copy Files

Copy the `SentryLegacyService\bin\Release\net48\` folder to the target machine:

```
C:\Program Files\SentryShield\
    SentryLegacyService.exe
    SentryCore.dll
    SentryDatabase.dll
    appsettings.json
    ... (all .dll dependencies)
```

### 2. Create the Data Directory

```cmd
mkdir C:\ProgramData\SentryShield
mkdir C:\SentryShield\Downloads
```

Copy the following from your deployment package into `C:\ProgramData\SentryShield\`:
- `trusted_suppliers.json` — supplier allow-list
- `yara_scanner.py` — YARA scan script (optional)
- `rules\` — YARA rules directory (optional)

### 3. Configure `appsettings.json`

Edit `C:\Program Files\SentryShield\appsettings.json` and adjust:

```json
{
  "SentryShield": {
    "Yara": {
      "EnableYaraScanning": false
    }
  }
}
```

Set `EnableYaraScanning` to `true` only if Python is installed (see [YARA Setup](#yara-setup-optional)).

### 4. Install the Windows Service

Open **Command Prompt as Administrator**:

```cmd
sc create SentryShield ^
   binPath= "C:\Program Files\SentryShield\SentryLegacyService.exe" ^
   DisplayName= "SentryShield ICS/OT Security Monitor" ^
   start= auto

sc description SentryShield "Monitors ICS/OT assets for vulnerabilities, driver issues, USB threats, and hardening gaps."

sc start SentryShield
```

### 5. Verify the Service Is Running

```cmd
sc query SentryShield
```

Expected output:
```
STATE              : 4  RUNNING
```

Check Windows **Event Viewer → Windows Logs → Application** and filter by source `SentryShield`. You should see:

```
SentryShield legacy service starting.
[LegacyYaraGuard] Python available: Python 3.11.x. YARA scanning enabled.
```
(or a warning that YARA is disabled if Python was not found).

---

## YARA Setup (Optional)

YARA scanning requires Python 3.x and the `yara-python` package.

### Install Python on Windows 7

1. Download **Python 3.8.x** (last version with Win7 support): [python.org/downloads](https://www.python.org/downloads/windows/)
2. Install to `C:\Python38\`
3. Install `yara-python`:
   ```cmd
   C:\Python38\python.exe -m pip install yara-python
   ```

### Configure SentryShield

Edit `appsettings.json`:

```json
"Yara": {
  "EnableYaraScanning": true,
  "PythonExe": "C:\\Python38\\python.exe"
}
```

### Graceful Fallback

If YARA scanning fails at any point (Python crash, rule parse error, timeout), SentryShield **does not stop**. It logs a warning to Event Log and continues with:
- ✅ IOC hash lookup (MalwareBazaar database)
- ✅ Shannon entropy analysis
- ✅ Magic byte / extension mismatch detection

---

## Updating the Service

```cmd
sc stop SentryShield
:: Copy new binaries over the existing ones
sc start SentryShield
```

---

## Uninstall

```cmd
sc stop SentryShield
sc delete SentryShield
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `sc start` fails immediately | .NET 4.8 not installed | Install .NET Framework 4.8 redistributable |
| No Event Log entries | Event Log source not registered | Run installer once as Administrator |
| `YARA scanning will be skipped` in Event Log | Python not found at configured path | Set `EnableYaraScanning: false` or fix `PythonExe` path |
| `Vulnerability scan failed` in Event Log | SQLite DB path not writable | Check `C:\ProgramData\SentryShield\` directory permissions |
