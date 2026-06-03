# SentryShield

SentryShield is an offline-first security monitoring platform for ICS/OT and manufacturing environments. It combines a Windows service, a WPF dashboard, a shared C# core, a SQLite-backed database layer, and Python helpers for YARA scanning, IOC population, and database sync.

## What’s included

- `SentryService` - Windows service that orchestrates scans and gateway monitoring
- `SentryCore` - Shared detection engines for vulnerabilities, USB activity, drivers, hardening, and supplier file validation
- `SentryDatabase` - SQLite-backed persistence and database initialization
- `SentryUI` - WPF dashboard for review and administration
- `SentryPython` - Python utilities for certificate parsing, YARA scanning, IOC population, and sync tasks
- `Tests` - Automated tests for core logic and Python helpers

## Repository layout

```text
SentryShield.sln
Docs/
Plugins/
rules/
SentryCore/
SentryDatabase/
SentryPython/
SentryService/
SentryUI/
Tests/
```

## Prerequisites

- Windows 10/11 or Windows Server 2019+
- .NET 8 SDK
- Python 3.11
- Administrator rights for service install, WMI, and Event Log access

## Setup

See `Docs/SETUP.md` for the full installation and deployment guide.

Quick start:

```cmd
git clone <repo-url> SentryShield
cd SentryShield

cd SentryPython
python -m venv venv
venv\Scripts\activate
pip install yara-python schedule requests pytest

cd ..
dotnet build SentryShield.sln
```

## Running locally

Run the service in console mode during development:

```cmd
cd SentryService
dotnet run
```

Open the dashboard:

```cmd
dotnet run --project SentryUI
```

## Testing

```cmd
dotnet test Tests/SentryCore.Tests/SentryCore.Tests.csproj --logger "console;verbosity=normal"
cd Tests/SentryPython
pytest tests/ -v
```

## Architecture

A full architecture overview is available in `Docs/ARCHITECTURE.md`.

In short:

- `SentryService` coordinates scans and gateway validation
- `SentryCore` performs detection and audit logic
- `SentryDatabase` stores findings, vulnerabilities, IOC data, and scan history
- `SentryUI` provides the admin dashboard
- `SentryPython` handles subprocess-based scanning and sync workflows

## Deployment notes

- The service is designed for Windows service deployment
- Python scripts are invoked as subprocesses and return JSON through stdout
- SQLite is used for local/offline persistence
- YARA rules live in `rules/`

## License

Add your project license here if one applies.
