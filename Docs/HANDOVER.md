# SentryShield — Handover Document

## Current Status (v2.5)

SentryShield has reached its `v2.5` milestone. The core infrastructure is complete, heavily tested, and actively functioning in an offline-first capacity. 
The system is divided into four pillars: Vulnerability Matching, USB Threat Detection, Supplier File Gateway, and Driver/Hardening Audits. All critical security mechanisms (Authenticode validation, YARA integration, TOCTOU mitigation) are in place.

## What Is Done (Production-Ready)
- **Plugin Architecture:** `SentryPlugin.Abstractions` is frozen and solid.
- **Security Hardening:** 
  - Authenticode signatures required for all dynamically loaded plugins.
  - Gateway TOCTOU fixes (pre and post-validation hashing).
  - Python IPC argument sanitization to prevent command injection.
  - Database schema integrity checks on boot.
- **Vulnerability Sync Pipeline:** Both NVD and CERT-In parsers are active, with fallback logic for CERT-In's offline states and proper NVD rate-limiting (HTTP 429) backoffs.
- **UI:** The WPF dashboard is fully operational with live, color-coded terminal synchronization logs.

## Known Limitations & Remaining Work
For the team taking over `v3.0` and beyond, be aware of the following:

1. **Distributed Syncing (Phase 3):** The `MeshPlugin` (Gossip protocol) is explicitly NOT built. Implementing mTLS mutual authentication in an air-gapped factory will require significant PKI infrastructure design.
2. **Nullable Warnings:** There are a few remaining nullable reference type warnings (e.g., in `IDSPluginTests.cs` and `VulnerabilityMatcher.cs`) that should be cleaned up for strict C# 12 compliance.
3. **Target Frameworks:** `SentryCore.csproj` currently targets `net8.0-windows`. If the testing infrastructure entirely moves to `net10.0-windows`, ensure `SentryCore.csproj` is updated to reflect this to avoid NU1702 warnings.
4. **UI Refinements:** 
   - Display the loaded plugins and their versions in the Settings view.
   - Surface the `SMBIOS` hash directly on the UI dashboard (it currently logs in the background but is not visualized).

## Getting Help
If the deployment breaks on a factory node:
1. **Check the Event Log:** SentryShield logs to the standard Windows Event Viewer (Event ID 2001 for USB Threats).
2. **Validate the DB Path:** Ensure `appsettings.json` points to the correctly initialized `vulnerability.db`.
3. **Verify Python Path:** The YARA engine falls back silently if Python is missing. Ensure Python 3.11 is installed in the path defined by `LegacyConfig.cs`.

*This document marks the official handover boundary of the MVP internship project. Godspeed.*
