# SentryShield — Handover Document

## Current Status (v2.7.0)

SentryShield has reached its `v2.7.0` milestone. The core infrastructure is complete, heavily tested, and actively functioning in an offline-first capacity. 
The system is divided into four pillars: Vulnerability Matching, USB Threat Detection, Supplier File Gateway, and Driver/Hardening Audits. All critical security mechanisms (Authenticode validation, YARA integration, TOCTOU mitigation) are in place.

## What Is Done (Production-Ready)
- **Plugin Architecture:** `SentryPlugin.Abstractions` is frozen and solid.
- **Security Hardening:** 
  - Authenticode signatures required for all dynamically loaded plugins.
  - Gateway TOCTOU fixes (pre and post-validation hashing).
  - Python IPC argument sanitization to prevent command injection.
  - Database schema integrity checks on boot.
  - Strict C# 12 nullability compliance across all codebases.
- **Vulnerability Sync Pipeline:** Both NVD and CERT-In parsers are active, with fallback logic for CERT-In's offline states and proper NVD rate-limiting (HTTP 429) backoffs.
- **Air-Gapped Ops:** Fully implemented Sneakernet Syncing (`SneakernetExporter` / `SneakernetImporter`) and a Local Update Server (`SentryUpdate`).
- **UI:** The WPF dashboard is fully operational with live, color-coded terminal synchronization logs, SMBIOS hardware hash visualization, and dynamic plugin telemetry.

## Known Limitations & Remaining Work
For the team taking over `v3.0` and beyond, be aware of the following:

1. **Distributed Syncing (Phase 3):** The **Hub-and-Spoke (UDP Push)** architecture is partially realized. While `SentryUpdate` and `UpdatePoller` provide local polling, the lightweight UDP broadcast push mechanisms and Monotonic Sequence Validations for completely decoupled environments still need full implementation.
2. **Stealth Hardware Inventory (v2.8):** A new `IDetectionPlugin` must be developed to silently parse local PLC project files (`.ap16`, `.acd`) on engineering workstations for asset discovery without network scanning.
3. **Contextual Risk Scoring (v2.9):** The SQLite schema should be updated to include an "Asset Criticality" tag, allowing the `VulnerabilityMatcher` to dynamically adjust CVSS severity scores based on asset role.
4. **Target Frameworks:** The solution has fully migrated to `net10.0-windows` (from `.NET 8`). Ensure the testing infrastructure remains aligned to avoid NU1702 warnings.

## Getting Help
If the deployment breaks on a factory node:
1. **Check the Event Log:** SentryShield logs to the standard Windows Event Viewer (Event ID 2001 for USB Threats).
2. **Validate the DB Path:** Ensure `appsettings.json` points to the correctly initialized `vulnerability.db`.
3. **Verify Python Path:** The YARA engine falls back silently if Python is missing. Ensure Python 3.11 is installed in the path defined by `LegacyConfig.cs`.

*This document marks the official handover boundary of the MVP internship project. Godspeed.*
