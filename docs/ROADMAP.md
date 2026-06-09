# SentryShield Roadmap

This document outlines the strategic vision and upcoming milestones for the SentryShield platform as it evolves from a standalone host-based agent into a distributed, enterprise-grade Industrial Control Systems (ICS) security solution.

---

## ✅ Phase 1: Core Foundation (v1.x)
*Status: Complete*

**Goal:** Establish the baseline database, Python intelligence gathering, and UI dashboard.

- **v1.0:** Base SQLite schema (`ioc.db`, `vulnerability.db`) and foundational C# models.
- **v1.1:** Python intelligence pipeline (`cert_in_parser.py`, `init_db.py`) for live CVE syncing from NIST NVD and CERT-In.
- **v1.2:** WPF UI Engine Integration. "Scan" and "Sync" dashboard buttons wired directly into native C# backend engines. Smart build automation (`build_and_run.ps1`) for .NET 4.8 and .NET 10.0 cross-compilation.

---

## ✅ Phase 2: Zero Trust Architecture & Hardening (v2.x)
*Status: Complete*

**Goal:** Pivot from a monolithic scanner to a dynamic, modular Zero Trust security platform hardened against advanced offline tampering.

- **v2.0:** The Great Shift to Dynamic Plugin Architecture (`SentryPlugin.Abstractions`). Standalone DLLs for Vulnerability and USB engines. NIST API self-healing fallback logic.
- **v2.1:** IDS (Intrusion Detection System) integration (`SentryPlugin.IDS`) monitoring egress traffic and packet floods. Thread safety and Deadlock prevention in plugin execution.
- **v2.5:** Final Security Lockdown. 
  - Deep System Integrity (`FirmwarePlugin`) via raw kernel API hooks.
  - Auto-Block-Then-Scan USB zero-trust enforcement (Registry Write-Protect, ACL execution deny, Native Toasts).
  - Pen-Tester Threat Model Defenses: Strict Authenticode plugin signatures, Gateway TOCTOU dual-hashing, Python command injection fixes, DB checksum validation, and YARA folder ACL lockdowns.

---

## 🚀 Phase 3: Distributed Intelligence (v3.0)
*Status: Up Next*

**Goal:** Enable SentryShield agents operating on isolated factory floors to communicate and share threat intelligence without internet access.

- **MeshPlugin (Offline P2P Sync):**
  - Implement a lightweight, decentralized peer-to-peer mesh network over local LAN/WLAN.
  - Automatic discovery of adjacent SentryShield nodes using mDNS/UDP broadcast.
  - Secure, mutually authenticated (mTLS) sync of newly discovered IOC hashes and Yara alerts.
- **Gossip Protocol:**
  - If Node A detects a malicious USB, it gossips the hash to Node B and Node C. If the same USB is inserted into Node B, it is instantly blocked based on Node A's findings.
- **Automated Air-Gap Bridging:**
  - "Sneakernet" sync: Allow authorized operators to export the threat mesh DB to a secure USB, walk it to a completely disconnected subnet, and ingest it to update that subnet's mesh.
- **Expanded Data Sources:**
  - Integrate a CISA ICS-CERT parser to capture Toyopuc (JTEKT) and other proprietary PLC vulnerabilities where NVD coverage is thin.

---

## 🛡️ Phase 4: Active Mitigation & Memory Scanning (v3.5)
*Status: Planned*

**Goal:** Shift from reactive logging and file-blocking to proactive, deep-system intervention.

- **Active Process Remediation:**
  - Expand the `RemediationPlugin` to forcibly suspend or terminate rogue processes detected by the engine.
- **In-Memory YARA Scanning:**
  - Utilize Windows API (`ReadProcessMemory`) to allow YARA to scan live process heaps for fileless malware, reflective DLL injections, and packed payloads.
- **Automated Network Isolation:**
  - Dynamically inject Windows Defender Firewall block rules to isolate a host if a `CRITICAL` network-worm threat is detected, preventing lateral movement across the OT network.

---

## 🏢 Phase 5: Enterprise Command & Control (v4.0)
*Status: Planned*

**Goal:** Provide centralized visibility and management for security operations centers (SOC).

- **Centralized Management Console (CMC):**
  - A dedicated web dashboard (React/Next.js) hosted on a secure internal server to visualize the health and threat status of the entire SentryShield mesh.
- **SIEM Integration:**
  - Native forwarding of threat telemetry in CEF (Common Event Format) and Syslog to enterprise SIEMs like Splunk, QRadar, or Microsoft Sentinel.
- **Remote Policy Management:**
  - Push updated YARA rules, trusted supplier manifests, and configuration profiles from the CMC down to the mesh nodes.
- **Role-Based Access Control (RBAC):**
  - Require cryptographically signed smart-cards or YubiKeys for operators to override `BLOCK` decisions at the gateway.
