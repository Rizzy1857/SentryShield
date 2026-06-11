# SentryShield Strategic Roadmap

This document outlines the strategic vision and upcoming milestones for the SentryShield platform as it evolves from a standalone host-based agent into a distributed, enterprise-grade Industrial Control Systems (ICS) security solution.

---

## ✅ Phase 1: Core Foundation (v1.x)
*Status: Complete*

**Goal:** Establish the baseline database, Python intelligence gathering, and UI dashboard.

- **v1.0:** Base SQLite schema (`ioc.db`, `vulnerability.db`) and foundational C# models.
- **v1.1:** Python intelligence pipeline (`cert_in_parser.py`, `init_db.py`) for live CVE syncing from NIST NVD and CERT-In.
- **v1.2:** WPF UI Engine Integration. "Scan" and "Sync" dashboard buttons wired directly into native C# backend engines. Smart build automation (`build_and_run.ps1`) for .NET 4.8 and .NET 10.0 cross-compilation.

---

## ✅ Phase 2: Zero Trust Architecture & Hardening (v2.0 - v2.5)
*Status: Complete*

**Goal:** Pivot from a monolithic scanner to a dynamic, modular Zero Trust security platform hardened against advanced offline tampering.

- **v2.0:** The Great Shift to Dynamic Plugin Architecture (`SentryPlugin.Abstractions`). Standalone DLLs for Vulnerability and USB engines. NIST API self-healing fallback logic.
- **v2.1:** IDS (Intrusion Detection System) integration (`SentryPlugin.IDS`) monitoring egress traffic and packet floods. Thread safety and Deadlock prevention in plugin execution.
- **v2.5:** Final Security Lockdown. 
  - Deep System Integrity (`FirmwarePlugin`) via raw kernel API hooks.
  - Auto-Block-Then-Scan USB zero-trust enforcement.
  - Pen-Tester Threat Model Defenses (Authenticode signatures, Gateway TOCTOU fixes, DB checksums).

---

## 🛠️ Phase 2.5: Tech Debt & Local Distribution (v2.6 - v2.7)
*Status: In Progress*

**v2.6 — Tech Debt & UI Polish**
*Focus: Stabilizing the v2.5 codebase and resolving documented handover debt.*
* **C# 12 Compliance:** Resolve remaining nullable reference type warnings within `IDSPluginTests.cs` and `VulnerabilityMatcher.cs` for strict compiler compliance.
* **Framework Alignment:** Ensure `SentryCore.csproj` targets `net10.0-windows` directly to prevent `NU1702` warnings.
* **UI Telemetry:** Update the WPF Settings view to dynamically display all actively loaded plugins alongside their respective versions.
* **Hardware Surfacing:** Visualize the generated physical firmware SMBIOS hash directly on the main UI dashboard.

**v2.7 — Air-Gap Bridging & Local Distribution**
*Focus: Bridging the gap between standalone nodes and a fully connected mesh.*
* **Sneakernet Syncing:** Build an automated export capability that allows operators to dump the local threat mesh database to a secure USB, walk it to a disconnected subnet, and ingest it safely.
* **Local Update Server:** Create a localized update distribution server (WSUS-style) inside the factory DMZ that isolated endpoints can poll for the latest YARA rules and CVE databases.

---

## 🚀 Phase 3: Distributed Intelligence & Proactive Defense (v3.0 - v3.9)
*Status: Planned*

**v3.0 — Distributed Intelligence (Resilient Star-Mesh)**
*Focus: Enabling offline peer-to-peer communication with Star Node authority.*
* **Star-Mesh Failover Architecture:** Establish a primary Star Node for intelligence distribution. Distribute cached peer routing tables to all endpoints during active connection to prepare for network segmentation.
* **Node Fallback & Local Discovery:** If the Star Node heartbeat fails, automatically enter fallback mode. Query cached peers first, then dynamically fallback to local mDNS/UDP broadcast to locate surviving neighbors.
* **Cryptographic & Monotonic Validation:** Reconcile intelligence using Monotonic Sequence Numbers (e.g., `Intelligence_v1042`) instead of timestamps to prevent clock drift. Enforce strict cryptographic signature validation on all peer-distributed updates.
* **PKI & mTLS Infrastructure:** Design a robust Public Key Infrastructure (PKI) to enforce mutually authenticated (mTLS) TLS connections across the entire Star-Mesh.

**v3.1 — Mesh Resilience & Alerting**
*Focus: Stabilizing the decentralized threat-sharing architecture against thundering herds and split brains.*
* **Star Health Monitoring:** Continuously monitor Star Node heartbeats. Instantly propagate high-priority system events and UI notifications upon detection of unavailability.
* **Operator Awareness & Alerting:** Prominently display Star Node health, failover activation state, active fallback peer source, and the active Intelligence Sequence Number on the WPF Dashboard and CMC.
* **Automatic Recovery (Thundering Herd Protection):** Periodically attempt Star Node reconnection using an exponential backoff algorithm with randomized jitter to prevent DDoS spikes upon network restoration.
* **State Resolution:** Implement Conflict-free Replicated Data Types (CRDTs) to handle split-brain database sync conflicts when merging data from prolonged network outages.

**v3.2 — Advanced ICS Protocol Parsing**
*Focus: Moving beyond TCP/IP layer blocking.*
* **Deep Packet Inspection (DPI):** Expand `SentryPlugin.IDS` to natively parse Modbus TCP, DNP3, and OPC UA protocols.
* **Command Anomaly Detection:** Detect and alert on unauthorized PLC write commands or firmware flash sequences bypassing engineering workstations.

**v3.3 — CISA ICS-CERT & Global Feeds**
*Focus: Expanding the intelligence graph.*
* **ICS-CERT Integration:** Implement custom parsers for proprietary PLC vulnerability feeds where NVD coverage is thin (e.g., Toyopuc, JTEKT, Siemens).

**v3.4 — Network Anomaly Detection**
*Focus: Establishing host baselines.*
* **Statistical Traffic Baselines:** Maintain a rolling 24-hour baseline of normal traffic patterns per endpoint.
* **Deviation Alerting:** Alert when packet throughput deviates more than 2 standard deviations from the established baseline, signaling potential lateral movement or scanning.

**v3.5 — Active Mitigation & Memory Scanning**
*Focus: Transitioning from reactive logging to proactive system intervention.*
* **Active Remediation:** Expand `RemediationPlugin` capabilities to forcefully suspend or terminate executing rogue processes detected by the system.
* **In-Memory YARA:** Implement live process heap scanning using `ReadProcessMemory` API calls to hunt for reflective DLL injections, fileless malware, and packed payloads.
* **Automated Network Isolation:** Develop dynamic Windows Defender Firewall injection to instantly block lateral movement if a critical network worm is detected.

**v3.6 — EDR Telemetry & API Hooking**
*Focus: Catching advanced evasive malware in-flight.*
* **Heuristic Engine:** Implement deep API hooking for `CreateRemoteThread`, `WriteProcessMemory`, and `VirtualAllocEx` to detect and block memory injection heuristically.
* **Process Lineage:** Track parent-child process execution trees to identify LOLBins (Living Off The Land Binaries) like unauthorized PowerShell invocations from Office apps.

**v3.7 — Automated Rollback & Safe State**
*Focus: Resiliency after a partial breach.*
* **VSS Integration:** Hook into Windows Volume Shadow Copy Service for automatic critical file rollback post-remediation.
* **PLC Safe-State Signaling:** Implement the ability to broadcast an emergency stop or safe-state command to critical PLCs upon detection of a systemic gateway breach.

**v3.8 — High-Performance Engine Upgrades (Rust Hybrid)**
*Focus: Injecting Rust strategically for speed and system-level safety without abandoning the C# ecosystem.*
* **Network IDS Rewrite:** Rebuild the network packet processing engine in Rust to safely handle millions of packets per minute without risking Garbage Collector (GC) micro-stalls.
* **Firmware Safety:** Migrate low-level SMBIOS/firmware validation API calls into a Rust-compiled module to leverage guaranteed memory safety boundaries.
* **Rigorous FFI Boundaries:** Implement a strict Foreign Function Interface (FFI) layer that catches any unhandled Rust errors (panics) and marshals them back to the C# worker as structured JSON.
* **Authenticode Pipeline:** Ensure the CI/CD pipeline runs `signtool.exe` against the new Rust native DLLs using the enterprise EV certificate.

**v3.9 — Rust Hybrid Finalization**
*Focus: Optimizing memory limits.*
* **YARA Offloading:** Expand the Rust FFI to include the entire YARA engine memory-scanning pipeline, drastically reducing GC memory pressure on the .NET runtime during large fleet scans.

---

## 🏢 Phase 4: Enterprise Command, Control & OS Integration (v4.0 - v4.5)
*Status: Horizon*

**v4.0 — Enterprise Command & Control**
*Focus: Centralized visibility and SOC integration.*
* **Centralized Management Console (CMC):** Deploy a localized React/Next.js web dashboard for Shift Supervisors and SOC analysts to visualize the health of the entire SentryShield mesh.
* **Enterprise SIEM Integration:** Build native telemetry forwarding to route threat intelligence in Common Event Format (CEF) and Syslog to central platforms like Splunk, QRadar, or Sentinel.
* **Remote Policy Enforcement:** Enable the CMC to push unified configurations, updated YARA rules, and trusted supplier manifest updates down to all connected mesh nodes.
* **Hardware RBAC:** Integrate Role-Based Access Control requiring physical, cryptographically signed smart-cards or YubiKeys for an operator to override gateway BLOCK decisions.

**v4.1 — Enterprise Mesh Federated Sync**
*Focus: Multi-facility coordination.*
* **Hub-and-Spoke Topology:** Implement federated sync capabilities to bridge multiple isolated factory floors via securely segmented DMZ proxies.

**v4.2 — Cloud Threat Intel Integration**
*Focus: Enterprise-wide proactive threat hunting.*
* **STIX/TAXII Ingestion:** Enable the CMC to pull external STIX/TAXII threat feeds and push them as compiled intelligence directly to air-gapped endpoints.

**v4.3 — Automated Playbooks (SOAR)**
*Focus: Automated SOC response.*
* **Custom Playbooks:** Allow security engineers to write Lua or Python-based response playbooks triggered by specific CMC alerts, drastically reducing incident mean-time-to-response (MTTR).

**v4.4 — Identity & Zero Trust Network Access (ZTNA)**
*Focus: Enforcing micro-segmentation.*
* **Cryptographic Identity:** Enforce OT network micro-segmentation based on cryptographic identity rather than legacy IP/MAC filtering, deeply integrating with SentryShield's endpoint mesh.

**v4.5 — Deep System Integration (Horizon)**
*Focus: Replacing user-space hooks with true OS-level interception.*
* **Kernel-Level Driver:** Replace current WMI and user-land registry hooks with a signed Windows Mini-Filter driver, achieving unbypassable, ring-0 file system interception and zero-trust USB monitoring.
