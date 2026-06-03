-- ===========================================================================
-- SentryShield v1.0 Database Schema
-- SQLite 3 — offline-first, no network required
-- Run once on first startup via DatabaseInitializer.cs
-- ===========================================================================

PRAGMA journal_mode=WAL;   -- Write-Ahead Logging for better concurrency
PRAGMA foreign_keys=ON;

-- ---------------------------------------------------------------------------
-- Vulnerability database (populated from NVD / curated JSON)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id               TEXT PRIMARY KEY,          -- CVE-YYYY-NNNNN or MFG-VUL-NNN
    product_name     TEXT NOT NULL,
    affected_versions TEXT,                     -- JSON: [{min, max, include_min, include_max}]
    cvss_score       REAL DEFAULT 0,
    severity         TEXT DEFAULT 'MEDIUM',     -- CRITICAL/HIGH/MEDIUM/LOW (fallback if no CVSS)
    description      TEXT,
    remediation      TEXT,
    source           TEXT DEFAULT 'CURATED',    -- 'NVD', 'CERT-IN', 'CURATED'
    first_seen       DATE,
    last_updated     DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ---------------------------------------------------------------------------
-- IOC database (known malware file hashes)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS iocs (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    file_hash        TEXT UNIQUE NOT NULL,      -- SHA-256 hex string
    malware_name     TEXT,
    malware_family   TEXT,
    confidence       INTEGER DEFAULT 100,       -- 0-100
    source           TEXT,                      -- 'VirusTotal', 'MISP', 'CURATED'
    detection_date   DATE DEFAULT (date('now'))
);

-- ---------------------------------------------------------------------------
-- Installed software inventory (snapshot per scan)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS software_inventory (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    machine_name     TEXT NOT NULL,
    software_name    TEXT NOT NULL,
    version          TEXT,
    publisher        TEXT,
    install_path     TEXT,
    scan_timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_vulnerable    INTEGER DEFAULT 0          -- 0=false, 1=true (BOOLEAN)
);

-- ---------------------------------------------------------------------------
-- Scan history (one row per scan run)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scan_results (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type        TEXT NOT NULL,             -- 'vulnerability', 'usb', 'driver', 'hardening'
    scan_timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP,
    findings_count   INTEGER DEFAULT 0,
    critical_count   INTEGER DEFAULT 0,
    high_count       INTEGER DEFAULT 0,
    medium_count     INTEGER DEFAULT 0,
    low_count        INTEGER DEFAULT 0,
    scan_duration_seconds INTEGER DEFAULT 0
);

-- ---------------------------------------------------------------------------
-- Findings (individual detections — the main output table)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS findings (
    id               TEXT PRIMARY KEY,          -- UUID
    machine_name     TEXT NOT NULL,
    finding_type     TEXT NOT NULL,             -- 'vulnerability', 'usb_threat', 'driver', 'hardening'
    severity         TEXT NOT NULL,             -- CRITICAL/HIGH/MEDIUM/LOW
    title            TEXT NOT NULL,
    description      TEXT,
    affected_component TEXT,
    remediation      TEXT,
    detection_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    acknowledged     INTEGER DEFAULT 0,         -- 0=false, 1=true
    notes            TEXT
);

-- ---------------------------------------------------------------------------
-- Gateway files (supplier file validation log)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS gateway_files (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    filename         TEXT NOT NULL,
    supplier_name    TEXT NOT NULL,
    file_hash        TEXT,
    file_size        INTEGER DEFAULT 0,
    received_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    validation_status TEXT DEFAULT 'PENDING',   -- ALLOWED/BLOCKED/PENDING/WARN
    block_reason     TEXT,
    validation_timestamp DATETIME,
    transferred_to_ot INTEGER DEFAULT 0         -- 0=false, 1=true
);

-- ---------------------------------------------------------------------------
-- Trusted supplier manifest (who can drop files in gateway folder)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS trusted_suppliers (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    supplier_name    TEXT UNIQUE NOT NULL,
    contact_email    TEXT,
    added_date       DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_active        INTEGER DEFAULT 1          -- 0=false, 1=true
);

-- ---------------------------------------------------------------------------
-- Indexes for query performance
-- ---------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_vuln_product    ON vulnerabilities(product_name);
CREATE INDEX IF NOT EXISTS idx_vuln_severity   ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_ioc_hash        ON iocs(file_hash);
CREATE INDEX IF NOT EXISTS idx_findings_ts     ON findings(detection_timestamp);
CREATE INDEX IF NOT EXISTS idx_findings_sev    ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_ack    ON findings(acknowledged);
CREATE INDEX IF NOT EXISTS idx_gateway_status  ON gateway_files(validation_status);
CREATE INDEX IF NOT EXISTS idx_gateway_supplier ON gateway_files(supplier_name);
CREATE INDEX IF NOT EXISTS idx_sw_machine      ON software_inventory(machine_name);

-- ---------------------------------------------------------------------------
-- Schema version tracking
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO schema_version (version) VALUES (1);
