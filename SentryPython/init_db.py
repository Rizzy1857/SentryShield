"""
SentryShield v1.0 — Database Initializer & Live Feed Bootstrapper (init_db.py)

ONE-SHOT SCRIPT: Creates the SQLite database from scratch and populates it
with LIVE vulnerability data from:
  1. NIST NVD API   — manufacturing-relevant CVEs (SCADA, HMI, PLC, Siemens, etc.)
  2. CERT-In        — India CERT advisories (live RSS + advisory scraping)

No synthetic/curated data is loaded unless --include-curated is passed.

Usage:
    python init_db.py --db C:\\ProgramData\\SentryShield\\vulnerability.db
    python init_db.py --db vulnerability.db --days-back 90
    python init_db.py --db vulnerability.db --days-back 365 --nvd-key YOUR_KEY

Environment:
    NVD_API_KEY  — Optional. Free from https://nvd.nist.gov/developers/request-an-api-key
                   Without key: 5 req/30s  (slow but works)
                   With key:    50 req/30s (10x faster)

What this script does:
    1. Creates vulnerability.db with the full SentryShield schema
    2. Pulls NVD CVEs for 16 manufacturing keywords
    3. Pulls CERT-In advisories for the last N days
    4. Prints a summary of what was loaded
    5. Optionally compresses the DB for offline distribution

After running this, the Windows service and VulnerabilityMatcher.cs can
immediately scan installed software against the live DB.
"""

import argparse
import json
import logging
import os
import sqlite3
import sys
import time
from datetime import datetime
from pathlib import Path

class ColorFormatter(logging.Formatter):
    def format(self, record):
        msg = super().format(record)
        if record.name == "cert_parser" or "NVD" in msg:
            return f"\033[96m{msg}\033[0m" # Cyan
        elif record.name == "cert_in" or "CERT-In" in msg:
            return f"\033[93m{msg}\033[0m" # Yellow
        return msg

logger = logging.getLogger()
logger.setLevel(logging.INFO)
if logger.hasHandlers():
    logger.handlers.clear()
handler = logging.StreamHandler(sys.stderr)
handler.setFormatter(ColorFormatter("[%(asctime)s] %(levelname)s %(message)s", "%Y-%m-%d %H:%M:%S"))
logger.addHandler(handler)
log = logging.getLogger("init_db")

# Full SQLite schema — mirrors SentryDatabase/Schema/init.sql exactly
SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- ── Vulnerability database ──────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id                  TEXT    PRIMARY KEY,         -- CVE-YYYY-NNNNN or CIVN-YYYY-NNNNN
    product_name        TEXT    NOT NULL,
    affected_versions   TEXT    DEFAULT '[]',        -- JSON: [{min, max, include_min, include_max}]
    cvss_score          REAL    DEFAULT 0.0,
    severity            TEXT    DEFAULT 'MEDIUM',    -- CRITICAL | HIGH | MEDIUM | LOW
    description         TEXT    DEFAULT '',
    remediation         TEXT    DEFAULT '',
    source              TEXT    DEFAULT 'NVD',       -- NVD | CERT-IN | CURATED
    first_seen          DATE,
    last_updated        DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_vuln_product  ON vulnerabilities (product_name COLLATE NOCASE);
CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities (severity);
CREATE INDEX IF NOT EXISTS idx_vuln_source   ON vulnerabilities (source);
CREATE INDEX IF NOT EXISTS idx_vuln_cvss     ON vulnerabilities (cvss_score DESC);

-- ── IOC (malware hash) database ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS iocs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    file_hash       TEXT    UNIQUE NOT NULL,    -- SHA-256 hex
    malware_name    TEXT    NOT NULL,
    malware_family  TEXT    DEFAULT '',
    confidence      INTEGER DEFAULT 100,        -- 0-100
    source          TEXT    DEFAULT 'CURATED',
    detection_date  DATE
);

CREATE INDEX IF NOT EXISTS idx_ioc_hash ON iocs (file_hash);

-- ── Software inventory (per-scan snapshot) ───────────────────────────────────
CREATE TABLE IF NOT EXISTS software_inventory (
    id               INTEGER  PRIMARY KEY AUTOINCREMENT,
    machine_name     TEXT     NOT NULL,
    software_name    TEXT     NOT NULL,
    version          TEXT     DEFAULT '',
    publisher        TEXT     DEFAULT '',
    install_path     TEXT     DEFAULT '',
    install_date     TEXT     DEFAULT '',
    is_vulnerable    BOOLEAN  DEFAULT FALSE,
    scan_timestamp   DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_sw_machine   ON software_inventory (machine_name);
CREATE INDEX IF NOT EXISTS idx_sw_name_ver  ON software_inventory (software_name, version);

-- ── Scan history ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_results (
    id               INTEGER  PRIMARY KEY AUTOINCREMENT,
    scan_type        TEXT     NOT NULL,   -- 'vulnerability' | 'usb' | 'gateway' | 'hardening'
    machine_name     TEXT     NOT NULL,
    start_time       DATETIME NOT NULL,
    end_time         DATETIME,
    findings_count   INTEGER  DEFAULT 0,
    critical_count   INTEGER  DEFAULT 0,
    high_count       INTEGER  DEFAULT 0,
    medium_count     INTEGER  DEFAULT 0,
    low_count        INTEGER  DEFAULT 0,
    duration_seconds INTEGER  DEFAULT 0,
    success          BOOLEAN  DEFAULT TRUE,
    error_message    TEXT
);

-- ── Findings (all detections) ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS findings (
    id                   TEXT     PRIMARY KEY,   -- UUID
    machine_name         TEXT     NOT NULL,
    finding_type         TEXT     NOT NULL,      -- 'vulnerability' | 'usb_threat' | 'driver' | 'hardening'
    severity             TEXT     NOT NULL,
    title                TEXT     NOT NULL,
    description          TEXT     DEFAULT '',
    affected_component   TEXT     DEFAULT '',
    remediation          TEXT     DEFAULT '',
    detection_timestamp  DATETIME DEFAULT CURRENT_TIMESTAMP,
    acknowledged         BOOLEAN  DEFAULT FALSE,
    notes                TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_machine   ON findings (machine_name);
CREATE INDEX IF NOT EXISTS idx_findings_severity  ON findings (severity);
CREATE INDEX IF NOT EXISTS idx_findings_type      ON findings (finding_type);
CREATE INDEX IF NOT EXISTS idx_findings_ack       ON findings (acknowledged);

-- ── Gateway file validation log ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS gateway_files (
    id                    INTEGER  PRIMARY KEY AUTOINCREMENT,
    filename              TEXT     NOT NULL,
    supplier_name         TEXT     DEFAULT '',
    file_hash             TEXT     DEFAULT '',
    file_size             INTEGER  DEFAULT 0,
    received_timestamp    DATETIME DEFAULT CURRENT_TIMESTAMP,
    validation_status     TEXT     DEFAULT 'PENDING',   -- ALLOWED | BLOCK | WARN | PENDING
    block_reason          TEXT,
    validation_timestamp  DATETIME,
    transferred_to_ot     BOOLEAN  DEFAULT FALSE
);

-- ── Trusted supplier whitelist ────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS trusted_suppliers (
    id              INTEGER  PRIMARY KEY AUTOINCREMENT,
    supplier_name   TEXT     UNIQUE NOT NULL,
    contact_email   TEXT     DEFAULT '',
    is_active       BOOLEAN  DEFAULT TRUE,
    added_date      DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ── Schema version tracking ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS schema_version (
    version    INTEGER PRIMARY KEY,
    applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO schema_version (version)
VALUES (1);
"""


def create_schema(db_path: str) -> None:
    """Create (or verify) the full SentryShield schema."""
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(SCHEMA_SQL)
        conn.commit()
        log.info("Schema created/verified: %s", db_path)
    finally:
        conn.close()


def run_nvd_sync(db_path: str, days_back: int, nvd_key: str = "") -> int:
    """Pull manufacturing-relevant CVEs from NVD API."""
    if nvd_key:
        os.environ["NVD_API_KEY"] = nvd_key

    # Import here so NVD_API_KEY env var is set first
    script_dir = Path(__file__).parent
    sys.path.insert(0, str(script_dir))
    from cert_parser import NVDFeedParser, MANUFACTURING_KEYWORDS

    parser = NVDFeedParser(db_path)
    try:
        log.info("Starting NVD sync — keywords: %s", MANUFACTURING_KEYWORDS)
        count = parser.sync_from_nvd(keywords=MANUFACTURING_KEYWORDS, days_back=days_back)
        return count
    finally:
        parser.close()


def run_cert_in_sync(db_path: str, days_back: int) -> dict:
    """Pull CERT-In advisories and cross-reference with NVD."""
    from cert_in_parser import CERTInParser

    parser = CERTInParser(db_path)
    try:
        return parser.sync(days_back=days_back)
    finally:
        parser.close()


def print_summary(db_path: str) -> None:
    """Print a breakdown of what's in the DB after population."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM vulnerabilities")
    total = cur.fetchone()[0]

    cur.execute("SELECT source, COUNT(*) FROM vulnerabilities GROUP BY source ORDER BY COUNT(*) DESC")
    by_source = cur.fetchall()

    cur.execute("SELECT severity, COUNT(*) FROM vulnerabilities GROUP BY severity ORDER BY "
                "CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END")
    by_severity = cur.fetchall()

    cur.execute("SELECT COUNT(*) FROM iocs")
    ioc_count = cur.fetchone()[0]

    cur.execute("SELECT version, applied_at FROM schema_version ORDER BY version DESC LIMIT 1")
    schema = cur.fetchone()

    conn.close()

    size_mb = Path(db_path).stat().st_size / (1024 * 1024)

    print("\n" + "=" * 58)
    print("  SentryShield Database Initialized")
    print("=" * 58)
    print(f"  Database     : {db_path}")
    print(f"  Size         : {size_mb:.2f} MB")
    print(f"  Schema v     : {schema[0] if schema else '?'}")
    print()
    print(f"  Vulnerabilities : {total} total")
    print()
    print("  By source:")
    for src, cnt in by_source:
        print(f"    {src:<12}  {cnt}")
    print()
    print("  By severity:")
    for sev, cnt in by_severity:
        print(f"    {sev:<10}  {cnt}")
    print()
    print(f"  IOC hashes   : {ioc_count}")
    print("=" * 58)
    print()


def main():
    parser = argparse.ArgumentParser(
        description="SentryShield DB init — creates schema + loads live CVE data"
    )
    parser.add_argument(
        "--db", required=True,
        help="Path to SQLite database (created if not exists)"
    )
    parser.add_argument(
        "--days-back", type=int, default=730,
        help="How far back to pull CVEs (default: 730 days = ~2 years of data)"
    )
    parser.add_argument(
        "--nvd-key",
        default=os.environ.get("NVD_API_KEY", ""),
        help="NVD API key for higher rate limits (or set NVD_API_KEY env var)"
    )
    parser.add_argument(
        "--skip-nvd", action="store_true",
        help="Skip NVD sync (use with --skip-cert-in to just create schema)"
    )
    parser.add_argument(
        "--skip-cert-in", action="store_true",
        help="Skip CERT-In sync"
    )
    parser.add_argument(
        "--include-curated", action="store_true",
        help="Also load curated_vulns.json (supplemental offline baseline)"
    )
    parser.add_argument(
        "--compress", action="store_true",
        help="Compress DB to .gz after init (for offline distribution)"
    )

    args = parser.parse_args()

    db_path = args.db
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    # ── Step 1: Schema ────────────────────────────────────────────────────
    log.info("Step 1/3: Creating database schema")
    create_schema(db_path)

    # ── Step 2: NVD ───────────────────────────────────────────────────────
    nvd_count = 0
    if not args.skip_nvd:
        log.info("Step 2/3: Fetching NVD CVEs (last %d days)...", args.days_back)
        if not args.nvd_key:
            log.warning(
                "No NVD_API_KEY set. Rate-limited to 5 req/30s — this will be slow.\n"
                "  Get a free key: https://nvd.nist.gov/developers/request-an-api-key\n"
                "  Then rerun with: --nvd-key YOUR_KEY  or  set NVD_API_KEY=YOUR_KEY"
            )
        try:
            nvd_count = run_nvd_sync(db_path, args.days_back, args.nvd_key)
            log.info("NVD: %d CVEs inserted", nvd_count)
        except Exception as e:
            log.error("NVD sync failed: %s", e)
    else:
        log.info("Step 2/3: NVD sync skipped (--skip-nvd)")

    # ── Step 3: CERT-In ───────────────────────────────────────────────────
    cert_in_count = 0
    if not args.skip_cert_in:
        log.info("Step 3/3: Fetching CERT-In advisories (last %d days)...", args.days_back)
        try:
            summary = run_cert_in_sync(db_path, args.days_back)
            cert_in_count = summary.get("inserted", 0)
            log.info("CERT-In: %d advisories → %d CVEs inserted", 
                     summary.get("advisories_processed", 0), cert_in_count)
        except Exception as e:
            log.error("CERT-In sync failed: %s", e)
    else:
        log.info("Step 3/3: CERT-In sync skipped (--skip-cert-in)")

    # ── Optional: Curated baseline ────────────────────────────────────────
    if args.include_curated:
        curated_path = Path(__file__).parent / "curated_vulns.json"
        if curated_path.exists():
            from cert_parser import NVDFeedParser
            p = NVDFeedParser(db_path)
            count = p.sync_from_curated(str(curated_path))
            p.close()
            log.info("Curated: %d records loaded", count)
        else:
            log.warning("curated_vulns.json not found — skipping")

    # ── Optional: Compress ────────────────────────────────────────────────
    if args.compress:
        from cert_parser import NVDFeedParser
        p = NVDFeedParser(db_path)
        checksum = p.compress_db()
        p.close()
        log.info("DB compressed. SHA-256: %s", checksum)

    # ── Summary ───────────────────────────────────────────────────────────
    print_summary(db_path)


if __name__ == "__main__":
    main()
