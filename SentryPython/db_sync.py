"""
SentryShield v1.0 — Daily DB Sync Scheduler (db_sync.py)

Runs nightly syncs from two live sources:
  1. NIST NVD API   — manufacturing-relevant CVEs (last 24h delta)
  2. CERT-In        — India CERT advisories (last 7 days rolling window)

Can be deployed as:
  - A Windows Task Scheduler task (recommended — run with --once flag)
  - A standalone Python process (schedule library)

Usage:
    python db_sync.py --db C:\\ProgramData\\SentryShield\\vulnerability.db
    python db_sync.py --db vulnerability.db --once        (run once and exit)
    python db_sync.py --db vulnerability.db --json        (JSON status output)
    python db_sync.py --db vulnerability.db --time 02:00  (run at 2am)

Environment:
    NVD_API_KEY — Optional NVD API key for 10x higher rate limits.
"""

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stderr
)
log = logging.getLogger("db_sync")

# Add script directory to path so imports work regardless of cwd
sys.path.insert(0, str(Path(__file__).parent))

from cert_parser import NVDFeedParser, MANUFACTURING_KEYWORDS


def run_sync(db_path: str, json_output: bool = False) -> dict:
    """
    Execute a full nightly sync:
      1. NVD delta (last 24h) for manufacturing keywords
      2. CERT-In delta (last 7 days) for new advisories
      3. Compress DB

    Returns status dict.
    """
    start = datetime.utcnow()
    log.info("=== SentryShield DB Sync starting at %s ===", start.isoformat())

    if not Path(db_path).exists():
        log.error("Database not found: %s — run init_db.py first", db_path)
        result = {"status": "error", "error": "DB not found — run init_db.py first"}
        if json_output:
            print(json.dumps(result))
        return result

    result = {
        "timestamp": start.isoformat(),
        "status": "error",
        "nvd_inserted": 0,
        "cert_in_inserted": 0,
        "total_vulnerabilities": 0,
        "db_compressed": False,
        "checksum": None,
        "error": None,
    }

    feed = NVDFeedParser(db_path)

    # ── 1. NVD delta (last 1 day) ─────────────────────────────────────────
    try:
        log.info("Syncing NVD (last 24h delta)...")
        result["nvd_inserted"] = feed.sync_from_nvd(
            keywords=MANUFACTURING_KEYWORDS,
            days_back=1
        )
        log.info("NVD delta: %d new records", result["nvd_inserted"])
    except Exception as e:
        log.warning("NVD sync failed (may be offline): %s", e)
        result["nvd_inserted"] = 0

    feed.close()

    # ── 2. CERT-In delta (last 7 days rolling) ────────────────────────────
    try:
        from cert_in_parser import CERTInParser
        log.info("Syncing CERT-In (last 7 days)...")
        cert_in = CERTInParser(db_path)
        summary = cert_in.sync(days_back=7)
        cert_in.close()
        result["cert_in_inserted"] = summary.get("inserted", 0)
        log.info("CERT-In: %d advisories → %d new CVEs",
                 summary.get("advisories_processed", 0),
                 result["cert_in_inserted"])
    except Exception as e:
        log.warning("CERT-In sync failed: %s", e)
        result["cert_in_inserted"] = 0

    # ── 3. Stats + compress ───────────────────────────────────────────────
    try:
        feed = NVDFeedParser(db_path)
        stats = feed.get_stats()
        result["total_vulnerabilities"] = stats["total_vulnerabilities"]

        checksum = feed.compress_db()
        result["db_compressed"] = True
        result["checksum"] = checksum
        feed.close()
    except Exception as e:
        log.warning("Post-sync compress/stats failed: %s", e)

    result["status"] = "success"
    elapsed = (datetime.utcnow() - start).total_seconds()
    total_new = result["nvd_inserted"] + result["cert_in_inserted"]
    log.info("=== Sync complete: %d new records in %.1fs ===", total_new, elapsed)

    if json_output:
        print(json.dumps(result))

    return result


def main():
    parser = argparse.ArgumentParser(
        description="SentryShield vulnerability DB daily sync (NVD + CERT-In)"
    )
    parser.add_argument("--db", required=True, help="Path to SQLite database")
    parser.add_argument(
        "--once", action="store_true",
        help="Run once and exit (for Windows Task Scheduler use)"
    )
    parser.add_argument(
        "--time", default="06:00",
        help="Daily sync time in HH:MM format (default: 06:00)"
    )
    parser.add_argument("--json", action="store_true", help="Output status as JSON")

    args = parser.parse_args()

    if args.once:
        run_sync(args.db, json_output=args.json)
        return

    # Schedule mode: run daily at configured time
    try:
        import schedule
    except ImportError:
        log.error("'schedule' package not found. Run: pip install schedule")
        log.info("Alternatively, use --once flag with Windows Task Scheduler.")
        sys.exit(1)

    log.info("DB sync scheduler running — daily at %s", args.time)

    def scheduled_sync():
        run_sync(args.db, json_output=False)

    schedule.every().day.at(args.time).do(scheduled_sync)

    # Run once immediately on startup
    scheduled_sync()

    while True:
        schedule.run_pending()
        time.sleep(60)


if __name__ == "__main__":
    main()
