"""
SentryShield v1.0 — Daily DB Sync Scheduler (db_sync.py)
Week 2 deliverable

Runs the NVD feed sync on a schedule.
Can be deployed as:
  - A Windows Task Scheduler task (recommended for air-gapped environments)
  - A standalone Python process

Usage:
    python db_sync.py --db C:\\ProgramData\\SentryShield\\vulnerability.db
    python db_sync.py --db vulnerability.db --once    (run once and exit)
    python db_sync.py --db vulnerability.db --json    (JSON status output)
"""

import argparse
import json
import logging
import sys
import time
from datetime import datetime
from pathlib import Path

import schedule

from cert_parser import NVDFeedParser, MANUFACTURING_KEYWORDS

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stderr
)
log = logging.getLogger("db_sync")


def run_sync(db_path: str, curated_json: str, json_output: bool = False) -> dict:
    """
    Execute a full sync cycle:
    1. Load curated manufacturing vulnerability list (offline baseline)
    2. Pull latest NVD CVEs for manufacturing keywords
    3. Compress DB for offline distribution
    Returns status dict.
    """
    start = datetime.utcnow()
    log.info("=== SentryShield DB Sync starting at %s ===", start.isoformat())

    result = {
        "timestamp": start.isoformat(),
        "status": "error",
        "curated_inserted": 0,
        "nvd_inserted": 0,
        "total_vulnerabilities": 0,
        "db_compressed": False,
        "checksum": None,
        "error": None
    }

    try:
        feed = NVDFeedParser(db_path)

        # Step 1: Curated list (always succeeds — offline)
        curated_path = Path(curated_json)
        if curated_path.exists():
            result["curated_inserted"] = feed.sync_from_curated(str(curated_path))
        else:
            log.warning("Curated JSON not found at %s — skipping", curated_json)

        # Step 2: NVD live sync (may fail on air-gapped networks — non-fatal)
        try:
            result["nvd_inserted"] = feed.sync_from_nvd(
                keywords=MANUFACTURING_KEYWORDS,
                days_back=1  # Daily sync: last 24 hours only
            )
        except Exception as e:
            log.warning("NVD sync failed (may be offline): %s", e)
            result["nvd_inserted"] = 0

        # Step 3: Compress DB
        try:
            checksum = feed.compress_db()
            result["db_compressed"] = True
            result["checksum"] = checksum
        except Exception as e:
            log.warning("DB compression failed: %s", e)

        # Stats
        stats = feed.get_stats()
        result["total_vulnerabilities"] = stats["total_vulnerabilities"]
        result["status"] = "success"

        elapsed = (datetime.utcnow() - start).total_seconds()
        log.info("=== Sync complete: %d new records in %.1fs ===",
                 result["curated_inserted"] + result["nvd_inserted"], elapsed)

        feed.close()

    except Exception as e:
        log.error("Sync failed: %s", e)
        result["error"] = str(e)

    if json_output:
        print(json.dumps(result))

    return result


def main():
    parser = argparse.ArgumentParser(
        description="SentryShield vulnerability DB daily sync scheduler"
    )
    parser.add_argument("--db", required=True, help="Path to SQLite database")
    parser.add_argument(
        "--curated-json",
        default=str(Path(__file__).parent / "curated_vulns.json"),
        help="Path to curated_vulns.json"
    )
    parser.add_argument(
        "--once", action="store_true",
        help="Run once and exit (for Task Scheduler / cron use)"
    )
    parser.add_argument(
        "--time", default="06:00",
        help="Daily sync time in HH:MM format (default: 06:00)"
    )
    parser.add_argument("--json", action="store_true", help="Output status as JSON")

    args = parser.parse_args()

    if args.once:
        # Run immediately once and exit (used by Windows Task Scheduler)
        run_sync(args.db, args.curated_json, json_output=args.json)
        return

    # Schedule mode: run daily at configured time
    log.info("DB sync scheduler starting — will run daily at %s", args.time)

    def scheduled_sync():
        run_sync(args.db, args.curated_json, json_output=False)

    schedule.every().day.at(args.time).do(scheduled_sync)

    # Run immediately on first start
    scheduled_sync()

    # Main loop
    while True:
        schedule.run_pending()
        time.sleep(60)


if __name__ == "__main__":
    main()
