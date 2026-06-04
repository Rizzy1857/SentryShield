"""
SentryShield v1.0 — IOC Database Population Script (ioc_populate.py)
Week 3 deliverable

Populates the `iocs` table with known malware file hashes.

Sources supported:
  1. Local curated_iocs.json — manufacturing-relevant threats
  2. MalwareBazaar API (abuse.ch) — free, no key required
  3. Any MISP-compatible threat feed (JSON)

Usage:
    python ioc_populate.py --db vulnerability.db --curated
    python ioc_populate.py --db vulnerability.db --malwarebazaar --tag ransomware
    python ioc_populate.py --db vulnerability.db --stats
"""

import argparse
import json
import logging
import sqlite3
import sys
import time
from datetime import datetime
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stderr
)
log = logging.getLogger("ioc_populate")

# MalwareBazaar API endpoint (free, no registration)
MALWAREBAZAAR_API = "https://mb-api.abuse.ch/api/v1/"


# ---------------------------------------------------------------------------
# Curated manufacturing IOC list
# ---------------------------------------------------------------------------
# This list is intentionally empty.
#
# Real IOC hashes are fetched at deployment time from MalwareBazaar (free):
#   python ioc_populate.py --db vulnerability.db --malwarebazaar --tag ransomware
#   python ioc_populate.py --db vulnerability.db --malwarebazaar --tag rat
#   python ioc_populate.py --db vulnerability.db --malwarebazaar --tag ics
#
# If you need an offline curated list, export from:
#   MalwareBazaar: https://bazaar.abuse.ch/export/ (SHA-256 CSV, free, no key)
#   VirusTotal:    https://www.virustotal.com/gui/home/upload
#   MISP:          https://www.misp-project.org
#
# Then import with: --json-file your_hashes.json
# ---------------------------------------------------------------------------

CURATED_IOCS: list[dict] = []


# ---------------------------------------------------------------------------
# Database operations
# ---------------------------------------------------------------------------

def insert_iocs(db_path: str, iocs: list[dict]) -> int:
    """Bulk insert IOC records, skip duplicates."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    inserted = 0
    sql = """
        INSERT OR IGNORE INTO iocs
            (file_hash, malware_name, malware_family, confidence, source, detection_date)
        VALUES (?, ?, ?, ?, ?, ?)
    """
    for ioc in iocs:
        try:
            cursor.execute(sql, (
                ioc["file_hash"].lower(),
                ioc.get("malware_name", "Unknown"),
                ioc.get("malware_family", "Unknown"),
                ioc.get("confidence", 100),
                ioc.get("source", "CURATED"),
                datetime.utcnow().strftime("%Y-%m-%d")
            ))
            inserted += 1
        except sqlite3.Error as e:
            log.warning("IOC insert error: %s", e)

    conn.commit()
    conn.close()
    return inserted


# ---------------------------------------------------------------------------
# MalwareBazaar integration
# ---------------------------------------------------------------------------

def fetch_malwarebazaar(tag: str = "ransomware", limit: int = 100) -> list[dict]:
    """
    Query MalwareBazaar API for samples by tag.
    Free, no API key needed.
    Tags: ransomware, trojan, rat, loader, miner, ics, etc.
    """
    log.info("Fetching MalwareBazaar samples tagged: '%s'", tag)

    payload = f"query=get_taginfo&tag={tag}&limit={limit}"
    req = Request(
        MALWAREBAZAAR_API,
        data=payload.encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )

    iocs = []
    try:
        with urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        if data.get("query_status") != "ok":
            log.warning("MalwareBazaar returned: %s", data.get("query_status"))
            return []

        for sample in data.get("data", []):
            sha256 = sample.get("sha256_hash", "")
            if not sha256:
                continue
            iocs.append({
                "file_hash": sha256,
                "malware_name": sample.get("signature", "Unknown"),
                "malware_family": tag.title(),
                "confidence": 90,
                "source": "MalwareBazaar"
            })

        log.info("MalwareBazaar: fetched %d hashes for tag '%s'", len(iocs), tag)

    except URLError as e:
        log.error("MalwareBazaar connection error: %s", e)
    except Exception as e:
        log.error("MalwareBazaar fetch failed: %s", e)

    return iocs


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="SentryShield IOC database population tool"
    )
    parser.add_argument("--db", required=True, help="Path to SQLite database")
    parser.add_argument(
        "--curated", action="store_true",
        help="Load embedded curated manufacturing IOC list"
    )
    parser.add_argument(
        "--malwarebazaar", action="store_true",
        help="Fetch from MalwareBazaar (requires internet)"
    )
    parser.add_argument(
        "--tag", default="ransomware",
        help="MalwareBazaar tag to query (default: ransomware)"
    )
    parser.add_argument(
        "--json-file",
        help="Load IOCs from a local JSON file (array of {file_hash, malware_name, ...})"
    )
    parser.add_argument("--stats", action="store_true", help="Show IOC stats and exit")

    args = parser.parse_args()

    if args.stats:
        conn = sqlite3.connect(args.db)
        count = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
        by_family = conn.execute(
            "SELECT malware_family, COUNT(*) FROM iocs GROUP BY malware_family ORDER BY 2 DESC LIMIT 10"
        ).fetchall()
        conn.close()
        print(f"Total IOCs: {count}")
        print("Top families:")
        for family, cnt in by_family:
            print(f"  {family}: {cnt}")
        return

    total = 0

    if args.curated:
        count = insert_iocs(args.db, CURATED_IOCS)
        log.info("Curated: inserted %d IOCs", count)
        total += count

    if args.malwarebazaar:
        iocs = fetch_malwarebazaar(tag=args.tag)
        count = insert_iocs(args.db, iocs)
        log.info("MalwareBazaar [%s]: inserted %d IOCs", args.tag, count)
        total += count

    if args.json_file:
        path = Path(args.json_file)
        if path.exists():
            with open(path, "r") as f:
                iocs = json.load(f)
            count = insert_iocs(args.db, iocs)
            log.info("JSON file: inserted %d IOCs", count)
            total += count
        else:
            log.error("JSON file not found: %s", args.json_file)

    if total == 0 and not args.stats:
        log.warning("No IOCs inserted. Use --curated, --malwarebazaar, or --json-file")

    log.info("IOC population complete. Total inserted: %d", total)


if __name__ == "__main__":
    main()
