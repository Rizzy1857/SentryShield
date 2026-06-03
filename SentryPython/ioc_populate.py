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
# Curated manufacturing IOC list (embedded — always available offline)
# These are well-known, high-confidence hashes relevant to ICS/OT environments.
# Replace placeholder hashes with real values from VirusTotal/MalwareBazaar.
# ---------------------------------------------------------------------------

CURATED_IOCS = [
    # Mimikatz variants
    {
        "file_hash": "92dc6ef532bbb6d6f9a9b5c7e8d2f4a1b3c5e7f9a2b4d6e8f0c2a4b6d8f0e2a",
        "malware_name": "mimikatz",
        "malware_family": "Credential Dumper",
        "confidence": 100,
        "source": "CURATED"
    },
    # PsExec (legitimate tool, commonly abused in OT attacks)
    {
        "file_hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        "malware_name": "PsExec (abused)",
        "malware_family": "Remote Admin Tool",
        "confidence": 75,
        "source": "CURATED"
    },
    # Industroyer/CRASHOVERRIDE (ICS-specific malware)
    {
        "file_hash": "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",
        "malware_name": "Industroyer",
        "malware_family": "ICS Malware",
        "confidence": 100,
        "source": "CURATED"
    },
    # TRITON/TRISIS (safety system attack tool)
    {
        "file_hash": "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
        "malware_name": "TRITON/TRISIS",
        "malware_family": "ICS Safety System Attack",
        "confidence": 100,
        "source": "CURATED"
    },
    # BlackEnergy (used in Ukrainian power grid attacks)
    {
        "file_hash": "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5",
        "malware_name": "BlackEnergy",
        "malware_family": "APT Malware",
        "confidence": 100,
        "source": "CURATED"
    },
    # Generic Cobalt Strike beacon (commonly used in ransomware pre-staging)
    {
        "file_hash": "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6",
        "malware_name": "Cobalt Strike Beacon",
        "malware_family": "C2 Framework",
        "confidence": 90,
        "source": "CURATED"
    },
    # WannaCry ransomware (still relevant in unpatched plant networks)
    {
        "file_hash": "f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7",
        "malware_name": "WannaCry",
        "malware_family": "Ransomware",
        "confidence": 100,
        "source": "CURATED"
    },
    # NotPetya (supply chain attack, manufacturing sector impact)
    {
        "file_hash": "a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8",
        "malware_name": "NotPetya",
        "malware_family": "Destructive Wiper",
        "confidence": 100,
        "source": "CURATED"
    },
    # RubberDucky HID attack payload script
    {
        "file_hash": "b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9",
        "malware_name": "RubberDucky Payload",
        "malware_family": "HID Attack",
        "confidence": 85,
        "source": "CURATED"
    },
    # Emotet dropper
    {
        "file_hash": "c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0",
        "malware_name": "Emotet",
        "malware_family": "Banking Trojan / Dropper",
        "confidence": 100,
        "source": "CURATED"
    }
    # NOTE: Replace all placeholder hashes above with real SHA-256 values.
    # Real hashes can be obtained from:
    #   - VirusTotal: https://www.virustotal.com
    #   - MalwareBazaar: https://bazaar.abuse.ch
    #   - MISP: https://www.misp-project.org
]


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
