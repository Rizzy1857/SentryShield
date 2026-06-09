"""
SentryShield v1.0 — NVD Feed Parser (cert_parser.py)
Week 2 deliverable

Downloads CVE data from:
  Primary:  NIST NVD JSON 2.0 API (real CVE data)
  Fallback: Local curated_vulns.json (offline, 100-item manufacturing list)

Populates the `vulnerabilities` table in the SentryShield SQLite database.

Usage:
    python cert_parser.py --db vulnerability.db [--curated-only]
    python cert_parser.py --db vulnerability.db --keyword "SCADA"

NVD API note: Rate-limited to 5 requests/30 seconds without API key.
              Set NVD_API_KEY env var to get 50 requests/30 seconds.
              Ref: https://nvd.nist.gov/developers/request-an-api-key
"""

import json
import sqlite3
import gzip
import hashlib
import os
import sys
import time
import logging
import argparse
import ssl
import urllib.parse
import logging
import argparse
from datetime import datetime, timedelta
from pathlib import Path
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("cert_parser")

# Bypass macOS missing root certificates for urllib
ssl._create_default_https_context = ssl._create_unverified_context

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "").strip()

# Manufacturing-relevant product keywords for targeted NVD queries
MANUFACTURING_KEYWORDS = [
    # Siemens
    "Siemens S7", "Siemens WinCC", "Siemens TIA Portal", "SIMATIC",
    "Siemens STEP 7",
    # Mitsubishi
    "Mitsubishi MELSEC", "Mitsubishi GOT", "Mitsubishi iQ",
    # Toyopuc
    "Toyopuc", "JTEKT PLC",
    # Windows Embedded (gear grinding + tester machines)
    "Windows Embedded", "Windows CE", "WES7",
    # High-impact universal CVEs relevant to any Windows OT machine
    "Log4j", "EternalBlue", "BlueKeep", "PrintNightmare",
    # Common OT protocols and software
    "Modbus", "OPC UA", "PROFINET"
]


# ---------------------------------------------------------------------------
# NVD JSON 2.0 Parser
# ---------------------------------------------------------------------------

class NVDFeedParser:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()

    def fetch_nvd_cves(
        self,
        keyword: str = "",
        days_back: int = 30,
        results_per_page: int = 200
    ) -> list[dict]:
        """
        Query NVD API for CVEs matching a keyword.
        Note: pubStartDate/pubEndDate filtering is currently returning 404
        from the NVD 2.0 API regardless of format. Keyword-only search works.
        """
        cves = []
        start_index = 0

        headers = {"User-Agent": "SentryShield/1.0 (security scanner; contact: admin@sentryshield.local)"}
        if NVD_API_KEY:
            headers["api_key"] = NVD_API_KEY

        while True:
            params = f"?resultsPerPage={results_per_page}&startIndex={start_index}"
            params += "&cvssV3Severity=HIGH,CRITICAL"
            if keyword:
                encoded_keyword = urllib.parse.quote(keyword)
                params += f"&keywordSearch={encoded_keyword}"

            url = NVD_BASE_URL + params
            log.info("Fetching NVD: %s", url)

            try:
                req = Request(url, headers=headers)
                with urlopen(req, context=ssl._create_unverified_context() if sys.platform == "darwin" else None, timeout=30) as resp:
                    data = json.loads(resp.read().decode("utf-8"))

                vulnerabilities = data.get("vulnerabilities", [])
                cves.extend(vulnerabilities)

                total = data.get("totalResults", 0)
                log.info("Got %d/%d CVEs (offset=%d)", len(cves), total, start_index)

                # Pagination
                start_index += results_per_page
                if start_index >= total:
                    break

                # NVD rate limit: wait 6s between requests (without API key)
                time.sleep(6 if "api_key" not in headers else 0.6)

            except HTTPError as e:
                if e.code == 429:
                    log.warning("NVD rate limit hit (HTTP 429). Waiting 35 seconds before retrying...")
                    time.sleep(35)
                    continue

                # NVD WAF sometimes returns 404 or 403 for invalid/expired API keys
                if e.code in (404, 403) and "api_key" in headers:
                    log.warning("NVD rejected the API key (HTTP %d). It may be expired or invalid. Falling back to unauthenticated requests...", e.code)
                    del headers["api_key"]
                    continue # Retry the exact same URL without the API key
                
                log.error("NVD HTTP error: %d %s", e.code, e.reason)
                break
            except URLError as e:
                log.error("NVD connection error: %s", e.reason)
                break
            except Exception as e:
                log.error("NVD fetch error: %s", e)
                break

        return cves

    def parse_nvd_cve(self, cve_item: dict) -> dict | None:
        """
        Parse a single NVD CVE 2.0 item into a flat vulnerability record.

        NVD 2.0 structure:
          { "cve": {
              "id": "CVE-2021-44228",
              "descriptions": [{"lang": "en", "value": "..."}],
              "metrics": { "cvssMetricV31": [{"cvssData": {"baseScore": 10.0}}] },
              "configurations": [...],
              "published": "2021-12-10T..."
          }}
        """
        try:
            cve = cve_item.get("cve", {})
            cve_id = cve.get("id", "")
            if not cve_id:
                return None

            # English description
            description = ""
            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # CVSS score (prefer v3.1, fall back to v3.0, then v2.0)
            cvss_score = 0.0
            for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metrics = cve.get("metrics", {}).get(metric_key, [])
                if metrics:
                    cvss_data = metrics[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    break

            # Severity from CVSS
            severity = _cvss_to_severity(cvss_score)

            # Affected product from configurations (first CPE match)
            product_name = _extract_product_name(cve)

            # Affected version ranges
            version_ranges = _extract_version_ranges(cve)

            # Published date
            first_seen = cve.get("published", "")[:10] if cve.get("published") else ""

            return {
                "id": cve_id,
                "product_name": product_name or "Unknown",
                "affected_versions": json.dumps(version_ranges),
                "cvss_score": cvss_score,
                "severity": severity,
                "description": description[:2000],  # Truncate for DB
                "remediation": _extract_remediation(cve),
                "source": "NVD",
                "first_seen": first_seen
            }
        except Exception as e:
            log.warning("Failed to parse CVE item: %s", e)
            return None

    def insert_vulnerabilities(self, vulns: list[dict]) -> int:
        """Batch insert with INSERT OR IGNORE (skip duplicates)."""
        inserted = 0
        sql = """
            INSERT OR IGNORE INTO vulnerabilities
                (id, product_name, affected_versions, cvss_score, severity,
                 description, remediation, source, first_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        for vuln in vulns:
            if not vuln or not vuln.get("id"):
                continue
            try:
                self.cursor.execute(sql, (
                    vuln["id"],
                    vuln["product_name"],
                    vuln["affected_versions"],
                    vuln["cvss_score"],
                    vuln["severity"],
                    vuln["description"],
                    vuln["remediation"],
                    vuln["source"],
                    vuln["first_seen"]
                ))
                inserted += 1
            except sqlite3.Error as e:
                log.warning("Insert error for %s: %s", vuln.get("id"), e)

        self.conn.commit()
        return inserted

    def sync_from_nvd(self, keywords: list[str] = None, days_back: int = 30) -> int:
        """
        Main sync: fetch NVD CVEs for each manufacturing keyword, insert into DB.
        Returns total new records inserted.
        """
        if keywords is None:
            keywords = MANUFACTURING_KEYWORDS

        total_inserted = 0

        for keyword in keywords:
            log.info("Syncing NVD for keyword: '%s'", keyword)
            raw_cves = self.fetch_nvd_cves(keyword=keyword, days_back=days_back)
            parsed = [self.parse_nvd_cve(item) for item in raw_cves]
            parsed = [p for p in parsed if p]  # Filter None

            inserted = self.insert_vulnerabilities(parsed)
            total_inserted += inserted
            log.info("Keyword '%s': %d/%d inserted", keyword, inserted, len(parsed))

            # Respect NVD rate limit between keyword queries
            time.sleep(2)

        log.info("NVD sync complete: %d total new records", total_inserted)
        return total_inserted

    def sync_from_curated(self, curated_json_path: str) -> int:
        """
        Load from local curated_vulns.json (offline fallback / manufacturing-specific list).
        """
        path = Path(curated_json_path)
        if not path.exists():
            log.error("Curated JSON not found: %s", curated_json_path)
            return 0

        with open(path, "r", encoding="utf-8") as f:
            vulns = json.load(f)

        log.info("Loading %d curated vulnerabilities from %s", len(vulns), path)
        inserted = self.insert_vulnerabilities(vulns)
        log.info("Curated sync: %d/%d inserted", inserted, len(vulns))
        return inserted

    def compress_db(self) -> str:
        """
        Compress the SQLite database to .gz for offline distribution.
        Returns SHA-256 checksum of the compressed file.
        """
        gz_path = self.db_path + ".gz"
        with open(self.db_path, "rb") as f_in:
            with gzip.open(gz_path, "wb") as f_out:
                f_out.write(f_in.read())

        # SHA-256 checksum
        with open(gz_path, "rb") as f:
            checksum = hashlib.sha256(f.read()).hexdigest()

        size_mb = Path(gz_path).stat().st_size / (1024 * 1024)
        log.info("DB compressed: %s (%.1f MB)", gz_path, size_mb)
        log.info("SHA-256: %s", checksum)

        # Write checksum file alongside
        with open(gz_path + ".sha256", "w") as f:
            f.write(checksum)

        return checksum

    def get_stats(self) -> dict:
        """Return DB statistics for reporting."""
        self.cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        vuln_count = self.cursor.fetchone()[0]

        self.cursor.execute("SELECT COUNT(*) FROM iocs")
        ioc_count = self.cursor.fetchone()[0]

        self.cursor.execute(
            "SELECT severity, COUNT(*) FROM vulnerabilities GROUP BY severity"
        )
        by_severity = dict(self.cursor.fetchall())

        return {
            "total_vulnerabilities": vuln_count,
            "total_iocs": ioc_count,
            "by_severity": by_severity,
            "db_size_mb": round(Path(self.db_path).stat().st_size / (1024 * 1024), 2)
        }

    def close(self):
        self.conn.close()


# ---------------------------------------------------------------------------
# CPE / Version parsing helpers
# ---------------------------------------------------------------------------

def _extract_product_name(cve: dict) -> str:
    """Extract a readable product name from CPE configuration."""
    try:
        for node in cve.get("configurations", [{}])[0].get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                # CPE format: cpe:2.3:a:vendor:product:version:...
                parts = cpe.split(":")
                if len(parts) >= 5:
                    vendor = parts[3].replace("_", " ").title()
                    product = parts[4].replace("_", " ").title()
                    return f"{vendor} {product}"
    except (IndexError, KeyError):
        pass
    return ""


def _extract_version_ranges(cve: dict) -> list[dict]:
    """
    Extract version ranges from CPE match criteria.
    Returns list of {min, max, include_min, include_max} dicts
    consumed by VulnerabilityMatcher.IsVersionVulnerable().

    NVD fields:
      versionStartIncluding → min, include_min=True  (>= min)
      versionStartExcluding → min, include_min=False (>  min)
      versionEndIncluding   → max, include_max=True  (<= max)
      versionEndExcluding   → max, include_max=False (<  max)
    """
    ranges = []
    try:
        for conf in cve.get("configurations", []):
            for node in conf.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if not match.get("vulnerable", False):
                        continue

                    v_start_inc = match.get("versionStartIncluding")
                    v_start_exc = match.get("versionStartExcluding")
                    v_end_inc   = match.get("versionEndIncluding")
                    v_end_exc   = match.get("versionEndExcluding")

                    version_range = {
                        "min":         v_start_inc or v_start_exc,
                        "max":         v_end_inc   or v_end_exc,
                        "include_min": v_start_inc is not None,  # True = >=, False = >
                        "include_max": v_end_inc   is not None,  # True = <=, False = <
                    }

                    # Only store if at least one bound is present
                    if version_range["min"] or version_range["max"]:
                        ranges.append(version_range)
    except (KeyError, TypeError):
        pass
    return ranges



def _extract_remediation(cve: dict) -> str:
    """Pull remediation hint from NVD references (look for 'Patch' tagged refs)."""
    for ref in cve.get("references", []):
        tags = ref.get("tags", [])
        if "Patch" in tags or "Vendor Advisory" in tags:
            return f"See: {ref.get('url', '')}"
    return "Apply latest vendor patch. See NVD for details."


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="SentryShield NVD/Curated vulnerability feed parser"
    )
    parser.add_argument("--db", required=True, help="Path to SQLite database")
    parser.add_argument(
        "--curated-only", action="store_true",
        help="Only load from curated_vulns.json (offline mode)"
    )
    parser.add_argument(
        "--curated-json",
        default=str(Path(__file__).parent / "curated_vulns.json"),
        help="Path to curated_vulns.json"
    )
    parser.add_argument(
        "--keyword",
        help="Single keyword to query from NVD (overrides default list)"
    )
    parser.add_argument(
        "--days-back", type=int, default=30,
        help="How many days back to pull NVD updates (default: 30)"
    )
    parser.add_argument(
        "--compress", action="store_true",
        help="Compress DB to .gz after sync"
    )
    parser.add_argument("--stats", action="store_true", help="Print DB stats and exit")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")

    args = parser.parse_args()

    feed = NVDFeedParser(args.db)

    if args.stats:
        stats = feed.get_stats()
        if args.json:
            print(json.dumps(stats))
        else:
            print(f"Vulnerabilities: {stats['total_vulnerabilities']}")
            print(f"IOCs:            {stats['total_iocs']}")
            print(f"By severity:     {stats['by_severity']}")
            print(f"DB size:         {stats['db_size_mb']} MB")
        feed.close()
        return

    total = 0

    if args.curated_only:
        total = feed.sync_from_curated(args.curated_json)
    else:
        # Always load curated list first (offline baseline)
        curated_count = feed.sync_from_curated(args.curated_json)
        log.info("Curated baseline: %d records", curated_count)

        # Then pull from NVD if network available
        keywords = [args.keyword] if args.keyword else MANUFACTURING_KEYWORDS
        nvd_count = feed.sync_from_nvd(keywords=keywords, days_back=args.days_back)
        total = curated_count + nvd_count

    log.info("Sync complete. Total new records: %d", total)

    if args.compress:
        feed.compress_db()

    if args.json:
        print(json.dumps({"inserted": total, "db": args.db}))

    feed.close()


if __name__ == "__main__":
    main()
