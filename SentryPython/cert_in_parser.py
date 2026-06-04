"""
SentryShield v1.0 — CERT-In Advisory Parser (cert_in_parser.py)

Fetches live vulnerability advisories from India's CERT-In:
  https://www.cert-in.org.in/

Two data sources:
  1. CERT-In RSS feed      — latest advisories (CIVN IDs + links)
  2. CERT-In advisory HTML — scrapes CVE references from each advisory page
  3. NVD cross-reference   — for each CVE found, fetches full data from NVD API
     (version ranges, CVSS scores, affected products)

Why cross-reference with NVD?
  CERT-In advisories are human-readable HTML — they list CVE IDs but don't
  provide machine-parseable version ranges. NVD does. So we use CERT-In as the
  discovery layer and NVD as the structured data layer.

Output: Populates the `vulnerabilities` table with source='CERT-IN'.

Usage:
    python cert_in_parser.py --db vulnerability.db
    python cert_in_parser.py --db vulnerability.db --days-back 90
    python cert_in_parser.py --db vulnerability.db --advisory CIVN-2024-0001
    python cert_in_parser.py --db vulnerability.db --stats

Dependencies (stdlib only — no pip needed):
    urllib, xml.etree.ElementTree, html.parser, sqlite3, re, json
"""

import argparse
import json
import logging
import os
import re
import sqlite3
import sys
import time
from datetime import datetime, timedelta
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, quote
from urllib.request import Request, urlopen
from xml.etree import ElementTree

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stderr,
)
log = logging.getLogger("cert_in")

# ---------------------------------------------------------------------------
# CERT-In endpoints
# ---------------------------------------------------------------------------

CERT_IN_RSS = "https://www.cert-in.org.in/s2cMainServlet?pageid=PUBVLNOTES01&rss=true"
CERT_IN_ADVISORY_BASE = "https://www.cert-in.org.in/s2cMainServlet?pageid=PUBVLNOTES02&"
CERT_IN_LIST_URL = "https://www.cert-in.org.in/s2cMainServlet?pageid=PUBVLNOTES01"

# NVD API for cross-referencing CVE details
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")

# Regex to extract CVE IDs from HTML text
CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Regex to extract CIVN IDs
CIVN_PATTERN = re.compile(r"CIVN-\d{4}-\d{4}", re.IGNORECASE)


# ---------------------------------------------------------------------------
# CERT-In RSS parser
# ---------------------------------------------------------------------------

class CERTInRSSParser:
    """Parses the CERT-In RSS feed to get a list of recent advisory IDs and links."""

    def parse(self, xml_text: str) -> list[dict]:
        """Returns list of {id, title, link, pub_date} dicts."""
        advisories = []
        try:
            root = ElementTree.fromstring(xml_text)
            channel = root.find("channel")
            if channel is None:
                # Try with namespace
                ns = {"": "http://www.w3.org/2005/Atom"}
                items = root.findall(".//item") or root.findall(".//entry")
            else:
                items = channel.findall("item")

            for item in items:
                title = item.findtext("title", "").strip()
                link  = item.findtext("link", "").strip()
                pub   = item.findtext("pubDate", "") or item.findtext("published", "")
                desc  = item.findtext("description", "")

                # Extract CIVN ID from title or link
                civn_match = CIVN_PATTERN.search(title) or CIVN_PATTERN.search(link)
                civn_id = civn_match.group(0).upper() if civn_match else ""

                # Extract any CVE IDs already in the description/title
                cves = list(set(CVE_PATTERN.findall(title + " " + desc)))

                advisories.append({
                    "civn_id": civn_id,
                    "title": title,
                    "link": link,
                    "pub_date": pub[:10] if pub else "",
                    "cves_in_rss": [c.upper() for c in cves],
                })

        except ElementTree.ParseError as e:
            log.warning("RSS XML parse error: %s", e)

        return advisories


# ---------------------------------------------------------------------------
# CERT-In advisory HTML scraper
# ---------------------------------------------------------------------------

class AdvisoryHTMLParser(HTMLParser):
    """Extracts CVE IDs from a CERT-In advisory HTML page."""

    def __init__(self):
        super().__init__()
        self.text_chunks: list[str] = []
        self._in_body = False

    def handle_data(self, data: str):
        self.text_chunks.append(data)

    def get_cves(self) -> list[str]:
        full_text = " ".join(self.text_chunks)
        return list(set(m.upper() for m in CVE_PATTERN.findall(full_text)))

    def get_severity(self) -> str:
        """CERT-In rates advisories as Critical/High/Medium/Low."""
        full_text = " ".join(self.text_chunks).lower()
        if "critical" in full_text:
            return "CRITICAL"
        elif "high" in full_text:
            return "HIGH"
        elif "medium" in full_text or "moderate" in full_text:
            return "MEDIUM"
        return "LOW"

    def get_affected_products(self) -> list[str]:
        """Best-effort extraction of product names mentioned in advisory."""
        full_text = " ".join(self.text_chunks)
        # Look for common product-version patterns like "Product X versions X.Y through Z"
        products = re.findall(
            r"([A-Za-z][A-Za-z0-9 _-]{2,40})\s+(?:version|versions?|v)[\s]*(\d[\d.x*]+)",
            full_text, re.IGNORECASE
        )
        return [f"{p[0].strip()} {p[1].strip()}" for p in products[:10]]


# ---------------------------------------------------------------------------
# NVD cross-reference
# ---------------------------------------------------------------------------

def fetch_nvd_cve(cve_id: str, retry: int = 3) -> dict | None:
    """
    Fetch a single CVE's full record from NVD API.
    Returns the parsed CVE dict or None on failure.
    """
    headers = {"User-Agent": "SentryShield/1.0 (Security Scanner)"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    url = f"{NVD_CVE_URL}?cveId={cve_id}"

    for attempt in range(retry):
        try:
            req = Request(url, headers=headers)
            with urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return None

            return vulns[0].get("cve", {})

        except HTTPError as e:
            if e.code == 404:
                return None  # CVE doesn't exist in NVD
            if e.code == 429:
                log.warning("NVD rate limit hit — waiting 30s...")
                time.sleep(30)
            else:
                log.warning("NVD HTTP %d for %s", e.code, cve_id)
                break
        except URLError as e:
            log.warning("NVD connection error for %s: %s", cve_id, e.reason)
            break
        except Exception as e:
            log.warning("NVD fetch error for %s: %s", cve_id, e)
            break

        time.sleep(2 ** attempt)  # Exponential backoff

    return None


def nvd_cve_to_record(cve: dict, civn_id: str = "", cert_in_severity: str = "") -> dict | None:
    """Convert NVD CVE dict → SentryShield vulnerability record."""
    cve_id = cve.get("id", "")
    if not cve_id:
        return None

    # English description
    description = ""
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            description = desc.get("value", "")
            break

    # CVSS score — prefer v3.1, fall back to v3.0, then v2.0
    cvss_score = 0.0
    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metrics = cve.get("metrics", {}).get(metric_key, [])
        if metrics:
            cvss_data = metrics[0].get("cvssData", {})
            cvss_score = cvss_data.get("baseScore", 0.0)
            break

    severity = _cvss_to_severity(cvss_score) if cvss_score > 0 else cert_in_severity or "MEDIUM"

    # Product name from CPE
    product_name = _extract_product_name_from_cve(cve) or cve_id

    # Version ranges (exact format VulnerabilityMatcher.cs expects)
    version_ranges = _extract_version_ranges_from_cve(cve)

    # Remediation from references
    remediation = _extract_remediation_from_cve(cve)
    if civn_id:
        remediation = (f"CERT-In Advisory {civn_id}. " + remediation)[:2000]

    first_seen = cve.get("published", "")[:10] if cve.get("published") else ""

    return {
        "id": cve_id,
        "product_name": product_name,
        "affected_versions": json.dumps(version_ranges),
        "cvss_score": cvss_score,
        "severity": severity,
        "description": description[:2000],
        "remediation": remediation,
        "source": "CERT-IN",
        "first_seen": first_seen,
    }


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

class CERTInParser:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.cursor = self.conn.cursor()
        self._rss_parser = CERTInRSSParser()

    # ── Public API ──────────────────────────────────────────────────────────

    def sync(self, days_back: int = 30) -> dict:
        """
        Full sync:
          1. Fetch CERT-In RSS → get advisory list
          2. For each advisory: scrape HTML → extract CVE IDs
          3. For each CVE: fetch NVD → parse version ranges → insert to DB
        Returns summary dict.
        """
        log.info("=== CERT-In sync starting (last %d days) ===", days_back)
        start = datetime.utcnow()

        advisories = self._fetch_rss()
        log.info("RSS: %d advisories found", len(advisories))

        # Filter by date
        cutoff = datetime.utcnow() - timedelta(days=days_back)
        filtered = []
        for adv in advisories:
            try:
                pub = datetime.strptime(adv["pub_date"], "%Y-%m-%d")
                if pub >= cutoff:
                    filtered.append(adv)
            except (ValueError, KeyError):
                filtered.append(adv)  # Include if date unknown

        log.info("After date filter: %d advisories to process", len(filtered))

        all_cves: set[str] = set()
        civn_cve_map: dict[str, str] = {}  # cve_id → civn_id

        # Collect all CVE IDs (from RSS + scraping each advisory)
        for adv in filtered:
            # CVEs already in RSS description
            for cve in adv.get("cves_in_rss", []):
                all_cves.add(cve)
                civn_cve_map[cve] = adv.get("civn_id", "")

            # Scrape advisory page for more CVEs
            if adv.get("link"):
                scraped_cves = self._scrape_advisory(adv["link"])
                for cve in scraped_cves:
                    all_cves.add(cve)
                    civn_cve_map[cve] = adv.get("civn_id", "")

                time.sleep(1)  # Be polite to CERT-In servers

        log.info("Total unique CVEs to look up in NVD: %d", len(all_cves))

        # Cross-reference with NVD
        inserted = 0
        failed = 0
        no_version_data = 0

        for i, cve_id in enumerate(sorted(all_cves)):
            civn_id = civn_cve_map.get(cve_id, "")
            log.info("[%d/%d] Fetching NVD: %s (CIVN: %s)",
                     i + 1, len(all_cves), cve_id, civn_id or "N/A")

            cve_data = fetch_nvd_cve(cve_id)
            if not cve_data:
                log.warning("  NVD: no data for %s", cve_id)
                failed += 1
                continue

            record = nvd_cve_to_record(cve_data, civn_id=civn_id)
            if not record:
                failed += 1
                continue

            version_ranges = json.loads(record.get("affected_versions", "[]"))
            if not version_ranges:
                no_version_data += 1
                log.debug("  %s: no version ranges in NVD — storing anyway", cve_id)

            if self._insert_record(record):
                inserted += 1
                log.info("  ✓ %s stored (CVSS %.1f, %s)",
                         cve_id, record["cvss_score"], record["severity"])
            else:
                log.debug("  %s already in DB — skipped", cve_id)

            # NVD rate limit: 5 req/30s without key, 50 req/30s with key
            time.sleep(0.8 if NVD_API_KEY else 6.5)

        elapsed = (datetime.utcnow() - start).total_seconds()
        summary = {
            "source": "CERT-IN",
            "advisories_found": len(advisories),
            "advisories_processed": len(filtered),
            "cves_discovered": len(all_cves),
            "inserted": inserted,
            "failed_nvd_lookup": failed,
            "no_version_data": no_version_data,
            "elapsed_seconds": round(elapsed, 1),
        }
        log.info("=== CERT-In sync complete: %s ===", json.dumps(summary))
        return summary

    def sync_single_advisory(self, civn_id: str) -> int:
        """Fetch and insert all CVEs from a single named CERT-In advisory."""
        url = CERT_IN_ADVISORY_BASE + f"CERTINID={quote(civn_id)}"
        cves = self._scrape_advisory(url)

        if not cves:
            log.warning("No CVEs found in advisory %s", civn_id)
            return 0

        log.info("Advisory %s: found CVEs: %s", civn_id, ", ".join(cves))
        inserted = 0
        for cve_id in cves:
            cve_data = fetch_nvd_cve(cve_id)
            if not cve_data:
                continue
            record = nvd_cve_to_record(cve_data, civn_id=civn_id)
            if record and self._insert_record(record):
                inserted += 1
            time.sleep(0.8 if NVD_API_KEY else 6.5)

        return inserted

    def get_stats(self) -> dict:
        self.cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE source='CERT-IN'")
        cert_in_count = self.cursor.fetchone()[0]
        self.cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        total = self.cursor.fetchone()[0]
        return {"cert_in_count": cert_in_count, "total_count": total}

    def close(self):
        self.conn.close()

    # ── Private helpers ─────────────────────────────────────────────────────

    def _fetch_rss(self) -> list[dict]:
        """Fetch and parse the CERT-In RSS feed."""
        try:
            req = Request(CERT_IN_RSS, headers={"User-Agent": "SentryShield/1.0"})
            with urlopen(req, timeout=20) as resp:
                xml_text = resp.read().decode("utf-8", errors="replace")
            return self._rss_parser.parse(xml_text)
        except HTTPError as e:
            log.error("CERT-In RSS HTTP %d: %s", e.code, e.reason)
        except URLError as e:
            log.error("CERT-In RSS connection error: %s", e.reason)
        except Exception as e:
            log.error("CERT-In RSS fetch failed: %s", e)
        return []

    def _scrape_advisory(self, url: str) -> list[str]:
        """Scrape a CERT-In advisory HTML page and extract all CVE IDs."""
        try:
            req = Request(url, headers={"User-Agent": "SentryShield/1.0"})
            with urlopen(req, timeout=15) as resp:
                html = resp.read().decode("utf-8", errors="replace")

            parser = AdvisoryHTMLParser()
            parser.feed(html)
            cves = parser.get_cves()
            log.debug("Scraped %s → %d CVEs", url[:80], len(cves))
            return cves

        except HTTPError as e:
            log.warning("Advisory scrape HTTP %d: %s", e.code, url[:80])
        except URLError as e:
            log.warning("Advisory scrape connection error: %s", e.reason)
        except Exception as e:
            log.warning("Advisory scrape failed: %s — %s", url[:80], e)

        return []

    def _insert_record(self, record: dict) -> bool:
        """Insert a vulnerability record. Returns True if newly inserted."""
        sql = """
            INSERT OR IGNORE INTO vulnerabilities
                (id, product_name, affected_versions, cvss_score, severity,
                 description, remediation, source, first_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        try:
            self.cursor.execute(sql, (
                record["id"],
                record["product_name"],
                record["affected_versions"],
                record["cvss_score"],
                record["severity"],
                record["description"],
                record["remediation"],
                record["source"],
                record["first_seen"],
            ))
            self.conn.commit()
            return self.cursor.rowcount > 0
        except sqlite3.Error as e:
            log.warning("DB insert error for %s: %s", record.get("id"), e)
            return False


# ---------------------------------------------------------------------------
# NVD parsing helpers (shared with cert_parser.py logic)
# ---------------------------------------------------------------------------

def _extract_product_name_from_cve(cve: dict) -> str:
    try:
        for conf in cve.get("configurations", []):
            for node in conf.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe = match.get("criteria", "")
                    parts = cpe.split(":")
                    if len(parts) >= 5:
                        vendor  = parts[3].replace("_", " ").title()
                        product = parts[4].replace("_", " ").title()
                        return f"{vendor} {product}"
    except (IndexError, KeyError):
        pass
    return ""


def _extract_version_ranges_from_cve(cve: dict) -> list[dict]:
    """
    Extract version ranges. Handles both:
      - versionStartIncluding / versionEndIncluding  → include_min=True, include_max=True
      - versionStartExcluding / versionEndExcluding  → include_min=False, include_max=False
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

                    range_entry = {
                        "min":         v_start_inc or v_start_exc,
                        "max":         v_end_inc   or v_end_exc,
                        "include_min": v_start_inc is not None,  # True only for Including
                        "include_max": v_end_inc   is not None,  # True only for Including
                    }

                    if range_entry["min"] or range_entry["max"]:
                        ranges.append(range_entry)
    except (KeyError, TypeError):
        pass
    return ranges


def _extract_remediation_from_cve(cve: dict) -> str:
    for ref in cve.get("references", []):
        tags = ref.get("tags", [])
        if "Patch" in tags or "Vendor Advisory" in tags:
            return f"See: {ref.get('url', '')}"
    return "Apply latest vendor-supplied patch. Refer to NVD for details."


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:   return "CRITICAL"
    elif score >= 7.0: return "HIGH"
    elif score >= 4.0: return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="SentryShield CERT-In advisory parser — fetches live CVE data"
    )
    parser.add_argument("--db", required=True, help="Path to SQLite database")
    parser.add_argument(
        "--days-back", type=int, default=30,
        help="Sync advisories published in last N days (default: 30)"
    )
    parser.add_argument(
        "--advisory",
        help="Sync a single named advisory, e.g. CIVN-2024-0001"
    )
    parser.add_argument("--stats", action="store_true", help="Print DB stats and exit")
    parser.add_argument("--json-output", action="store_true", help="Output summary as JSON")

    args = parser.parse_args()

    if not Path(args.db).exists():
        log.error("Database not found: %s — run init_db.py first", args.db)
        sys.exit(1)

    cert_in = CERTInParser(args.db)

    if args.stats:
        stats = cert_in.get_stats()
        if args.json_output:
            print(json.dumps(stats))
        else:
            print(f"CERT-In records : {stats['cert_in_count']}")
            print(f"Total in DB     : {stats['total_count']}")
        cert_in.close()
        return

    if args.advisory:
        count = cert_in.sync_single_advisory(args.advisory)
        log.info("Advisory %s: %d new CVEs inserted", args.advisory, count)
        if args.json_output:
            print(json.dumps({"advisory": args.advisory, "inserted": count}))
    else:
        summary = cert_in.sync(days_back=args.days_back)
        if args.json_output:
            print(json.dumps(summary))

    cert_in.close()


if __name__ == "__main__":
    main()
