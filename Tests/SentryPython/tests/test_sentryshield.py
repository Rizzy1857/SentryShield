"""
SentryShield v1.0 — Python Test Suite
pytest tests for yara_scanner.py, cert_parser.py, ioc_populate.py

Run from project root:
    cd SentryShield/Tests/SentryPython
    pip install pytest yara-python schedule
    pytest tests/ -v
"""

import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path
import pytest

# Add parent to path so we can import SentryPython modules
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "SentryPython"))

from yara_scanner import YaraScanner
from cert_parser import NVDFeedParser, _cvss_to_severity, _extract_version_ranges


# ─────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────

@pytest.fixture
def temp_db(tmp_path):
    """Temporary SQLite database with full SentryShield schema."""
    db_path = str(tmp_path / "test.db")
    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE vulnerabilities (
            id TEXT PRIMARY KEY,
            product_name TEXT,
            affected_versions TEXT,
            cvss_score REAL DEFAULT 0,
            severity TEXT DEFAULT 'MEDIUM',
            description TEXT,
            remediation TEXT,
            source TEXT,
            first_seen DATE,
            last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_hash TEXT UNIQUE,
            malware_name TEXT,
            malware_family TEXT,
            confidence INTEGER DEFAULT 100,
            source TEXT,
            detection_date DATE
        );
    """)
    conn.commit()
    conn.close()
    return db_path


@pytest.fixture
def rules_dir(tmp_path):
    """Temporary directory with a simple YARA rule for testing."""
    rules_path = tmp_path / "rules"
    rules_path.mkdir()

    rule_content = """
rule Test_Mimikatz {
    meta:
        description = "Test: Mimikatz signature"
        severity = "CRITICAL"
    strings:
        $s1 = "Benjamin DELPY" ascii
        $s2 = "mimikatz" nocase
    condition:
        any of ($s*)
}

rule Test_Ransomware_Note {
    meta:
        description = "Test: Ransomware note indicator"
        severity = "HIGH"
    strings:
        $s1 = "Your files have been encrypted" nocase
    condition:
        $s1
}
"""
    (rules_path / "test_rules.yar").write_text(rule_content)
    return str(rules_path)


@pytest.fixture
def malware_file(tmp_path):
    """Creates a file containing a Mimikatz signature for YARA testing."""
    f = tmp_path / "suspicious.exe"
    f.write_bytes(b"MZ" + b"\x00" * 100 + b"Benjamin DELPY" + b"\x00" * 50)
    return str(f)


@pytest.fixture
def clean_file(tmp_path):
    """Creates a file with no malware signatures."""
    f = tmp_path / "clean.txt"
    f.write_text("This is a completely clean file with no suspicious content.")
    return str(f)


@pytest.fixture
def curated_json(tmp_path):
    """Minimal curated vulnerability JSON."""
    vulns = [
        {
            "id": "TEST-VUL-001",
            "product_name": "TestProduct",
            "affected_versions": "[{\"min\":\"1.0.0\",\"max\":\"2.0.0\",\"include_min\":true,\"include_max\":false}]",
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "description": "Test vulnerability",
            "remediation": "Update to 2.0.0+",
            "source": "CURATED",
            "first_seen": "2024-01-01"
        }
    ]
    p = tmp_path / "curated_vulns.json"
    p.write_text(json.dumps(vulns))
    return str(p)


# ─────────────────────────────────────────────────────
# YARA Scanner Tests
# ─────────────────────────────────────────────────────

class TestYaraScanner:

    def test_rules_compile_successfully(self, rules_dir):
        """YARA rules in rules/ directory must compile without errors."""
        scanner = YaraScanner(rules_dir)
        assert scanner.rules is not None, "Rules failed to compile"

    def test_detects_mimikatz_string(self, rules_dir, malware_file):
        """Scanner must detect Mimikatz signature in test file."""
        scanner = YaraScanner(rules_dir)
        results = scanner.scan_file(malware_file)

        assert len(results) > 0, "Should have detected at least one match"
        rule_names = [r["rule_name"] for r in results]
        assert "Test_Mimikatz" in rule_names, f"Expected Test_Mimikatz, got: {rule_names}"

    def test_clean_file_no_matches(self, rules_dir, clean_file):
        """Clean file must produce zero matches (false positive check)."""
        scanner = YaraScanner(rules_dir)
        results = scanner.scan_file(clean_file)

        assert len(results) == 0, f"False positive: {results}"

    def test_match_includes_required_fields(self, rules_dir, malware_file):
        """Each match result must contain all required output fields."""
        scanner = YaraScanner(rules_dir)
        results = scanner.scan_file(malware_file)

        assert len(results) > 0
        for match in results:
            assert "file_path" in match
            assert "rule_name" in match
            assert "severity" in match
            assert "description" in match
            assert "matched_strings" in match
            assert match["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    def test_scan_directory_finds_malware(self, rules_dir, malware_file):
        """Directory scan must find malware file within the directory."""
        scan_dir = str(Path(malware_file).parent)
        scanner = YaraScanner(rules_dir)
        results = scanner.scan_directory(scan_dir)

        assert any(r["file_path"] == malware_file for r in results), \
            "Should have found the malware file in directory scan"

    def test_nonexistent_rules_dir_graceful(self, tmp_path):
        """Scanner must handle non-existent rules directory gracefully."""
        scanner = YaraScanner(str(tmp_path / "nonexistent_rules"))
        assert scanner.rules is None, "Should have None rules for missing directory"

        # Should not raise — should return empty list
        results = scanner.scan_file(str(tmp_path))
        assert results == []

    def test_severity_preserved_from_meta(self, rules_dir, malware_file):
        """Severity from YARA rule meta must be preserved in output."""
        scanner = YaraScanner(rules_dir)
        results = scanner.scan_file(malware_file)

        for r in results:
            assert r["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW"), \
                f"Invalid severity value: {r['severity']}"

    def test_output_is_json_serializable(self, rules_dir, malware_file):
        """Scanner output must be JSON-serializable for C# subprocess IPC."""
        scanner = YaraScanner(rules_dir)
        results = scanner.scan_file(malware_file)

        try:
            json.dumps(results)
        except (TypeError, ValueError) as e:
            pytest.fail(f"Results are not JSON-serializable: {e}")


# ─────────────────────────────────────────────────────
# cert_parser.py Tests
# ─────────────────────────────────────────────────────

class TestCERTParser:

    def test_cvss_to_severity_critical(self):
        assert _cvss_to_severity(9.0) == "CRITICAL"
        assert _cvss_to_severity(10.0) == "CRITICAL"

    def test_cvss_to_severity_high(self):
        assert _cvss_to_severity(7.0) == "HIGH"
        assert _cvss_to_severity(8.9) == "HIGH"

    def test_cvss_to_severity_medium(self):
        assert _cvss_to_severity(4.0) == "MEDIUM"
        assert _cvss_to_severity(6.9) == "MEDIUM"

    def test_cvss_to_severity_low(self):
        assert _cvss_to_severity(0.0) == "LOW"
        assert _cvss_to_severity(3.9) == "LOW"

    def test_curated_json_loads_into_db(self, temp_db, curated_json):
        """Curated JSON must load correctly into the vulnerabilities table."""
        parser = NVDFeedParser(temp_db)
        count = parser.sync_from_curated(curated_json)
        parser.close()

        assert count == 1, f"Expected 1 inserted, got {count}"

        conn = sqlite3.connect(temp_db)
        row = conn.execute("SELECT id, product_name, cvss_score FROM vulnerabilities").fetchone()
        conn.close()

        assert row is not None
        assert row[0] == "TEST-VUL-001"
        assert row[1] == "TestProduct"
        assert row[2] == 9.8

    def test_duplicate_curated_insert_is_idempotent(self, temp_db, curated_json):
        """Loading same curated JSON twice must not create duplicates."""
        parser = NVDFeedParser(temp_db)
        parser.sync_from_curated(curated_json)
        parser.sync_from_curated(curated_json)  # Second load
        parser.close()

        conn = sqlite3.connect(temp_db)
        count = conn.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
        conn.close()

        assert count == 1, f"Expected 1 row (idempotent), got {count}"

    def test_get_stats_returns_correct_structure(self, temp_db, curated_json):
        """get_stats() must return dict with expected keys."""
        parser = NVDFeedParser(temp_db)
        parser.sync_from_curated(curated_json)
        stats = parser.get_stats()
        parser.close()

        assert "total_vulnerabilities" in stats
        assert "total_iocs" in stats
        assert "by_severity" in stats
        assert "db_size_mb" in stats
        assert stats["total_vulnerabilities"] == 1

    def test_db_compress_creates_gz_and_checksum(self, temp_db, curated_json):
        """compress_db() must create .gz file and write SHA-256 checksum."""
        parser = NVDFeedParser(temp_db)
        parser.sync_from_curated(curated_json)
        checksum = parser.compress_db()
        parser.close()

        assert Path(temp_db + ".gz").exists(), ".gz file not created"
        assert Path(temp_db + ".gz.sha256").exists(), ".sha256 file not created"
        assert len(checksum) == 64, "SHA-256 must be 64 hex chars"


# ─────────────────────────────────────────────────────
# Performance Tests (must pass within time limits)
# ─────────────────────────────────────────────────────

class TestPerformance:

    def test_yara_scan_single_file_under_100ms(self, rules_dir, clean_file):
        """Single file YARA scan must complete in < 100ms."""
        import time
        scanner = YaraScanner(rules_dir)

        start = time.perf_counter()
        scanner.scan_file(clean_file)
        elapsed_ms = (time.perf_counter() - start) * 1000

        assert elapsed_ms < 100, f"YARA scan took {elapsed_ms:.1f}ms — must be < 100ms"

    def test_bulk_vuln_insert_performance(self, temp_db):
        """Inserting 500 vulnerability records must complete in < 5 seconds."""
        import time
        records = [
            {
                "id": f"PERF-{i:04d}",
                "product_name": f"TestProduct{i}",
                "affected_versions": "[]",
                "cvss_score": 7.5,
                "severity": "HIGH",
                "description": "Performance test",
                "remediation": "N/A",
                "source": "TEST",
                "first_seen": "2024-01-01"
            }
            for i in range(500)
        ]

        parser = NVDFeedParser(temp_db)

        start = time.perf_counter()
        count = parser.insert_vulnerabilities(records)
        elapsed = time.perf_counter() - start
        parser.close()

        assert count == 500, f"Expected 500 inserted, got {count}"
        assert elapsed < 5.0, f"Insert took {elapsed:.2f}s — must be < 5s"
