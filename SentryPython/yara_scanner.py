"""
SentryShield v1.0 — YARA Scanner (yara_scanner.py)
Week 3 deliverable

Compiles YARA rules from rules/ directory and scans files/directories.
Outputs JSON to stdout for C# subprocess IPC consumption.

Usage:
    python yara_scanner.py --scan-dir C:\\SentryShield\\Downloads\\ --rules C:\\SentryShield\\rules\\ --json
    python yara_scanner.py --scan-file C:\\path\\to\\file.exe --rules C:\\SentryShield\\rules\\ --json

Output (JSON array written to stdout):
    [
      {
        "file_path": "C:\\..\\file.exe",
        "rule_name": "Mimikatz_Credential_Dumper",
        "severity": "CRITICAL",
        "description": "Mimikatz credential extraction tool",
        "matched_strings": ["Benjamin DELPY", "mimikatz"]
      },
      ...
    ]
    
Exits 0 on success (even with 0 matches), 1 on YARA compilation error.
"""

import argparse
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import Optional

try:
    import yara
except ImportError:
    print(json.dumps({"error": "yara-python not installed. Run: pip install yara-python"}))
    sys.exit(1)

logging.basicConfig(
    level=logging.WARNING,   # Quiet by default — only print JSON to stdout
    format="[%(asctime)s] %(levelname)s %(message)s",
    stream=sys.stderr        # All logs go to stderr, JSON goes to stdout
)
log = logging.getLogger("yara_scanner")


# ---------------------------------------------------------------------------
# YARA rule compiler + scanner
# ---------------------------------------------------------------------------

class YaraScanner:
    def __init__(self, rules_path: str, verbose: bool = False):
        self.rules_path = Path(rules_path)
        self.verbose = verbose
        self.rules: Optional[yara.Rules] = None
        self.rule_count = 0
        self._compile_rules()

    def _compile_rules(self):
        """
        Compile all .yar / .yara files in the rules directory into a single
        compiled ruleset for fast repeated scanning.
        """
        rule_files = list(self.rules_path.glob("*.yar")) + \
                     list(self.rules_path.glob("*.yara"))

        if not rule_files:
            log.error("No YARA rule files found in: %s", self.rules_path)
            self.rules = None
            return

        # Build filepaths dict for yara.compile (handles multiple files cleanly)
        filepaths = {f.stem: str(f) for f in rule_files}

        try:
            self.rules = yara.compile(filepaths=filepaths)
            self.rule_count = len(rule_files)
            log.info("Compiled %d YARA rule file(s) from %s", self.rule_count, self.rules_path)
        except yara.SyntaxError as e:
            log.error("YARA syntax error: %s", e)
            self.rules = None
        except Exception as e:
            log.error("YARA compilation failed: %s", e)
            self.rules = None

    def scan_file(self, file_path: str, timeout: int = 10) -> list[dict]:
        """
        Scan a single file. Returns list of match dicts.
        timeout: per-file scan timeout in seconds (prevents stalling on large files).
        """
        if not self.rules:
            return []

        results = []
        try:
            matches = self.rules.match(file_path, timeout=timeout)
            for match in matches:
                # Extract matched string values (first 5, truncated to 100 chars)
                matched_strings = []
                for string_match in match.strings[:5]:
                    for instance in string_match.instances[:3]:
                        try:
                            decoded = instance.matched_data.decode("utf-8", errors="replace")
                            matched_strings.append(decoded[:100])
                        except Exception:
                            matched_strings.append("<binary>")

                results.append({
                    "file_path": file_path,
                    "rule_name": match.rule,
                    "severity": match.meta.get("severity", "MEDIUM"),
                    "description": match.meta.get("description", ""),
                    "author": match.meta.get("author", "SentryShield"),
                    "matched_strings": matched_strings[:5]
                })

        except yara.TimeoutError:
            log.warning("YARA scan timed out on: %s", file_path)
        except yara.Error as e:
            log.warning("YARA scan error on %s: %s", file_path, e)
        except PermissionError:
            log.debug("Permission denied: %s", file_path)
        except Exception as e:
            log.warning("Unexpected error scanning %s: %s", file_path, e)

        return results

    def scan_directory(
        self,
        dir_path: str,
        max_file_size_mb: float = 50.0,
        extensions: Optional[list[str]] = None
    ) -> list[dict]:
        """
        Recursively scan all files in a directory.

        max_file_size_mb: Skip files larger than this (avoids stalling on ISOs, etc.)
        extensions: If set, only scan files with these extensions (e.g. ['.exe', '.dll'])
        """
        if not self.rules:
            return []

        all_results = []
        dir_path = Path(dir_path)
        max_bytes = int(max_file_size_mb * 1024 * 1024)

        file_list = list(dir_path.rglob("*"))
        total = sum(1 for f in file_list if f.is_file())
        scanned = 0
        skipped = 0

        log.info("Scanning %d files in %s", total, dir_path)

        for file_path in file_list:
            if not file_path.is_file():
                continue

            # Extension filter
            if extensions and file_path.suffix.lower() not in extensions:
                continue

            # Size filter
            try:
                if file_path.stat().st_size > max_bytes:
                    log.debug("Skipping large file: %s", file_path)
                    skipped += 1
                    continue
            except OSError:
                continue

            matches = self.scan_file(str(file_path))
            all_results.extend(matches)
            scanned += 1

            if self.verbose and scanned % 50 == 0:
                log.info("Progress: %d/%d scanned, %d matches so far",
                         scanned, total, len(all_results))

        log.info("Scan complete: %d files scanned, %d skipped, %d matches",
                 scanned, skipped, len(all_results))

        return all_results

    def get_rule_names(self) -> list[str]:
        """Return list of compiled rule names (for diagnostics)."""
        if not self.rules:
            return []
        # yara.Rules doesn't expose names directly; we'd need to track during compile
        # Return count info instead
        return [f"[{self.rule_count} rule files compiled]"]


# ---------------------------------------------------------------------------
# Benchmark / performance test
# ---------------------------------------------------------------------------

def benchmark(scanner: YaraScanner, test_dir: str, iterations: int = 3):
    """Quick benchmark: time scans over the test directory."""
    times = []
    for i in range(iterations):
        start = time.perf_counter()
        results = scanner.scan_directory(test_dir)
        elapsed = time.perf_counter() - start
        times.append(elapsed)
        log.warning("Run %d: %.2fs, %d matches", i + 1, elapsed, len(results))

    avg = sum(times) / len(times)
    log.warning("Average scan time: %.2fs over %d runs", avg, iterations)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="SentryShield YARA scanner — outputs JSON to stdout"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--scan-dir", help="Directory to scan recursively")
    group.add_argument("--scan-file", help="Single file to scan")

    parser.add_argument("--rules", required=True, help="Path to YARA rules directory")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--verbose", action="store_true", help="Verbose progress logging")
    parser.add_argument(
        "--max-size-mb", type=float, default=50.0,
        help="Skip files larger than this (MB). Default: 50"
    )
    parser.add_argument(
        "--ext", nargs="*",
        help="Only scan files with these extensions (e.g. .exe .dll .ps1)"
    )
    parser.add_argument(
        "--benchmark", action="store_true",
        help="Run benchmark (3 scan iterations)"
    )

    args = parser.parse_args()

    scanner = YaraScanner(args.rules, verbose=args.verbose)

    if not scanner.rules:
        error = {"error": "YARA rule compilation failed", "rules_path": args.rules}
        if args.json:
            print(json.dumps(error))
        else:
            print("ERROR:", error["error"], file=sys.stderr)
        sys.exit(1)

    if args.benchmark and args.scan_dir:
        benchmark(scanner, args.scan_dir)
        return

    if args.scan_dir:
        results = scanner.scan_directory(
            args.scan_dir,
            max_file_size_mb=args.max_size_mb,
            extensions=args.ext
        )
    else:
        results = scanner.scan_file(args.scan_file)

    if args.json:
        print(json.dumps(results, indent=None, ensure_ascii=False))
    else:
        if not results:
            print("No YARA matches found.")
        for r in results:
            print(f"[{r['severity']}] {r['rule_name']} → {r['file_path']}")
            print(f"  {r['description']}")
            if r["matched_strings"]:
                print(f"  Strings: {', '.join(r['matched_strings'][:3])}")
            print()


if __name__ == "__main__":
    main()
