#!/usr/bin/env python3
"""
SecurityForge test suite — validates package structure, payload integrity, and CLI.

Run:
    pytest tests/test_package.py -v
"""
import json
import importlib
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
PKG = ROOT / "securityforge"
PAYLOADS = PKG / "payloads"


# ── Package structure ──────────────────────────────────────────────────

class TestPackageStructure:
    def test_package_importable(self):
        import securityforge
        assert hasattr(securityforge, "__version__")

    def test_version_format(self):
        import securityforge
        parts = securityforge.__version__.split(".")
        assert len(parts) == 3
        assert all(p.isdigit() for p in parts)

    def test_core_modules_importable(self):
        from securityforge.detector import WAFDetector
        from securityforge.tester import WAFTester
        from securityforge.cli import main
        assert callable(WAFDetector)
        assert callable(WAFTester)
        assert callable(main)

    def test_payloads_dir_exists(self):
        assert PAYLOADS.is_dir()

    def test_init_exports(self):
        import securityforge
        assert securityforge.__author__ == "DALI Security"
        assert securityforge.__license__ == "MIT"


# ── Payload integrity ──────────────────────────────────────────────────

class TestPayloads:
    def test_payload_categories_exist(self):
        categories = [d.name for d in sorted(PAYLOADS.iterdir()) if d.is_dir()]
        assert len(categories) >= 15, f"Expected 15+ categories, got {len(categories)}"
        for required in ["xss", "sqli", "ssrf", "ssti", "xxe", "ai_prompt_injection"]:
            assert required in categories, f"Missing required category: {required}"

    def test_all_json_payloads_valid(self):
        errors = []
        for json_file in sorted(PAYLOADS.rglob("*.json")):
            try:
                data = json.loads(json_file.read_text(encoding="utf-8"))
                assert isinstance(data, (dict, list)), f"{json_file.name}: root must be dict or list"
            except (json.JSONDecodeError, AssertionError) as e:
                errors.append(f"{json_file.relative_to(PAYLOADS)}: {e}")
        assert not errors, "Invalid JSON files:\n" + "\n".join(errors)

    def test_json_payloads_have_content(self):
        empty = []
        for json_file in sorted(PAYLOADS.rglob("*.json")):
            data = json.loads(json_file.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "payloads" in data:
                if len(data["payloads"]) == 0:
                    empty.append(str(json_file.relative_to(PAYLOADS)))
            elif isinstance(data, list) and len(data) == 0:
                empty.append(str(json_file.relative_to(PAYLOADS)))
        assert not empty, f"Empty payload files: {empty}"

    def test_txt_payloads_not_empty(self):
        empty = []
        for txt_file in sorted(PAYLOADS.rglob("*.txt")):
            content = txt_file.read_text(encoding="utf-8").strip()
            # Filter out comment-only lines
            lines = [l for l in content.splitlines() if l.strip() and not l.strip().startswith("#")]
            if len(lines) == 0:
                empty.append(str(txt_file.relative_to(PAYLOADS)))
        assert not empty, f"Empty txt payload files: {empty}"

    def test_payload_count_minimum(self):
        """Verify total payload count is at least 4000."""
        total = 0
        for json_file in PAYLOADS.rglob("*.json"):
            data = json.loads(json_file.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "payloads" in data:
                total += len(data["payloads"])
            elif isinstance(data, list):
                total += len(data)
        for txt_file in PAYLOADS.rglob("*.txt"):
            lines = [l for l in txt_file.read_text(encoding="utf-8").splitlines()
                     if l.strip() and not l.strip().startswith("#")]
            total += len(lines)
        assert total >= 4000, f"Expected 4000+ payloads, got {total}"

    def test_no_false_cve_claims(self):
        """Ensure no payload files falsely claim CVE-2026-28515/16/17 as WordPress."""
        for f in PAYLOADS.rglob("*"):
            if not f.is_file():
                continue
            content = f.read_text(encoding="utf-8", errors="ignore")
            for cve in ["CVE-2026-28515", "CVE-2026-28516", "CVE-2026-28517"]:
                if cve in content:
                    assert "WordPress" not in content.split(cve)[0][-200:], \
                        f"{f.name} falsely attributes {cve} to WordPress (it's an openDCIM CVE)"


# ── WAF Detector ───────────────────────────────────────────────────────

class TestWAFDetector:
    def test_detector_instantiation(self):
        from securityforge.detector import WAFDetector
        d = WAFDetector()
        assert hasattr(d, "detect_waf")
        assert hasattr(d, "print_results")
        assert hasattr(d, "waf_signatures")

    def test_detector_has_25_vendors(self):
        from securityforge.detector import WAFDetector
        d = WAFDetector()
        assert len(d.waf_signatures) >= 25, \
            f"Expected 25+ WAF vendors, got {len(d.waf_signatures)}"


# ── CLI ────────────────────────────────────────────────────────────────

class TestCLI:
    def _run(self, *args):
        result = subprocess.run(
            [sys.executable, "-m", "securityforge.cli", *args],
            capture_output=True, text=True, timeout=10
        )
        return result

    def test_help(self):
        r = self._run("--help")
        assert r.returncode == 0
        assert "SecurityForge" in r.stdout

    def test_version(self):
        r = self._run("version")
        assert r.returncode == 0
        assert "SecurityForge v" in r.stdout

    def test_payloads(self):
        r = self._run("payloads")
        assert r.returncode == 0
        assert "xss" in r.stdout
        assert "sqli" in r.stdout

    def test_detect_help(self):
        r = self._run("detect", "--help")
        assert r.returncode == 0
        assert "target" in r.stdout.lower()

    def test_test_help(self):
        r = self._run("test", "--help")
        assert r.returncode == 0
        assert "category" in r.stdout.lower() or "payload" in r.stdout.lower()

    def test_bad_category_exits_nonzero(self):
        r = self._run("test", "https://example.com", "-c", "nonexistent_xyz")
        assert r.returncode != 0

    def test_payloads_lists_categories(self):
        from securityforge.cli import list_categories
        cats = list_categories()
        assert isinstance(cats, list)
        assert "xss" in cats
        assert "sqli" in cats
