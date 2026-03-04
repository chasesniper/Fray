#!/usr/bin/env python3
"""
Fray Bounty — Bug Bounty Platform Integration

Usage:
    fray bounty --platform hackerone --program <handle>
    fray bounty --platform bugcrowd --program <handle>
    fray bounty --urls urls.txt
    fray bounty --program <handle> --categories xss,sqli --max 20

Integrates with HackerOne and Bugcrowd APIs to:
    1. Fetch program scope (in-scope URLs/domains)
    2. Auto-detect WAF on each target
    3. Run payload tests across scope
    4. Generate consolidated bounty report

API Keys (set via environment variables):
    HACKERONE_API_TOKEN   — HackerOne API token
    HACKERONE_API_USER    — HackerOne API username
    BUGCROWD_API_TOKEN    — Bugcrowd API token

Zero external dependencies — stdlib only.
"""

import http.client
import json
import os
import re
import ssl
import sys
import base64
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from fray import __version__, PAYLOADS_DIR


class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    END = '\033[0m'


# ── API Clients (stdlib only) ────────────────────────────────────────────────

class HackerOneAPI:
    """HackerOne API v1 client using stdlib."""

    API_HOST = "api.hackerone.com"

    def __init__(self, username: str, token: str):
        self.auth = base64.b64encode(f"{username}:{token}".encode()).decode()
        self.headers = {
            "Authorization": f"Basic {self.auth}",
            "Accept": "application/json",
            "User-Agent": f"Fray/{__version__}",
        }

    def _request(self, method: str, path: str) -> Tuple[int, Dict]:
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(self.API_HOST, 443, context=ctx, timeout=30)
        conn.request(method, path, headers=self.headers)
        resp = conn.getresponse()
        data = resp.read().decode("utf-8", errors="replace")
        conn.close()
        try:
            return resp.status, json.loads(data)
        except json.JSONDecodeError:
            return resp.status, {"raw": data[:500]}

    def get_program_scope(self, handle: str) -> Tuple[bool, List[Dict]]:
        """Fetch in-scope assets for a program."""
        path = f"/v1/hackers/programs/{handle}"
        status, data = self._request("GET", path)

        if status != 200:
            msg = data.get("errors", [{}])[0].get("title", "") if isinstance(data.get("errors"), list) else ""
            return False, [{"error": msg or f"HTTP {status}"}]

        scopes = []
        relationships = data.get("data", {}).get("relationships", {})
        structured_scopes = relationships.get("structured_scopes", {}).get("data", [])

        for scope in structured_scopes:
            attrs = scope.get("attributes", {})
            if attrs.get("eligible_for_submission", True):
                asset_type = attrs.get("asset_type", "")
                identifier = attrs.get("asset_identifier", "")
                instruction = attrs.get("instruction", "")
                if asset_type in ("URL", "DOMAIN", "WILDCARD"):
                    scopes.append({
                        "type": asset_type,
                        "identifier": identifier,
                        "instruction": instruction[:100] if instruction else "",
                        "eligible": True,
                    })

        return True, scopes


class BugcrowdAPI:
    """Bugcrowd API client using stdlib."""

    API_HOST = "api.bugcrowd.com"

    def __init__(self, token: str):
        self.headers = {
            "Authorization": f"Token {token}",
            "Accept": "application/vnd.bugcrowd+json",
            "User-Agent": f"Fray/{__version__}",
        }

    def _request(self, method: str, path: str) -> Tuple[int, Dict]:
        ctx = ssl.create_default_context()
        conn = http.client.HTTPSConnection(self.API_HOST, 443, context=ctx, timeout=30)
        conn.request(method, path, headers=self.headers)
        resp = conn.getresponse()
        data = resp.read().decode("utf-8", errors="replace")
        conn.close()
        try:
            return resp.status, json.loads(data)
        except json.JSONDecodeError:
            return resp.status, {"raw": data[:500]}

    def get_program_scope(self, handle: str) -> Tuple[bool, List[Dict]]:
        """Fetch in-scope targets for a program."""
        path = f"/programs/{handle}/target_groups"
        status, data = self._request("GET", path)

        if status != 200:
            return False, [{"error": f"HTTP {status}"}]

        scopes = []
        for group in data.get("data", []):
            targets = group.get("relationships", {}).get("targets", {}).get("data", [])
            for target in targets:
                attrs = target.get("attributes", {})
                name = attrs.get("name", "")
                uri = attrs.get("uri", "")
                category = attrs.get("category", "")
                if category in ("website", "api", "domain"):
                    scopes.append({
                        "type": category.upper(),
                        "identifier": uri or name,
                        "instruction": "",
                        "eligible": True,
                    })

        return True, scopes


# ── URL Extraction & Normalization ───────────────────────────────────────────

def normalize_scope_to_urls(scopes: List[Dict]) -> List[str]:
    """Convert scope entries to testable URLs."""
    urls = []
    for scope in scopes:
        identifier = scope.get("identifier", "").strip()
        if not identifier:
            continue

        # Skip wildcard-only entries
        if identifier in ("*", "*."):
            continue

        # Handle wildcard domains: *.example.com → https://example.com
        if identifier.startswith("*."):
            identifier = identifier[2:]

        # Add scheme if missing
        if not identifier.startswith(("http://", "https://")):
            identifier = f"https://{identifier}"

        # Clean up trailing paths
        parsed = urllib.parse.urlparse(identifier)
        if parsed.hostname:
            url = f"{parsed.scheme}://{parsed.hostname}"
            if parsed.port and parsed.port not in (80, 443):
                url += f":{parsed.port}"
            urls.append(url)

    return sorted(set(urls))


def load_urls_from_file(filepath: str) -> List[str]:
    """Load URLs from a text file (one per line)."""
    urls = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    if not line.startswith(("http://", "https://")):
                        line = f"https://{line}"
                    urls.append(line)
    except (FileNotFoundError, OSError) as e:
        print(f"{Colors.RED}Error reading {filepath}: {e}{Colors.END}")
    return urls


# ── Bounty Testing ───────────────────────────────────────────────────────────

def scan_target(url: str, categories: List[str], max_payloads: int = 10,
                timeout: int = 8, delay: float = 0.5) -> Dict:
    """Run WAF detection and payload tests on a single target."""
    result = {
        "url": url,
        "waf": None,
        "waf_confidence": 0,
        "categories": {},
        "total_tested": 0,
        "total_blocked": 0,
        "total_passed": 0,
        "block_rate": 0.0,
    }

    # WAF detection
    try:
        from fray.detector import WAFDetector
        detector = WAFDetector()
        detection = detector.detect_waf(url)
        result["waf"] = detection.get("waf", "None")
        result["waf_confidence"] = detection.get("confidence", 0)
    except Exception as e:
        result["waf"] = f"Error: {e}"

    # Payload tests per category
    from fray.tester import WAFTester
    for cat in categories:
        cat_dir = PAYLOADS_DIR / cat
        if not cat_dir.exists():
            continue

        tester = WAFTester(target=url, timeout=timeout, delay=delay)
        all_payloads = []
        for pf in sorted(cat_dir.glob("*.json")):
            all_payloads.extend(tester.load_payloads(str(pf)))

        if not all_payloads:
            continue

        results = tester.test_payloads(all_payloads, max_payloads=max_payloads)
        blocked = sum(1 for r in results if r.get("blocked"))
        passed = len(results) - blocked
        rate = (blocked / len(results) * 100) if results else 0.0

        bypassed = [
            {"payload": r.get("payload", "")[:80], "status": r.get("status_code", 0)}
            for r in results if not r.get("blocked")
        ]

        result["categories"][cat] = {
            "total": len(results),
            "blocked": blocked,
            "passed": passed,
            "block_rate": round(rate, 1),
            "bypassed": bypassed,
        }
        result["total_tested"] += len(results)
        result["total_blocked"] += blocked
        result["total_passed"] += passed

    if result["total_tested"] > 0:
        result["block_rate"] = round(result["total_blocked"] / result["total_tested"] * 100, 1)

    return result


# ── Report ───────────────────────────────────────────────────────────────────

def print_bounty_report(targets: List[Dict], program: str, platform: str):
    """Print formatted bounty test report."""
    print(f"\n{Colors.DIM}{'━' * 65}{Colors.END}")
    print(f"\n  {Colors.BOLD}Fray Bug Bounty Report{Colors.END}")
    print(f"  {Colors.DIM}Program: {program} ({platform}){Colors.END}")
    print(f"  {Colors.DIM}{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}{Colors.END}")
    print(f"  {Colors.DIM}Fray v{__version__}{Colors.END}")

    # Per-target summary
    print(f"\n  {Colors.BOLD}Target Results{Colors.END}")
    print(f"  {'Target':<35} {'WAF':<16} {'Block Rate':>10} {'Bypassed':>10}")
    print(f"  {'─' * 71}")

    total_bypassed = 0
    interesting_targets = []

    for t in targets:
        waf = t.get("waf", "None") or "None"
        rate = t.get("block_rate", 0.0)
        passed = t.get("total_passed", 0)
        total_bypassed += passed

        rc = Colors.GREEN if rate >= 95 else (Colors.YELLOW if rate >= 80 else Colors.RED)
        url_short = t["url"][:33] + ".." if len(t["url"]) > 35 else t["url"]
        waf_short = waf[:14] + ".." if len(waf) > 16 else waf

        print(f"  {url_short:<35} {waf_short:<16} {rc}{rate:>9.1f}%{Colors.END} {passed:>10}")

        if passed > 0:
            interesting_targets.append(t)

    # Bypass details
    if interesting_targets:
        print(f"\n  {Colors.RED}{Colors.BOLD}Potential Findings{Colors.END}")
        for t in interesting_targets:
            print(f"\n  {Colors.CYAN}{t['url']}{Colors.END} — {t.get('waf', 'Unknown')} WAF")
            for cat, cr in t.get("categories", {}).items():
                if cr.get("passed", 0) > 0:
                    print(f"    {Colors.RED}{cat}:{Colors.END} {cr['passed']} bypass(es)")
                    for bp in cr.get("bypassed", [])[:3]:
                        print(f"      Status {bp.get('status', '?')}: {bp.get('payload', '')[:60]}")

    # Summary
    total_tested = sum(t.get("total_tested", 0) for t in targets)
    total_blocked = sum(t.get("total_blocked", 0) for t in targets)
    overall_rate = (total_blocked / total_tested * 100) if total_tested > 0 else 0

    print(f"\n  {Colors.DIM}{'─' * 65}{Colors.END}")
    print(f"  {Colors.BOLD}Summary{Colors.END}")
    print(f"  Targets scanned:  {len(targets)}")
    print(f"  Payloads tested:  {total_tested}")
    print(f"  Overall block:    {overall_rate:.1f}%")
    print(f"  Total bypasses:   {Colors.RED if total_bypassed > 0 else Colors.GREEN}"
          f"{total_bypassed}{Colors.END}")
    print(f"\n{Colors.DIM}{'━' * 65}{Colors.END}\n")


# ── Entry Point ──────────────────────────────────────────────────────────────

def run_bounty(
    platform: Optional[str] = None,
    program: Optional[str] = None,
    urls_file: Optional[str] = None,
    categories: Optional[List[str]] = None,
    max_payloads: int = 10,
    timeout: int = 8,
    delay: float = 0.5,
    output: Optional[str] = None,
):
    """Main entry point for fray bounty."""
    print(f"\n{Colors.BOLD}Fray Bounty v{__version__}{Colors.END}")
    print(f"{Colors.DIM}{'━' * 60}{Colors.END}")

    test_categories = categories or ["xss", "sqli"]
    # Filter to existing categories
    available = [d.name for d in PAYLOADS_DIR.iterdir() if d.is_dir() and not d.name.startswith(".")]
    test_categories = [c for c in test_categories if c in available]

    urls: List[str] = []

    # ── Fetch scope from platform API ────────────────────────────────────
    if urls_file:
        print(f"  Loading URLs from: {urls_file}")
        urls = load_urls_from_file(urls_file)
        platform = platform or "file"
        program = program or urls_file

    elif platform and program:
        platform = platform.lower()
        print(f"  Platform: {platform}")
        print(f"  Program:  {program}")

        if platform == "hackerone":
            username = os.environ.get("HACKERONE_API_USER", "")
            token = os.environ.get("HACKERONE_API_TOKEN", "")
            if not username or not token:
                print(f"\n  {Colors.RED}Error: HackerOne credentials not set.{Colors.END}")
                print(f"  {Colors.DIM}Set environment variables:{Colors.END}")
                print(f"    export HACKERONE_API_USER=your_username")
                print(f"    export HACKERONE_API_TOKEN=your_api_token")
                print(f"  {Colors.DIM}Get your token at: https://hackerone.com/settings/api_token/edit{Colors.END}\n")
                return

            print(f"{Colors.DIM}  Fetching scope from HackerOne...{Colors.END}")
            api = HackerOneAPI(username, token)
            ok, scopes = api.get_program_scope(program)
            if not ok:
                err = scopes[0].get("error", "Unknown error") if scopes else "Unknown error"
                print(f"  {Colors.RED}Failed to fetch scope: {err}{Colors.END}")
                return

            urls = normalize_scope_to_urls(scopes)
            print(f"  {Colors.GREEN}Found {len(scopes)} scope entries → {len(urls)} testable URL(s){Colors.END}")

            if scopes:
                print(f"\n  {Colors.BOLD}In-Scope Assets:{Colors.END}")
                for s in scopes[:15]:
                    print(f"    {s['type']:<10} {s['identifier']}")
                if len(scopes) > 15:
                    print(f"    ... and {len(scopes) - 15} more")

        elif platform == "bugcrowd":
            token = os.environ.get("BUGCROWD_API_TOKEN", "")
            if not token:
                print(f"\n  {Colors.RED}Error: Bugcrowd API token not set.{Colors.END}")
                print(f"  {Colors.DIM}Set environment variable:{Colors.END}")
                print(f"    export BUGCROWD_API_TOKEN=your_api_token")
                print(f"  {Colors.DIM}Get your token at: https://bugcrowd.com/settings/api{Colors.END}\n")
                return

            print(f"{Colors.DIM}  Fetching scope from Bugcrowd...{Colors.END}")
            api = BugcrowdAPI(token)
            ok, scopes = api.get_program_scope(program)
            if not ok:
                err = scopes[0].get("error", "Unknown error") if scopes else "Unknown error"
                print(f"  {Colors.RED}Failed to fetch scope: {err}{Colors.END}")
                return

            urls = normalize_scope_to_urls(scopes)
            print(f"  {Colors.GREEN}Found {len(scopes)} scope entries → {len(urls)} testable URL(s){Colors.END}")

        else:
            print(f"  {Colors.RED}Unknown platform: {platform}{Colors.END}")
            print(f"  {Colors.DIM}Supported: hackerone, bugcrowd{Colors.END}")
            return
    else:
        print(f"  {Colors.RED}Provide --platform + --program, or --urls file{Colors.END}")
        print(f"  {Colors.DIM}Examples:{Colors.END}")
        print(f"    fray bounty --platform hackerone --program github")
        print(f"    fray bounty --platform bugcrowd --program tesla")
        print(f"    fray bounty --urls targets.txt")
        return

    if not urls:
        print(f"\n  {Colors.YELLOW}No testable URLs found in scope.{Colors.END}\n")
        return

    print(f"\n  {Colors.BOLD}Testing {len(urls)} target(s) × {len(test_categories)} categories × {max_payloads} payloads{Colors.END}")
    print(f"  {Colors.DIM}Categories: {', '.join(test_categories)}{Colors.END}\n")

    # ── Run tests ────────────────────────────────────────────────────────
    all_results = []
    for i, url in enumerate(urls, 1):
        print(f"  {Colors.DIM}[{i}/{len(urls)}]{Colors.END} {Colors.CYAN}{url}{Colors.END}")
        result = scan_target(url, test_categories, max_payloads=max_payloads,
                             timeout=timeout, delay=delay)
        all_results.append(result)

        waf = result.get("waf", "None") or "None"
        rate = result.get("block_rate", 0.0)
        rc = Colors.GREEN if rate >= 95 else (Colors.YELLOW if rate >= 80 else Colors.RED)
        print(f"    WAF: {waf} | Block rate: {rc}{rate:.1f}%{Colors.END}")

    # ── Report ───────────────────────────────────────────────────────────
    print_bounty_report(all_results, program, platform)

    # Save output
    if output:
        report = {
            "platform": platform,
            "program": program,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "fray_version": __version__,
            "categories": test_categories,
            "targets": all_results,
        }
        with open(output, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"  {Colors.GREEN}Report saved: {output}{Colors.END}\n")
