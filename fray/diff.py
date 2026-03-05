#!/usr/bin/env python3
"""
Fray Diff — Compare two scan results and surface regressions.

Usage:
    fray diff before.json after.json
    fray diff before.json after.json --json
    fray diff before.json after.json -o diff_report.json

Compares two Fray scan results (from `fray bypass --output` or `fray test`)
and highlights:
  - Regressions: payloads that were BLOCKED before but BYPASS now
  - Improvements: payloads that BYPASSED before but are BLOCKED now
  - Score changes, strictness changes, new/removed blocked patterns
  - Summary verdict: PASS / REGRESSED / IMPROVED

Designed for WAF config change validation in CI/CD pipelines.
"""

import json
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Tuple


@dataclass
class DiffResult:
    """Result of comparing two scan reports."""
    # Metadata
    before_file: str = ""
    after_file: str = ""
    target: str = ""
    before_timestamp: str = ""
    after_timestamp: str = ""

    # Verdict: PASS, REGRESSED, IMPROVED, MIXED
    verdict: str = ""

    # Score delta
    before_score: float = 0.0
    after_score: float = 0.0
    score_delta: float = 0.0

    # Bypass rate delta
    before_bypass_rate: float = 0.0
    after_bypass_rate: float = 0.0
    bypass_rate_delta: float = 0.0

    # Strictness change
    before_strictness: str = ""
    after_strictness: str = ""

    # Stat deltas
    before_total_tested: int = 0
    after_total_tested: int = 0
    before_total_blocked: int = 0
    after_total_blocked: int = 0
    before_total_bypassed: int = 0
    after_total_bypassed: int = 0

    # Regressions: payloads blocked before → bypass now
    regressions: List[Dict] = field(default_factory=list)

    # Improvements: payloads bypassed before → blocked now
    improvements: List[Dict] = field(default_factory=list)

    # New bypasses (payload not in before scan at all)
    new_bypasses: List[Dict] = field(default_factory=list)

    # WAF profile changes
    new_blocked_tags: List[str] = field(default_factory=list)
    removed_blocked_tags: List[str] = field(default_factory=list)
    new_blocked_events: List[str] = field(default_factory=list)
    removed_blocked_events: List[str] = field(default_factory=list)
    new_blocked_keywords: List[str] = field(default_factory=list)
    removed_blocked_keywords: List[str] = field(default_factory=list)


def _normalize_report(data: dict) -> dict:
    """Normalize both bypass scorecard and test result formats into a common shape."""
    # Bypass scorecard format (from `fray bypass --output`)
    if "overall_evasion_score" in data:
        total = data.get("total_tested", 0) + data.get("mutations_tested", 0)
        bypassed = data.get("total_bypassed", 0) + data.get("mutations_bypassed", 0)
        blocked = total - bypassed

        # Build payload→status map from bypasses list
        payload_map = {}
        for bp in data.get("bypasses", []):
            payload_map[bp.get("payload", "")] = {
                "blocked": False,
                "status": bp.get("status", 0),
                "evasion_score": bp.get("evasion_score", 0),
                "technique": bp.get("technique", ""),
                "reflected": bp.get("reflected", False),
            }

        return {
            "format": "bypass",
            "target": data.get("target", ""),
            "timestamp": data.get("timestamp", ""),
            "score": data.get("overall_evasion_score", 0.0),
            "strictness": data.get("waf_strictness", ""),
            "total_tested": total,
            "total_blocked": blocked,
            "total_bypassed": bypassed,
            "bypass_rate": (bypassed / total * 100) if total > 0 else 0.0,
            "blocked_tags": set(data.get("blocked_tags", [])),
            "blocked_events": set(data.get("blocked_events", [])),
            "blocked_keywords": set(data.get("blocked_keywords", [])),
            "payload_map": payload_map,
        }

    # Test result format (from `fray test`)
    if "results" in data:
        results = data["results"]
    elif isinstance(data, list):
        results = data
    else:
        results = []

    total = len(results)
    bypassed = sum(1 for r in results if not r.get("blocked", True))
    blocked = total - bypassed

    payload_map = {}
    for r in results:
        p = r.get("payload", "")
        payload_map[p] = {
            "blocked": r.get("blocked", True),
            "status": r.get("status", 0),
            "evasion_score": 0.0,
            "technique": "",
            "reflected": r.get("reflected", False),
        }

    return {
        "format": "test",
        "target": data.get("target", ""),
        "timestamp": data.get("timestamp", ""),
        "score": 0.0,
        "strictness": "",
        "total_tested": total,
        "total_blocked": blocked,
        "total_bypassed": bypassed,
        "bypass_rate": (bypassed / total * 100) if total > 0 else 0.0,
        "blocked_tags": set(),
        "blocked_events": set(),
        "blocked_keywords": set(),
        "payload_map": payload_map,
    }


def run_diff(before_path: str, after_path: str) -> DiffResult:
    """Compare two scan result files and return a DiffResult.

    Args:
        before_path: Path to the baseline ("before") scan JSON
        after_path: Path to the new ("after") scan JSON

    Returns:
        DiffResult with regressions, improvements, and verdict
    """
    with open(before_path, "r", encoding="utf-8") as f:
        before_raw = json.load(f)
    with open(after_path, "r", encoding="utf-8") as f:
        after_raw = json.load(f)

    before = _normalize_report(before_raw)
    after = _normalize_report(after_raw)

    result = DiffResult(
        before_file=before_path,
        after_file=after_path,
        target=after.get("target", before.get("target", "")),
        before_timestamp=before.get("timestamp", ""),
        after_timestamp=after.get("timestamp", ""),
        before_score=before["score"],
        after_score=after["score"],
        score_delta=round(after["score"] - before["score"], 1),
        before_bypass_rate=round(before["bypass_rate"], 1),
        after_bypass_rate=round(after["bypass_rate"], 1),
        bypass_rate_delta=round(after["bypass_rate"] - before["bypass_rate"], 1),
        before_strictness=before["strictness"],
        after_strictness=after["strictness"],
        before_total_tested=before["total_tested"],
        after_total_tested=after["total_tested"],
        before_total_blocked=before["total_blocked"],
        after_total_blocked=after["total_blocked"],
        before_total_bypassed=before["total_bypassed"],
        after_total_bypassed=after["total_bypassed"],
    )

    # WAF profile changes (bypass format only)
    result.new_blocked_tags = sorted(after["blocked_tags"] - before["blocked_tags"])
    result.removed_blocked_tags = sorted(before["blocked_tags"] - after["blocked_tags"])
    result.new_blocked_events = sorted(after["blocked_events"] - before["blocked_events"])
    result.removed_blocked_events = sorted(before["blocked_events"] - after["blocked_events"])
    result.new_blocked_keywords = sorted(after["blocked_keywords"] - before["blocked_keywords"])
    result.removed_blocked_keywords = sorted(before["blocked_keywords"] - after["blocked_keywords"])

    # Payload-level comparison
    before_map = before["payload_map"]
    after_map = after["payload_map"]

    for payload, after_info in after_map.items():
        if payload in before_map:
            before_info = before_map[payload]
            # Regression: was blocked → now bypasses
            if before_info["blocked"] and not after_info["blocked"]:
                result.regressions.append({
                    "payload": payload[:80],
                    "before_status": before_info["status"],
                    "after_status": after_info["status"],
                    "evasion_score": after_info.get("evasion_score", 0),
                    "technique": after_info.get("technique", ""),
                    "reflected": after_info.get("reflected", False),
                })
            # Improvement: was bypass → now blocked
            elif not before_info["blocked"] and after_info["blocked"]:
                result.improvements.append({
                    "payload": payload[:80],
                    "before_status": before_info["status"],
                    "after_status": after_info["status"],
                })
        else:
            # New bypass not in before scan
            if not after_info["blocked"]:
                result.new_bypasses.append({
                    "payload": payload[:80],
                    "status": after_info["status"],
                    "evasion_score": after_info.get("evasion_score", 0),
                    "technique": after_info.get("technique", ""),
                })

    # Verdict
    if result.regressions and not result.improvements:
        result.verdict = "REGRESSED"
    elif result.improvements and not result.regressions:
        result.verdict = "IMPROVED"
    elif result.regressions and result.improvements:
        result.verdict = "MIXED"
    elif result.score_delta > 0.5:
        result.verdict = "REGRESSED"
    elif result.score_delta < -0.5:
        result.verdict = "IMPROVED"
    else:
        result.verdict = "PASS"

    # Sort regressions by score (worst first)
    result.regressions.sort(key=lambda r: r.get("evasion_score", 0), reverse=True)

    return result


class _Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    CYAN = '\033[96m'


def _verdict_badge(verdict: str):
    """Create a rich Text badge for the verdict."""
    from rich.text import Text
    style_map = {
        "REGRESSED": "bold white on red",
        "IMPROVED": "bold white on green",
        "MIXED": "bold white on yellow",
        "PASS": "bold white on green",
    }
    return Text(f" {verdict} ", style=style_map.get(verdict, "bold"))


def _delta_rich(val: float, suffix: str = "", higher_is_worse: bool = True) -> str:
    """Format a delta value with rich markup (green=better, red=worse)."""
    if val == 0:
        return "[dim]±0" + suffix + "[/dim]"
    sign = "+" if val > 0 else ""
    color = "red" if (val > 0 and higher_is_worse) or (val < 0 and not higher_is_worse) else "green"
    return f"[{color}]{sign}{val}{suffix}[/{color}]"


def print_diff(diff: DiffResult) -> None:
    """Print a formatted diff report with rich output."""
    from fray.output import console, print_header, make_summary_table
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    print_header("Fray Diff — Scan Comparison", target=diff.target)

    # ── Summary panel ──
    tbl = make_summary_table()
    tbl.add_row("Before", diff.before_file)
    tbl.add_row("After", diff.after_file)
    tbl.add_row("Verdict", _verdict_badge(diff.verdict))

    if diff.before_score or diff.after_score:
        tbl.add_row("Evasion Score",
                     f"{diff.before_score} → {diff.after_score}  {_delta_rich(diff.score_delta)}")
    tbl.add_row("Bypass Rate",
                 f"{diff.before_bypass_rate}% → {diff.after_bypass_rate}%  {_delta_rich(diff.bypass_rate_delta, '%')}")
    tbl.add_row("Tested", f"{diff.before_total_tested} → {diff.after_total_tested}")
    blocked_delta = diff.after_total_blocked - diff.before_total_blocked
    tbl.add_row("Blocked",
                 f"{diff.before_total_blocked} → {diff.after_total_blocked}  {_delta_rich(blocked_delta, '', higher_is_worse=False)}")
    bypassed_delta = diff.after_total_bypassed - diff.before_total_bypassed
    tbl.add_row("Bypassed",
                 f"{diff.before_total_bypassed} → {diff.after_total_bypassed}  {_delta_rich(bypassed_delta, '')}")

    if diff.before_strictness and diff.after_strictness and diff.before_strictness != diff.after_strictness:
        tbl.add_row("Strictness", f"{diff.before_strictness} → {diff.after_strictness}")

    console.print(Panel(tbl, border_style="bright_cyan", expand=False))

    # ── WAF profile changes ──
    profile_changes = (diff.new_blocked_tags or diff.removed_blocked_tags or
                       diff.new_blocked_events or diff.removed_blocked_events or
                       diff.new_blocked_keywords or diff.removed_blocked_keywords)
    if profile_changes:
        console.print()
        console.print("  [bold cyan]WAF Profile Changes:[/bold cyan]")
        if diff.new_blocked_tags:
            console.print(f"    [green]+ Now blocking tags:[/green] {', '.join(diff.new_blocked_tags)}")
        if diff.removed_blocked_tags:
            console.print(f"    [red]- No longer blocking tags:[/red] {', '.join(diff.removed_blocked_tags)}")
        if diff.new_blocked_events:
            console.print(f"    [green]+ Now blocking events:[/green] {', '.join(diff.new_blocked_events)}")
        if diff.removed_blocked_events:
            console.print(f"    [red]- No longer blocking events:[/red] {', '.join(diff.removed_blocked_events)}")
        if diff.new_blocked_keywords:
            console.print(f"    [green]+ Now blocking keywords:[/green] {', '.join(diff.new_blocked_keywords)}")
        if diff.removed_blocked_keywords:
            console.print(f"    [red]- No longer blocking keywords:[/red] {', '.join(diff.removed_blocked_keywords)}")

    # ── Regressions table ──
    if diff.regressions:
        reg_table = Table(title=f"⚠ Regressions ({len(diff.regressions)} payloads now bypass)",
                          show_lines=False, box=None, pad_edge=False,
                          title_style="bold red")
        reg_table.add_column("#", style="dim", width=3, justify="right")
        reg_table.add_column("Status", width=12)
        reg_table.add_column("Payload", min_width=40)

        for i, reg in enumerate(diff.regressions[:10], 1):
            reflected = " [yellow]REFLECTED[/yellow]" if reg.get("reflected") else ""
            technique = f" [dim][{reg['technique']}][/dim]" if reg.get("technique") else ""
            reg_table.add_row(
                str(i),
                f"{reg['before_status']} → {reg['after_status']}",
                f"[dim]{reg['payload']}[/dim]{technique}{reflected}",
            )
        if len(diff.regressions) > 10:
            reg_table.add_row("", "", f"[dim]... and {len(diff.regressions) - 10} more[/dim]")

        console.print()
        console.print(Panel(reg_table, border_style="red", expand=False))

    # ── Improvements table ──
    if diff.improvements:
        imp_table = Table(title=f"✓ Improvements ({len(diff.improvements)} payloads now blocked)",
                          show_lines=False, box=None, pad_edge=False,
                          title_style="bold green")
        imp_table.add_column("#", style="dim", width=3, justify="right")
        imp_table.add_column("Status", width=12)
        imp_table.add_column("Payload", min_width=40)

        for i, imp in enumerate(diff.improvements[:10], 1):
            imp_table.add_row(
                str(i),
                f"{imp['before_status']} → {imp['after_status']}",
                f"[dim]{imp['payload']}[/dim]",
            )
        if len(diff.improvements) > 10:
            imp_table.add_row("", "", f"[dim]... and {len(diff.improvements) - 10} more[/dim]")

        console.print()
        console.print(Panel(imp_table, border_style="green", expand=False))

    # ── New bypasses ──
    if diff.new_bypasses:
        console.print()
        console.print(f"  [bold yellow]New bypasses ({len(diff.new_bypasses)} not in baseline):[/bold yellow]")
        for i, nb in enumerate(diff.new_bypasses[:5], 1):
            technique = f" [dim][{nb['technique']}][/dim]" if nb.get("technique") else ""
            console.print(f"    {i}. status {nb['status']}{technique}")
            console.print(f"       [dim]{nb['payload']}[/dim]")
        if len(diff.new_bypasses) > 5:
            console.print(f"    [dim]... and {len(diff.new_bypasses) - 5} more[/dim]")

    if not diff.regressions and not diff.improvements and not diff.new_bypasses:
        console.print()
        console.print("  [green]No payload-level changes detected.[/green]")

    console.print()
    console.rule(style="dim")
