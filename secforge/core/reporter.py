"""
Report generation — JSON and Markdown output.

Every finding is evidence-backed. Reports clearly mark
CONFIRMED / PROBABLE / SPECULATIVE status on each item.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from secforge.models.finding import Finding
from secforge.models.enums import Severity, FindingStatus
from secforge.models.target import TargetConfig

console = Console()

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


class ScanResult:
    """Container for a completed scan's findings + metadata."""

    def __init__(self, target: TargetConfig, findings: list[Finding], duration_s: float = 0.0):
        self.target = target
        self.findings = sorted(findings, key=lambda f: f.severity.order)
        self.duration_s = duration_s
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.scanner_version = "0.1.0"

    @property
    def counts(self) -> dict[str, int]:
        return {
            sev.value: sum(1 for f in self.findings if f.severity == sev)
            for sev in SEVERITY_ORDER
        }

    @property
    def confirmed_count(self) -> int:
        return sum(1 for f in self.findings if f.status == FindingStatus.CONFIRMED)

    def has_findings_above(self, threshold: Severity) -> bool:
        return any(f.severity.order <= threshold.order for f in self.findings)


# ──────────────────────────────────────────────
# Terminal display
# ──────────────────────────────────────────────

def print_summary(result: ScanResult) -> None:
    """Print a rich summary table to the terminal."""
    counts = result.counts
    total = sum(counts.values())

    console.print()
    console.print(Panel(
        f"[bold]Target:[/bold] [cyan]{result.target.url}[/cyan]\n"
        f"[bold]Scan time:[/bold] {result.duration_s:.1f}s   "
        f"[bold]Findings:[/bold] {total}   "
        f"[bold]Confirmed:[/bold] {result.confirmed_count}",
        title="[bold]ApiScan Scan Complete[/bold]",
        border_style="green" if total == 0 else "yellow",
    ))

    if not result.findings:
        console.print("[green]✅ No findings detected.[/green]\n")
        return

    table = Table(box=box.ROUNDED, show_header=True, header_style="bold")
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Count", justify="right", width=8)
    table.add_column("Sample", style="dim")

    for sev in SEVERITY_ORDER:
        count = counts[sev.value]
        if count == 0:
            continue
        sample = next((f.title for f in result.findings if f.severity == sev), "")
        color = {"CRITICAL": "red", "HIGH": "orange1", "MEDIUM": "yellow",
                 "LOW": "blue", "INFO": "white"}[sev.value]
        table.add_row(
            f"[{color}]{sev.emoji} {sev.value}[/{color}]",
            f"[{color}]{count}[/{color}]",
            sample[:60],
        )

    console.print(table)
    console.print()

    for finding in result.findings:
        _print_finding(finding)


def _print_finding(f: Finding) -> None:
    color = {"CRITICAL": "red", "HIGH": "orange1", "MEDIUM": "yellow",
             "LOW": "blue", "INFO": "white"}[f.severity.value]
    status_color = {"CONFIRMED": "green", "PROBABLE": "yellow", "SPECULATIVE": "dim"}[f.status.value]

    console.print(Panel(
        f"[bold]{f.description}[/bold]\n\n"
        f"[dim]Status:[/dim] [{status_color}]{f.status}[/{status_color}]"
        + (f"   [dim]OWASP:[/dim] {f.owasp_id}" if f.owasp_id else "")
        + (f"   [dim]Endpoint:[/dim] {f.endpoint}" if f.endpoint else "")
        + (f"\n\n[bold]Remediation:[/bold] {f.remediation}" if f.remediation else "")
        + (f"\n\n[dim]Evidence: {len(f.evidence)} item(s)[/dim]" if f.evidence else ""),
        title=f"[{color}]{f.severity.emoji} {f.severity} — {f.title}[/{color}]",
        border_style=color,
    ))


# ──────────────────────────────────────────────
# JSON export
# ──────────────────────────────────────────────

def to_json(result: ScanResult, path: Optional[str] = None) -> str:
    """Serialize scan results to JSON. Optionally write to file."""
    data = {
        "scanner": "ApiScan",
        "version": result.scanner_version,
        "timestamp": result.timestamp,
        "duration_seconds": result.duration_s,
        "target": {
            "url": result.target.url,
            "name": result.target.name,
        },
        "summary": result.counts,
        "confirmed_count": result.confirmed_count,
        "findings": [
            {
                "title": f.title,
                "description": f.description,
                "severity": f.severity.value,
                "status": f.status.value,
                "owasp_id": f.owasp_id,
                "endpoint": f.endpoint,
                "plugin": f.plugin,
                "remediation": f.remediation,
                "references": f.references,
                "evidence": [
                    {
                        "method": e.request_method,
                        "url": e.request_url,
                        "response_status": e.response_status,
                        "note": e.note,
                    }
                    for e in f.evidence
                ],
            }
            for f in result.findings
        ],
    }
    output = json.dumps(data, indent=2)
    if path:
        Path(path).write_text(output)
        console.print(f"[green]✅ JSON report saved:[/green] {path}")
    return output


# ──────────────────────────────────────────────
# Markdown export
# ──────────────────────────────────────────────

def to_markdown(result: ScanResult, path: Optional[str] = None) -> str:
    """Generate a Markdown report. Optionally write to file."""
    lines: list[str] = []
    counts = result.counts
    total = sum(counts.values())

    lines += [
        f"# ApiScan Security Report",
        f"",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| **Target** | `{result.target.url}` |",
        f"| **Name** | {result.target.name or '—'} |",
        f"| **Scan Date** | {result.timestamp[:10]} |",
        f"| **Duration** | {result.duration_s:.1f}s |",
        f"| **Scanner** | ApiScan v{result.scanner_version} |",
        f"",
        f"## Summary",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
    ]

    for sev in SEVERITY_ORDER:
        lines.append(f"| {sev.emoji} **{sev.value}** | {counts[sev.value]} |")

    lines += [
        f"| **Total** | **{total}** |",
        f"",
        f"> **Confirmed exploited:** {result.confirmed_count} of {total}",
        f"",
        f"---",
        f"",
    ]

    if not result.findings:
        lines.append("## ✅ No Findings\n\nNo security issues were detected.\n")
    else:
        lines.append("## Findings\n")
        for f in result.findings:
            lines += _markdown_finding(f)

    lines += [
        f"---",
        f"",
        f"*Generated by [ApiScan](https://github.com/apiscan-ai/secforge) — "
        f"CLI-native API security scanner*",
    ]

    output = "\n".join(lines)
    if path:
        Path(path).write_text(output)
        console.print(f"[green]✅ Markdown report saved:[/green] {path}")
    return output


def _markdown_finding(f: Finding) -> list[str]:
    status_badges = {
        "CONFIRMED": "🟢 **CONFIRMED**",
        "PROBABLE": "🟡 **PROBABLE**",
        "SPECULATIVE": "⚪ **SPECULATIVE**",
    }
    lines = [
        f"### {f.severity.emoji} {f.severity} — {f.title}",
        f"",
        f"**Status:** {status_badges[f.status.value]}"
        + (f" | **OWASP:** {f.owasp_id}" if f.owasp_id else "")
        + (f" | **Endpoint:** `{f.endpoint}`" if f.endpoint else ""),
        f"",
        f"{f.description}",
        f"",
    ]

    if f.evidence:
        lines.append("**Evidence:**")
        lines.append("")
        for i, e in enumerate(f.evidence, 1):
            lines.append(f"{i}. {e.note}")
            if e.request_url:
                lines.append(f"   - Request: `{e.request_method} {e.request_url}`")
            if e.response_status:
                lines.append(f"   - Response: `HTTP {e.response_status}`")
            if e.response_body_snippet:
                lines.append(f"   - Body: `{e.response_body_snippet[:200]}`")
        lines.append("")

    if f.remediation:
        lines += [f"**Remediation:** {f.remediation}", f""]

    if f.references:
        lines.append("**References:**")
        for ref in f.references:
            lines.append(f"- {ref}")
        lines.append("")

    lines.append("---\n")
    return lines
