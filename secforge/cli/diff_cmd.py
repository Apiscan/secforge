"""
`secforge diff` — compare two JSON scan reports.

Shows what was fixed, what's new, and what persists between scans.
Useful for CI/CD gates and tracking remediation progress over time.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()


def diff_cmd(
    before: Path = typer.Argument(..., help="Earlier scan report (JSON)"),
    after: Path = typer.Argument(..., help="Later scan report (JSON)"),
    output: str = typer.Option("terminal", "--output", "-o", help="Output: terminal | json | markdown"),
    out_file: Optional[Path] = typer.Option(None, "--out", help="Output file path"),
    fail_on_new: bool = typer.Option(False, "--fail-on-new", help="Exit 1 if new findings introduced"),
):
    """
    Compare two SecForge scan reports and show what changed.

    Example:
      secforge diff reports/before.json reports/after.json
    """
    before_data = _load(before)
    after_data = _load(after)

    before_findings = {_fingerprint(f): f for f in before_data.get("findings", [])}
    after_findings = {_fingerprint(f): f for f in after_data.get("findings", [])}

    fixed = {k: v for k, v in before_findings.items() if k not in after_findings}
    new = {k: v for k, v in after_findings.items() if k not in before_findings}
    persists = {k: v for k, v in after_findings.items() if k in before_findings}

    diff = {
        "before": {"target": before_data.get("target", {}), "timestamp": before_data.get("timestamp", ""),
                   "total": sum(before_data.get("summary", {}).values())},
        "after": {"target": after_data.get("target", {}), "timestamp": after_data.get("timestamp", ""),
                  "total": sum(after_data.get("summary", {}).values())},
        "fixed": list(fixed.values()),
        "new": list(new.values()),
        "persists": list(persists.values()),
        "score": {
            "fixed_count": len(fixed),
            "new_count": len(new),
            "persists_count": len(persists),
            "net_change": len(new) - len(fixed),
        },
    }

    fmt = output.lower()

    if fmt in ("terminal", "all"):
        _print_diff(diff)

    if fmt in ("json", "all"):
        out = json.dumps(diff, indent=2)
        if out_file:
            Path(out_file).write_text(out)
            console.print(f"[green]✅ Diff saved:[/green] {out_file}")
        else:
            console.print(out)

    if fmt in ("markdown", "all"):
        md = _to_markdown_diff(diff)
        if out_file:
            p = str(out_file) if str(out_file).endswith(".md") else str(out_file) + ".md"
            Path(p).write_text(md)
            console.print(f"[green]✅ Markdown diff saved:[/green] {p}")
        else:
            console.print(md)

    if fail_on_new and new:
        console.print(f"[red]❌ {len(new)} new finding(s) introduced — CI gate failed.[/red]")
        raise typer.Exit(1)


def _load(path: Path) -> dict:
    if not path.exists():
        console.print(f"[red]❌ File not found: {path}[/red]")
        raise typer.Exit(1)
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as e:
        console.print(f"[red]❌ Invalid JSON in {path}: {e}[/red]")
        raise typer.Exit(1)


def _fingerprint(finding: dict) -> str:
    """Stable identifier for a finding across scans."""
    return f"{finding.get('plugin', '')}::{finding.get('title', '')}::{finding.get('endpoint', '')}"


def _print_diff(diff: dict) -> None:
    before = diff["before"]
    after = diff["after"]
    score = diff["score"]

    net = score["net_change"]
    net_color = "green" if net < 0 else ("red" if net > 0 else "yellow")
    net_str = f"{'−' if net < 0 else '+' if net > 0 else ''}{abs(net)}"

    console.print()
    console.print(Panel(
        f"[bold]Before:[/bold] [dim]{before['timestamp'][:10]}[/dim] — {before['total']} findings\n"
        f"[bold]After: [/bold] [dim]{after['timestamp'][:10]}[/dim] — {after['total']} findings\n\n"
        f"[green]✅ Fixed: {score['fixed_count']}[/green]   "
        f"[red]🆕 New: {score['new_count']}[/red]   "
        f"[yellow]⏳ Persists: {score['persists_count']}[/yellow]   "
        f"[{net_color}]Net: {net_str}[/{net_color}]",
        title="[bold]SecForge Diff Report[/bold]",
        border_style="cyan",
    ))

    if diff["fixed"]:
        console.print("\n[bold green]✅ FIXED[/bold green]\n")
        for f in sorted(diff["fixed"], key=lambda x: x.get("severity", "INFO")):
            _sev = f.get("severity", "INFO")
            console.print(f"  [green]✓[/green] [{_sev}] {f.get('title', '')} — [dim]{f.get('endpoint', '')}[/dim]")

    if diff["new"]:
        console.print("\n[bold red]🆕 NEW FINDINGS[/bold red]\n")
        for f in sorted(diff["new"], key=lambda x: x.get("severity", "INFO")):
            _sev = f.get("severity", "INFO")
            color = {"CRITICAL": "red", "HIGH": "orange1", "MEDIUM": "yellow",
                     "LOW": "blue", "INFO": "white"}.get(_sev, "white")
            console.print(f"  [{color}]! [{_sev}] {f.get('title', '')} — {f.get('endpoint', '')}[/{color}]")

    if diff["persists"]:
        console.print("\n[bold yellow]⏳ STILL OPEN[/bold yellow]\n")
        for f in sorted(diff["persists"], key=lambda x: x.get("severity", "INFO")):
            _sev = f.get("severity", "INFO")
            console.print(f"  [yellow]→[/yellow] [{_sev}] {f.get('title', '')} — [dim]{f.get('endpoint', '')}[/dim]")

    console.print()


def _to_markdown_diff(diff: dict) -> str:
    score = diff["score"]
    before = diff["before"]
    after = diff["after"]
    net = score["net_change"]
    net_str = f"{'−' if net < 0 else '+' if net > 0 else ''}{abs(net)}" if net != 0 else "0"

    lines = [
        "# SecForge Diff Report",
        "",
        f"| | Before | After |",
        f"|--|--|--|",
        f"| **Scan date** | {before['timestamp'][:10]} | {after['timestamp'][:10]} |",
        f"| **Total findings** | {before['total']} | {after['total']} |",
        f"| **Net change** | | {net_str} |",
        "",
        f"✅ **Fixed:** {score['fixed_count']}  |  🆕 **New:** {score['new_count']}  |  ⏳ **Persists:** {score['persists_count']}",
        "",
        "---",
        "",
    ]

    if diff["fixed"]:
        lines += ["## ✅ Fixed\n"]
        for f in diff["fixed"]:
            lines.append(f"- [{f.get('severity')}] **{f.get('title')}** — `{f.get('endpoint', '')}`")
        lines.append("")

    if diff["new"]:
        lines += ["## 🆕 New Findings\n"]
        for f in diff["new"]:
            lines.append(f"- [{f.get('severity')}] **{f.get('title')}** — `{f.get('endpoint', '')}`")
        lines.append("")

    if diff["persists"]:
        lines += ["## ⏳ Still Open\n"]
        for f in diff["persists"]:
            lines.append(f"- [{f.get('severity')}] **{f.get('title')}** — `{f.get('endpoint', '')}`")
        lines.append("")

    return "\n".join(lines)
