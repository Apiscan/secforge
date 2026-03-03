"""
`secforge scan` command — orchestrates the full scan pipeline.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from secforge.core.config import load_target, load_target_from_url
from secforge.core.scope import enforce_scope
from secforge.core.scope_file import ScopeFile, SCOPE_FILE_TEMPLATE
from secforge.core.client import SecForgeClient
from secforge.core.reporter import ScanResult, print_summary, to_json, to_markdown
from secforge.core.html_report import to_html
from secforge.core.ai_triage import triage_findings
from secforge.models.enums import Severity
from secforge.plugins import ALL_PLUGINS, DEFAULT_PLUGINS

console = Console()


def scan_cmd(
    url: Optional[str] = typer.Argument(None, help="Target URL (e.g. https://api.example.com)"),
    profile: Optional[Path] = typer.Option(None, "--profile", "-p", help="Target profile YAML"),
    plugins: Optional[str] = typer.Option(
        None, "--plugins",
        help=f"Comma-separated plugin list. Available: {', '.join(ALL_PLUGINS)}. Default: all"
    ),
    output: str = typer.Option("terminal", "--output", "-o", help="Output format: terminal | json | markdown | all"),
    out_file: Optional[Path] = typer.Option(None, "--out", help="Output file path"),
    fail_on: Optional[str] = typer.Option(
        None, "--fail-on",
        help="Exit code 1 if any finding at or above this severity (CRITICAL|HIGH|MEDIUM|LOW)"
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip authorization prompt (requires scope.authorized=true in profile)"),
    no_verify: bool = typer.Option(False, "--no-verify", help="Disable SSL certificate verification"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
    scope_file: Optional[Path] = typer.Option(None, "--scope-file", help="YAML scope file for CI/CD pre-authorization"),
    ai_triage: bool = typer.Option(False, "--ai-triage", help="Run AI-powered finding analysis (requires ANTHROPIC_API_KEY)"),
    ai_model: str = typer.Option("claude-haiku-4-5", "--ai-model", help="AI model to use for triage"),
):
    """
    Run a security scan against an API target.

    Examples:

      secforge scan https://api.example.com

      secforge scan --profile ./targets/myapi.yaml --output markdown --out report.md

      secforge scan https://api.example.com --plugins tls,headers --fail-on HIGH
    """
    # ── 1. Load target config ─────────────────────────────────────────────
    if profile:
        try:
            target = load_target(profile)
        except FileNotFoundError as e:
            console.print(f"[red]❌ {e}[/red]")
            raise typer.Exit(1)
    elif url:
        target = load_target_from_url(url)
    else:
        console.print("[red]❌ Provide a URL or --profile.[/red]")
        console.print("  Example: [cyan]secforge scan https://api.example.com[/cyan]")
        raise typer.Exit(1)

    # Override from CLI flags
    if url and profile:
        target.url = url  # CLI URL takes precedence
    if no_verify:
        target.options.verify_ssl = False

    # ── 2a. Scope file — CI/CD pre-authorization ──────────────────────────
    if scope_file:
        try:
            sf = ScopeFile(scope_file)
            if not sf.authorize_target(target):
                console.print(f"[red]❌ Target {target.url!r} is not in the scope file: {scope_file}[/red]")
                console.print("[dim]Add it to the scope file or use --yes with scope.authorized=true.[/dim]")
                raise typer.Exit(1)
            console.print(f"[green]✅ Scope file authorized:[/green] {target.url}")
            yes = True  # Skip interactive prompt
        except FileNotFoundError as e:
            console.print(f"[red]❌ {e}[/red]")
            raise typer.Exit(1)

    # ── 2b. Interactive scope enforcement ─────────────────────────────────
    if not enforce_scope(target, skip_prompt=yes):
        raise typer.Exit(1)

    # ── 3. Resolve plugins ────────────────────────────────────────────────
    if plugins:
        selected_names = [p.strip() for p in plugins.split(",")]
        unknown = [n for n in selected_names if n not in ALL_PLUGINS]
        if unknown:
            console.print(f"[red]❌ Unknown plugins: {', '.join(unknown)}[/red]")
            console.print(f"   Available: {', '.join(ALL_PLUGINS)}")
            raise typer.Exit(1)
    else:
        selected_names = DEFAULT_PLUGINS

    plugin_instances = [ALL_PLUGINS[n]() for n in selected_names]

    console.print(
        f"\n[bold]🔐 SecForge[/bold] scanning [cyan]{target.url}[/cyan]\n"
        f"[dim]Plugins: {', '.join(selected_names)}[/dim]\n"
    )

    # ── 4. Run scan ───────────────────────────────────────────────────────
    findings = asyncio.run(_run_scan(target, plugin_instances, verbose))

    # ── 5. Build result ───────────────────────────────────────────────────
    result = ScanResult(target, findings)

    # ── 5a. AI Triage (optional) ──────────────────────────────────────────
    if ai_triage and findings:
        console.print("[dim]🤖 Running AI triage...[/dim]")
        triage = asyncio.run(triage_findings(result, model=ai_model))
        if triage.skipped:
            console.print(f"[yellow]⚠️  AI triage skipped: {triage.skip_reason}[/yellow]")
        else:
            result = ScanResult(target, triage.findings, result.duration_s)
            if triage.executive_summary:
                console.print()
                from rich.panel import Panel as RPanel
                console.print(RPanel(
                    triage.executive_summary,
                    title="[bold cyan]🤖 AI Executive Summary[/bold cyan]",
                    border_style="cyan",
                ))
            if triage.top_risks:
                console.print("\n[bold cyan]🎯 Top Risks by Exploitability:[/bold cyan]")
                for r in triage.top_risks:
                    console.print(
                        f"  #{r.get('rank')} [bold]{r.get('title')}[/bold]\n"
                        f"     Why: {r.get('why', '')}\n"
                        f"     Blast radius: {r.get('blast_radius', '')}"
                    )
            if triage.false_positives:
                console.print(f"\n[yellow]🔍 AI flagged {len(triage.false_positives)} likely false positive(s) → marked SPECULATIVE[/yellow]")

    # ── 6. Output ─────────────────────────────────────────────────────────
    fmt = output.lower()

    if fmt in ("terminal", "all"):
        print_summary(result)

    if fmt in ("json", "all"):
        path = str(out_file) if out_file else None
        if fmt == "all" and not out_file:
            path = f"secforge-report-{int(time.time())}.json"
        to_json(result, path)
        if fmt == "json" and not out_file:
            import json
            from secforge.core.reporter import to_json as tj
            console.print(tj(result))

    if fmt in ("markdown", "all"):
        path = str(out_file) if out_file else None
        if fmt == "all" and not out_file:
            path = f"secforge-report-{int(time.time())}.md"
        md = to_markdown(result, path)
        if fmt == "markdown" and not out_file:
            console.print(md)

    if fmt in ("html", "all"):
        path = str(out_file) if out_file else None
        if fmt == "all" and not out_file:
            path = f"secforge-report-{int(time.time())}.html"
        elif fmt == "html" and out_file and not str(out_file).endswith(".html"):
            path = str(out_file) + ".html"
        to_html(result, path)
        if fmt == "html" and not out_file:
            console.print(to_html(result))

    # ── 7. Exit code for CI/CD ────────────────────────────────────────────
    if fail_on:
        try:
            threshold = Severity(fail_on.upper())
            if result.has_findings_above(threshold):
                console.print(
                    f"[red]❌ CI/CD gate: findings at or above {threshold} detected.[/red]"
                )
                raise typer.Exit(1)
        except ValueError:
            console.print(f"[red]❌ Invalid --fail-on value: {fail_on}[/red]")
            raise typer.Exit(1)


async def _run_scan(target, plugin_instances, verbose: bool) -> list:
    """Execute all plugins concurrently and collect findings."""
    all_findings = []

    async with SecForgeClient(target) as client:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(
                f"[cyan]Running {len(plugin_instances)} plugin(s)…",
                total=len(plugin_instances),
            )

            async def run_plugin(plugin):
                if verbose:
                    console.print(f"  [dim]→ {plugin.name}: {plugin.description}[/dim]")
                try:
                    results = await plugin.run(target, client)
                    progress.advance(task)
                    return results
                except Exception as e:
                    console.print(f"[yellow]⚠️  Plugin {plugin.name} failed: {e}[/yellow]")
                    progress.advance(task)
                    return []

            results = await asyncio.gather(*[run_plugin(p) for p in plugin_instances])
            for r in results:
                all_findings.extend(r)

    return all_findings
