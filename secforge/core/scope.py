"""
Scope enforcement — authorization acknowledgment before any scan.

This is non-negotiable. SecForge will never scan a target without
explicit authorization from the operator. Built in from day one.
"""

from __future__ import annotations

import sys
from datetime import date
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt

from secforge.models.target import TargetConfig, ScopeConfig

console = Console()


SCOPE_BANNER = """[bold red]⚠️  AUTHORIZATION REQUIRED[/bold red]

SecForge performs active security testing that may:
  • Generate unusual traffic patterns
  • Trigger security alerts and WAF rules
  • Temporarily affect target availability
  • Leave traces in server logs

[bold]You must have explicit, written authorization from the owner
of the target system before proceeding.[/bold]

Unauthorized scanning is illegal under laws including:
  • Computer Fraud and Abuse Act (CFAA) — US
  • Computer Misuse Act — UK
  • Cybercrime laws in your jurisdiction

SecForge is not responsible for unauthorized use."""


def enforce_scope(target: TargetConfig, skip_prompt: bool = False) -> bool:
    """
    Check scope authorization. Returns True if authorized to proceed.
    
    If skip_prompt=True and scope.authorized=True in config, skips the
    interactive prompt (for CI/CD use).
    """
    if target.scope.authorized and skip_prompt:
        _log_scope(target)
        return True

    console.print(Panel(SCOPE_BANNER, border_style="red"))
    console.print(f"\n[bold]Target:[/bold] [cyan]{target.url}[/cyan]")

    if target.scope.authorized and target.scope.acknowledged_by:
        console.print(
            f"[green]✓ Authorization on record:[/green] "
            f"{target.scope.acknowledged_by} on {target.scope.date or 'unspecified date'}"
        )
        if target.scope.notes:
            console.print(f"[dim]Note: {target.scope.notes}[/dim]")
        console.print()
    else:
        console.print("\n[yellow]No authorization found in target profile.[/yellow]\n")

    confirmed = Confirm.ask(
        "[bold]Do you confirm you have explicit written authorization to test this target?[/bold]",
        default=False,
    )

    if not confirmed:
        console.print("\n[red]❌ Scan aborted — authorization not confirmed.[/red]")
        console.print("[dim]Configure scope.authorized in your target profile or confirm interactively.[/dim]\n")
        return False

    if not target.scope.acknowledged_by:
        name = Prompt.ask("Your name (for audit trail)", default="")
        target.scope.acknowledged_by = name
        target.scope.date = str(date.today())

    console.print(
        f"\n[green]✅ Authorization confirmed by {target.scope.acknowledged_by} "
        f"on {target.scope.date}[/green]\n"
    )
    return True


def _log_scope(target: TargetConfig) -> None:
    console.print(
        f"[green]✅ Scope: authorized[/green] "
        f"(acknowledged by [bold]{target.scope.acknowledged_by}[/bold] "
        f"on {target.scope.date})"
    )
