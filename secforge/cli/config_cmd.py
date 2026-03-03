"""
`secforge config` subcommand — target profile management.
"""

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.syntax import Syntax

from secforge.core.config import DEFAULT_PROFILE, save_profile
from secforge.core.scope_file import SCOPE_FILE_TEMPLATE
from secforge.plugins import ALL_PLUGINS

app = typer.Typer(no_args_is_help=True)
console = Console()


@app.command("init")
def config_init(
    path: Path = typer.Argument(Path("targets/target.yaml"), help="Output path for the profile"),
    url: Optional[str] = typer.Option(None, "--url", help="Pre-fill the target URL"),
    name: Optional[str] = typer.Option(None, "--name", help="Pre-fill the target name"),
):
    """Generate a new target profile template."""
    content = DEFAULT_PROFILE
    if url:
        content = content.replace("https://api.example.com", url)
    if name:
        content = content.replace('"My API"', f'"{name}"')

    if path.exists():
        overwrite = typer.confirm(f"⚠️  {path} already exists — overwrite?", default=False)
        if not overwrite:
            raise typer.Exit(0)

    save_profile(path, content)
    console.print(f"[green]✅ Profile created:[/green] {path}")
    console.print(f"\nEdit it, then run:\n  [cyan]secforge scan --profile {path}[/cyan]\n")


@app.command("show")
def config_show(
    path: Path = typer.Argument(..., help="Path to the target profile YAML"),
):
    """Display a target profile with syntax highlighting."""
    if not path.exists():
        console.print(f"[red]❌ Not found: {path}[/red]")
        raise typer.Exit(1)

    content = path.read_text()
    console.print(Syntax(content, "yaml", theme="monokai", line_numbers=True))


@app.command("scope")
def config_scope(
    path: Path = typer.Argument(Path("scope.yml"), help="Output path for the scope file"),
):
    """Generate a scope file template for CI/CD pre-authorization."""
    if path.exists():
        overwrite = typer.confirm(f"⚠️  {path} already exists — overwrite?", default=False)
        if not overwrite:
            raise typer.Exit(0)
    path.write_text(SCOPE_FILE_TEMPLATE)
    console.print(f"[green]✅ Scope file created:[/green] {path}")
    console.print(f"\nEdit it, then scan with:\n  [cyan]secforge scan --scope-file {path} https://api.example.com[/cyan]\n")


@app.command("plugins")
def config_plugins():
    """List all available scan plugins."""
    console.print("\n[bold]Available Plugins:[/bold]\n")
    for name, cls in ALL_PLUGINS.items():
        instance = cls()
        owasp = f"  [dim]{instance.owasp_id}[/dim]" if instance.owasp_id else ""
        console.print(f"  [cyan]{name}[/cyan] — {instance.description}{owasp}")
    console.print()
