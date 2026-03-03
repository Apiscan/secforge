"""SecForge CLI — main entry point."""

import typer
from rich.console import Console

from secforge.cli.scan import scan_cmd
from secforge.cli.diff_cmd import diff_cmd
from secforge.cli.config_cmd import app as config_app

app = typer.Typer(
    name="secforge",
    help="🔐 SecForge — CLI-native API security scanner. Blackbox. Evidence-based. CI/CD-ready.",
    rich_markup_mode="rich",
    no_args_is_help=True,
)

console = Console()

app.command(name="scan", help="Run a security scan against a target")(scan_cmd)
app.command(name="diff", help="Compare two scan reports — track remediation progress")(diff_cmd)
app.add_typer(config_app, name="config", help="Manage target configuration profiles")


@app.callback()
def main():
    pass


if __name__ == "__main__":
    app()
