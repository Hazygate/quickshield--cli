from __future__ import annotations
from pathlib import Path
from typing import Optional
import typer
from . import __version__
from .config import write_default_config, load_config, basic_validate

# Let the root command run without a subcommand (so --version works)
app = typer.Typer(no_args_is_help=True, add_completion=False, help="QuickShield CE CLI")

@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Optional[bool] = typer.Option(
        None, "--version", "-V", help="Show version and exit.", is_eager=True
    ),
):
    if version:
        typer.echo(f"quickshield {__version__}")
        raise typer.Exit()

@app.command(help="Create a starter quickshield.yml in the current directory.")
def init(
    path: Path = typer.Option(
        Path("quickshield.yml"),
        "--path", "-p",
        help="Where to write the config file.",
        show_default=True,
    )
):
    if path.exists():
        typer.secho(f"Refusing to overwrite existing {path}", fg="yellow")
        raise typer.Exit(code=1)
    write_default_config(path)
    typer.secho(f"Created {path}", fg="green")

@app.command(help="Validate quickshield.yml and print any issues.")
def validate(
    path: Path = typer.Option(
        Path("quickshield.yml"), "--path", "-p", help="Path to config file."
    )
):
    if not path.exists():
        typer.secho(f"Config not found: {path}", fg="red")
        raise typer.Exit(code=1)
    try:
        cfg = load_config(path)
    except Exception as e:
        typer.secho(f"Failed to parse YAML: {e}", fg="red")
        raise typer.Exit(code=1)

    errors = basic_validate(cfg)
    if errors:
        typer.secho("Config has issues:", fg="red")
        for err in errors:
            typer.echo(f" - {err}")
        raise typer.Exit(code=1)

    typer.secho("Config looks good ✅", fg="green")

@app.command(help="(Placeholder) Run checks now. Implemented in next step.")
def check():
    typer.secho("Not implemented yet in CE skeleton. Coming next. 🧱", fg="yellow")
    raise typer.Exit(code=0)
