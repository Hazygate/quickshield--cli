from __future__ import annotations
from pathlib import Path
from typing import Optional, List, Dict, Any
import json
import time
import typer
from . import __version__
from .config import write_default_config, load_config, basic_validate
from .checks.http_check import run_http_check, HttpCheckResult

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

@app.command(help="Run HTTP uptime checks for all sites in the config.")
def check(
    path: Path = typer.Option(Path("quickshield.yml"), "--path", "-p", help="Path to config file."),
    outdir: Path = typer.Option(Path("output"), "--outdir", "-o", help="Directory for results."),
    site: Optional[str] = typer.Option(None, "--site", "-s", help="Only check a specific site by name."),
):
    if not path.exists():
        typer.secho(f"Config not found: {path}", fg="red")
        raise typer.Exit(code=1)

    try:
        cfg: Dict[str, Any] = load_config(path)
    except Exception as e:
        typer.secho(f"Failed to parse YAML: {e}", fg="red")
        raise typer.Exit(code=1)

    errors = basic_validate(cfg)
    if errors:
        typer.secho("Config has issues:", fg="red")
        for err in errors:
            typer.echo(f" - {err}")
        raise typer.Exit(code=1)

    sites: List[Dict[str, Any]] = cfg["sites"]
    if site:
        sites = [s for s in sites if s.get("name") == site]
        if not sites:
            typer.secho(f"No site named '{site}' found in config.", fg="red")
            raise typer.Exit(code=1)

    outdir.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    outfile = outdir / f"checks-{ts}.json"

    results: List[HttpCheckResult] = []
    for s in sites:
        name = str(s.get("name"))
        url = str(s.get("url"))
        expect_keyword = s.get("expect_keyword") or None
        typer.echo(f"→ Checking {name} ({url}) ...")
        res = run_http_check(name=name, url=url, expect_keyword=expect_keyword)
        results.append(res)
        status = "OK" if res.ok else "FAIL"
        typer.secho(f"   {status} | status={res.status_code} latency={res.latency_ms}ms"
                    + (f" error={res.error}" if res.error else ""), fg=("green" if res.ok else "red"))

    with outfile.open("w", encoding="utf-8") as f:
        json.dump([r.to_dict() for r in results], f, indent=2)
    typer.secho(f"Saved results → {outfile}", fg="cyan")
