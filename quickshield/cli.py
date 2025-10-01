from __future__ import annotations
from pathlib import Path
from typing import Optional, List, Dict, Any
from .checks.dns_check import run_dns_check, DnsCheckResult
from .reporting.csv_report import write_csv
import json
import time
import typer

from . import __version__
from .config import write_default_config, load_config, basic_validate
from .checks.http_check import run_http_check, HttpCheckResult
from .checks.ssl_check import run_ssl_check, SslCheckResult
from .checks.headers_check import run_headers_check, HeadersCheckResult

# Root Typer app
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

    # QoL: show which config + sites we validated
    typer.secho(f"Using config: {path.resolve()}", fg="cyan")
    typer.echo("Sites: " + ", ".join(str(s.get("name")) for s in cfg["sites"]))

    typer.secho("Config looks good ✅", fg="green")

@app.command(help="Run HTTP, SSL, and Security Headers checks for all sites (or one).")
def check(
    path: Path = typer.Option(Path("quickshield.yml"), "--path", "-p", help="Path to config file."),
    outdir: Path = typer.Option(Path("output"), "--outdir", "-o", help="Directory for results."),
    site: Optional[str] = typer.Option(None, "--site", "-s", help="Only check a specific site by name."),
    format: str = typer.Option("json", "--format", "-f", help="Report format: json, csv, or both",
                               case_sensitive=False),
):
    format = format.lower()
    if format not in {"json", "csv", "both"}:
        typer.secho("Invalid --format. Use: json, csv, or both.", fg="red")
        raise typer.Exit(code=2)

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
    json_outfile = outdir / f"checks-{ts}.json"
    csv_outfile = outdir / f"checks-{ts}.csv"

    # QoL: show which config + sites we're using right now
    typer.secho(f"Using config: {path.resolve()}", fg="cyan")
    typer.echo("Sites: " + ", ".join(str(s.get("name")) for s in sites))

    results: List[Dict[str, Any]] = []
    for s in sites:
        name = str(s.get("name"))
        url = str(s.get("url"))
        expect_keyword = s.get("expect_keyword") or None

        # HTTP
        typer.echo(f"→ HTTP:     {name} ({url})")
        http_res: HttpCheckResult = run_http_check(name=name, url=url, expect_keyword=expect_keyword)
        typer.secho(
            f"   {'OK' if http_res.ok else 'FAIL'} | status={http_res.status_code} latency={http_res.latency_ms}ms"
            + (f" error={http_res.error}" if http_res.error else ""),
            fg=("green" if http_res.ok else "red"),
        )

        # SSL
        host = url.replace("https://", "").replace("http://", "").split("/")[0]
        typer.echo(f"→ SSL:      {name} ({host}:443)")
        ssl_res: SslCheckResult = run_ssl_check(name=name, host=host, port=443)
        typer.secho(
            f"   {'OK' if ssl_res.ok else 'FAIL'} |"
            + (f" exp={ssl_res.days_to_expiry}d" if ssl_res.days_to_expiry is not None else "")
            + (f" error={ssl_res.error}" if ssl_res.error else ""),
            fg=("green" if ssl_res.ok else "red"),
        )

        # HEADERS
        typer.echo(f"→ HEADERS:  {name} ({url})")
        hdr_res: HeadersCheckResult = run_headers_check(name=name, url=url)
        typer.secho(
            f"   grade={hdr_res.grade} "
            + ("" if not hdr_res.issues else f"| issues={len(hdr_res.issues)}"),
            fg=("green" if hdr_res.ok else "red"),
        )

        # DNS
        from .checks.dns_check import run_dns_check  # lazy import to avoid circulars
        dns_res = run_dns_check(name=name, host=host)
        typer.secho(
            f"→ DNS:      {'OK' if dns_res.ok else 'FAIL'} | "
            f"A={len(dns_res.records.get('A', []))} "
            f"AAAA={len(dns_res.records.get('AAAA', []))} "
            f"CNAME={len(dns_res.records.get('CNAME', []))} "
            f"MX={len(dns_res.records.get('MX', []))}",
            fg=("green" if dns_res.ok else "red"),
        )

        results.append({
            "name": name,
            "url": url,
            "http": http_res.to_dict(),
            "ssl": ssl_res.to_dict(),
            "headers": hdr_res.to_dict(),
            "dns": dns_res.to_dict(),
        })

    saved = []
    if format in {"json", "both"}:
        with json_outfile.open("w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        saved.append(str(json_outfile))
    if format in {"csv", "both"}:
        write_csv(results, csv_outfile)
        saved.append(str(csv_outfile))

    for path_str in saved:
        typer.secho(f"Saved → {path_str}", fg="cyan")