from __future__ import annotations
from pathlib import Path
from typing import Optional, List, Dict, Any, Set
import json
import time
import sys
import shutil
import typer

from . import __version__
from .config import write_default_config, load_config, basic_validate
from .checks.http_check import run_http_check, HttpCheckResult
from .checks.ssl_check import run_ssl_check, SslCheckResult
from .checks.headers_check import run_headers_check, HeadersCheckResult
from .checks.dns_check import run_dns_check, DnsCheckResult
from .reporting.csv_report import write_csv

# Root Typer app
app = typer.Typer(no_args_is_help=True, add_completion=False, help="QuickShield CE CLI")

# ---------------------------
# Utilities
# ---------------------------

_ALLOWED_CHECKS: Set[str] = {"http", "ssl", "headers", "dns"}
_PRESETS_MINUTES = {
    "30m": 30,
    "6h": 6 * 60,
    "12h": 12 * 60,
    "24h": 24 * 60,
}

def _parse_only_list(only: Optional[str]) -> Set[str]:
    """Parse comma-separated --only checks into a validated set."""
    if not only:
        return set(_ALLOWED_CHECKS)
    parts = [p.strip().lower() for p in only.split(",") if p.strip()]
    invalid = [p for p in parts if p not in _ALLOWED_CHECKS]
    if invalid:
        raise typer.BadParameter(
            f"Invalid check(s): {', '.join(invalid)}. "
            f"Valid: {', '.join(sorted(_ALLOWED_CHECKS))}"
        )
    return set(parts)

def _python_executable() -> str:
    """Return the entry used to run QuickShield in scheduled commands."""
    exe = shutil.which("quickshield")
    if exe:
        # Use the installed console script if available for portability
        return exe
    # Fallback to python -m quickshield (works in virtualenvs)
    return f"{sys.executable} -m quickshield"

# ---------------------------
# Global callback
# ---------------------------

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

# ---------------------------
# Commands
# ---------------------------

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

@app.command(help="Run selected checks (HTTP, SSL, Headers, DNS) and export results.")
def check(
    path: Path = typer.Option(Path("quickshield.yml"), "--path", "-p", help="Path to config file."),
    outdir: Path = typer.Option(Path("output"), "--outdir", "-o", help="Directory for results."),
    site: Optional[str] = typer.Option(None, "--site", "-s", help="Only check a specific site by name."),
    format: str = typer.Option("json", "--format", "-f", help="Report format: json, csv, or both",
                               case_sensitive=False),
    only: Optional[str] = typer.Option(None, "--only", help="Comma-separated checks to run: http,ssl,headers,dns"),
):
    """
    Examples:
      quickshield check --format both
      quickshield check --only http,ssl
      quickshield check --site Araknitect --only headers
    """
    format = format.lower()
    if format not in {"json", "csv", "both"}:
        typer.secho("Invalid --format. Use: json, csv, or both.", fg="red")
        raise typer.Exit(code=2)

    try:
        selected_checks = _parse_only_list(only)
    except typer.BadParameter as e:
        typer.secho(str(e), fg="red")
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
    typer.echo("Checks: " + ", ".join(sorted(selected_checks)))

    results: List[Dict[str, Any]] = []
    for s in sites:
        name = str(s.get("name"))
        url = str(s.get("url"))
        expect_keyword = s.get("expect_keyword") or None
        host = url.replace("https://", "").replace("http://", "").split("/")[0]

        site_result: Dict[str, Any] = {"name": name, "url": url}

        # HTTP
        if "http" in selected_checks:
            typer.echo(f"→ HTTP:     {name} ({url})")
            http_res: HttpCheckResult = run_http_check(name=name, url=url, expect_keyword=expect_keyword)
            typer.secho(
                f"   {'OK' if http_res.ok else 'FAIL'} | status={http_res.status_code} latency={http_res.latency_ms}ms"
                + (f" error={http_res.error}" if http_res.error else ""),
                fg=("green" if http_res.ok else "red"),
            )
            site_result["http"] = http_res.to_dict()

        # SSL
        if "ssl" in selected_checks:
            typer.echo(f"→ SSL:      {name} ({host}:443)")
            ssl_res: SslCheckResult = run_ssl_check(name=name, host=host, port=443)
            typer.secho(
                f"   {'OK' if ssl_res.ok else 'FAIL'} |"
                + (f" exp={ssl_res.days_to_expiry}d" if ssl_res.days_to_expiry is not None else "")
                + (f" error={ssl_res.error}" if ssl_res.error else ""),
                fg=("green" if ssl_res.ok else "red"),
            )
            site_result["ssl"] = ssl_res.to_dict()

        # HEADERS
        if "headers" in selected_checks:
            typer.echo(f"→ HEADERS:  {name} ({url})")
            hdr_res: HeadersCheckResult = run_headers_check(name=name, url=url)
            typer.secho(
                f"   grade={hdr_res.grade} "
                + ("" if not hdr_res.issues else f"| issues={len(hdr_res.issues)}"),
                fg=("green" if hdr_res.ok else "red"),
            )
            site_result["headers"] = hdr_res.to_dict()

        # DNS
        if "dns" in selected_checks:
            typer.echo(f"→ DNS:      {name} ({host})")
            dns_res: DnsCheckResult = run_dns_check(name=name, host=host)
            typer.secho(
                f"   {'OK' if dns_res.ok else 'FAIL'} | "
                f"A={len(dns_res.records.get('A', []))} "
                f"AAAA={len(dns_res.records.get('AAAA', []))} "
                f"CNAME={len(dns_res.records.get('CNAME', []))} "
                f"MX={len(dns_res.records.get('MX', []))}",
                fg=("green" if dns_res.ok else "red"),
            )
            site_result["dns"] = dns_res.to_dict()

        results.append(site_result)

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

@app.command(help="Print OS-specific scheduler snippets (no changes applied).")
def schedule(
    subcommand: str = typer.Argument("print", help="Only 'print' is supported in CE."),
    preset: str = typer.Option("12h", "--preset", "-p", help="Interval preset: 30m, 6h, 12h, 24h"),
    path: Path = typer.Option(Path("quickshield.yml"), "--path", help="Path to config file."),
    only: Optional[str] = typer.Option(None, "--only", help="Restrict checks: http,ssl,headers,dns"),
    fmt: str = typer.Option("both", "--format", "-f", help="Report format: json, csv, or both"),
):
    """
    Examples:
      quickshield schedule print
      quickshield schedule print --preset 6h
      quickshield schedule print --preset 30m --only http
      quickshield schedule print --preset 24h --only ssl,headers,dns --format json
    """
    if subcommand != "print":
        typer.secho("Only 'schedule print' is supported in CE.", fg="red")
        raise typer.Exit(code=2)

    preset = preset.lower()
    if preset not in _PRESETS_MINUTES:
        typer.secho("Invalid --preset. Use one of: 30m, 6h, 12h, 24h", fg="red")
        raise typer.Exit(code=2)

    try:
        selected_checks = _parse_only_list(only)
    except typer.BadParameter as e:
        typer.secho(str(e), fg="red")
        raise typer.Exit(code=2)

    fmt = fmt.lower()
    if fmt not in {"json", "csv", "both"}:
        typer.secho("Invalid --format. Use: json, csv, or both.", fg="red")
        raise typer.Exit(code=2)

    cfg_path = path.resolve()
    runner = _python_executable()

    checks_arg = ""
    if selected_checks != _ALLOWED_CHECKS:
        checks_arg = f' --only {",".join(sorted(selected_checks))}'

    cmd = f'"{runner}" check --path "{cfg_path}" --format {fmt}{checks_arg}'

    minutes = _PRESETS_MINUTES[preset]
    typer.secho("Scheduler snippets (copy/paste as needed):", fg="cyan", bold=True)
    typer.echo("")

    if sys.platform.startswith("win"):
        # Windows Task Scheduler
        typer.secho("Windows (Task Scheduler):", fg="magenta", bold=True)
        if minutes < 60:
            typer.echo(
                f'schtasks /Create /TN "QuickShieldCheck" /TR {cmd} /SC MINUTE /MO {minutes} /RL LIMITED'
            )
        else:
            hours = minutes // 60
            typer.echo(
                f'schtasks /Create /TN "QuickShieldCheck" /TR {cmd} /SC HOURLY /MO {hours} /RL LIMITED'
            )
        typer.echo('To delete later: schtasks /Delete /TN "QuickShieldCheck" /F')
        typer.echo("")

    elif sys.platform == "darwin":
        # macOS launchd
        typer.secho("macOS (launchd):", fg="magenta", bold=True)
        stdout_path = str((Path.cwd() / "logs" / "quickshield.out").resolve())
        stderr_path = str((Path.cwd() / "logs" / "quickshield.err").resolve())
        # Split the runner in case it's "python -m quickshield"
        runner_parts = runner.split()
        plist = f"""\
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key><string>com.quickshield.check</string>
    <key>ProgramArguments</key>
    <array>
      {"".join(f"<string>{part}</string>" for part in runner_parts)}
      <string>check</string>
      <string>--path</string><string>{cfg_path}</string>
      <string>--format</string><string>{fmt}</string>
      {"<string>--only</string><string>"+",".join(sorted(selected_checks))+"</string>" if selected_checks != _ALLOWED_CHECKS else ""}
    </array>
    <key>StartInterval</key><integer>{minutes * 60}</integer>
    <key>StandardOutPath</key><string>{stdout_path}</string>
    <key>StandardErrorPath</key><string>{stderr_path}</string>
    <key>RunAtLoad</key><true/>
  </dict>
</plist>
"""
        typer.echo("# Save as: ~/Library/LaunchAgents/com.quickshield.check.plist")
        typer.echo(plist)
        typer.echo("Load:   launchctl load ~/Library/LaunchAgents/com.quickshield.check.plist")
        typer.echo("Unload: launchctl unload ~/Library/LaunchAgents/com.quickshield.check.plist")
        typer.echo("")

    else:
        # Linux cron
        typer.secho("Linux (cron):", fg="magenta", bold=True)
        if minutes < 60 and 60 % minutes == 0:
            # e.g., 30m
            step = minutes
            typer.echo(f"*/{step} * * * * {cmd}")
        elif minutes % 60 == 0:
            # hours
            hours = minutes // 60
            if hours == 1:
                typer.echo(f"0 * * * * {cmd}")
            else:
                typer.echo(f"0 */{hours} * * * {cmd}")
        else:
            # Fallback (shouldn't hit with our presets)
            typer.echo(f"* * * * * (test $(( $(date +\\%s) / 60 % {minutes} )) -eq 0 && {cmd})")
        typer.echo("")
