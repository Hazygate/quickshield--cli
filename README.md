QuickShield CE 🛡️

Community Edition – Website & Infrastructure Health Checker

QuickShield CE is a lightweight, Python-based tool that helps you keep tabs on your websites and infrastructure.
It runs checks for uptime, SSL expiry, security headers, and DNS snapshots — with results saved to JSON or CSV for easy reporting.

✅ Open source & MIT licensed

✅ Minimal dependencies

✅ Cross-platform (Linux, macOS, Windows)

✅ No background daemons — safe to run on demand or scheduled

✨ Features

HTTP Uptime – status, latency, and optional keyword matching

SSL Expiry – days to expiry + issuer info

Security Headers – grades key headers (A–F)

DNS Snapshot – resolves A/AAAA/CNAME/MX + hash for change detection

Reports – JSON or CSV (spreadsheet-ready)

Automation – generate scheduler snippets (cron, launchd, schtasks)

Selective Checks – run only what you need (--only http,ssl)

🚀 Install

QuickShield CE works with Python 3.9+.

Option A — pipx (recommended)

Isolates QuickShield into its own environment and gives you a global quickshield command.

python3 -m pip install --user pipx
python3 -m pipx ensurepath
pipx install .

Option B — Virtual environment

The classic development workflow.

python3 -m venv .venv
source .venv/bin/activate        # Windows: .\.venv\Scripts\Activate.ps1
pip install -e .

📖 Quickstart
1. Initialize Config
quickshield init


Creates quickshield.yml with example sites.

2. Validate Config
quickshield validate

3. Run Checks
quickshield check --format both


Results saved into output/checks-<timestamp>.json and .csv.

4. Run Specific Checks
quickshield check --only http,ssl

5. Schedule Checks

Generate OS-specific scheduler snippets (copy/paste into cron, Task Scheduler, or launchd):

quickshield schedule print --preset 12h --only http --format csv

🛠️ Example Config (quickshield.yml)
sites:
  - name: Araknitect
    url: https://araknitect.com
    expect_keyword: Araknitect

  - name: Example
    url: https://example.com

🧩 Roadmap

CE: JSON + CSV reports, scheduler snippets, selective checks

Pro: Enhanced HTML/PDF reports, CI/CD integration, alerting (email/Slack)

Agency: Multi-client dashboards, branding, advanced scheduling

📜 License

MIT License – use, copy, modify, and share freely.