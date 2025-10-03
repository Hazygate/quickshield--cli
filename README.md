# QuickShield CE 🛡️  
> Community Edition – Website & Infrastructure Health Checker

QuickShield CE is a lightweight, Python-based tool to keep tabs on website health.  
It runs checks for **uptime**, **SSL expiry**, **security headers**, and **DNS snapshots** — saving results to **JSON** and/or **CSV**.

- ✅ Open source (MIT)  
- ✅ Cross-platform (Linux, macOS, Windows)  
- ✅ No daemons; run on demand or via OS scheduler  
- ✅ Works with Python **3.9–3.13** (incl. 3.13.7)

---

## ✨ Features
- **HTTP Uptime** – status code, latency, optional *expect_keyword* content check  
- **SSL Expiry** – days to expiry, `notAfter`, issuer  
- **Security Headers** – grade (A–F) with issues list  
- **DNS Snapshot** – A / AAAA / CNAME / MX + stable hash  
- **Reports** – JSON (detailed) or CSV (one row per site)  
- **Automation** – print scheduler snippets (cron, launchd, schtasks)  
- **Selective Runs** – `--only http,ssl,headers,dns`

---

## 🚀 Install

### Option A — pipx (recommended; global & isolated)
```powershell
py -m pip install --user pipx
py -m pipx ensurepath
# restart PowerShell if needed
pipx install .
Option B — Virtual environment (developer workflow)
powershell
Copy code
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .
📖 Quickstart
powershell
Copy code
quickshield init          # creates quickshield.yml in the current folder
quickshield validate
quickshield check --format both
Outputs go to ./output/checks-<timestamp>.json and .csv.

Run specific checks:

powershell
Copy code
quickshield check --only http,ssl
Print scheduler snippets (copy/paste into your OS scheduler):

powershell
Copy code
quickshield schedule print --preset 12h --only http --format csv
Presets: 30m, 6h, 12h, 24h.

🛠️ Editing the Config (quickshield.yml)
The file is plain YAML. Open it with Notepad (or any editor):

powershell
Copy code
notepad quickshield.yml
Example:

yaml
Copy code
sites:
  - name: My Blog
    url: https://myblog.net
    expect_keyword: Welcome

  - name: Client Shop
    url: https://shop.client.com
    expect_keyword: null   # disable keyword verification
Fields

name: Friendly label (any string).

url: Full URL (https://…). Redirects are followed.

expect_keyword (optional): Exact, case-sensitive string that must appear in the fetched HTML.

Use text that is present in the initial HTML source (footer, heading, meta content).

If your site builds content with JavaScript only, choose something server-rendered (like footer text).

Don't need this? Set to null or remove the line.

Multiple configs (recommended layout on Windows):

lua
Copy code
C:\QuickShield\
  clientA\  quickshield.yml  output\
  clientB\  quickshield.yml  output\
Run with explicit paths:

powershell
Copy code
quickshield validate --path "C:\QuickShield\clientA\quickshield.yml"
quickshield check --path "C:\QuickShield\clientA\quickshield.yml" --format both --outdir "C:\QuickShield\clientA\output"
🧠 What the keyword actually does
During the HTTP check, QuickShield:

Fetches the HTML.

Verifies status code + latency.

If expect_keyword is set: searches for that exact substring in the HTML.

If not found → HTTP check fails with Keyword '…' not found.

Use View Source (Ctrl+U in browser) to copy the exact casing/spacing of the keyword.

Example:

Page shows: Maddog Method

Config must say:

yaml
Copy code
expect_keyword: "Maddog Method"
Using Maddogmethod will fail (different spacing).

🔁 Scheduling (optional)
We suggest every 12–24 hours for all checks, and 30 minutes for uptime-only (--only http) if critical.

Examples:

powershell
Copy code
quickshield schedule print --preset 12h --format both
quickshield schedule print --preset 30m --only http --format csv
🧩 Roadmap
CE: JSON/CSV reports, scheduler snippets, selective checks

Pro: HTML/PDF reports, email/Slack alerts, binaries (no Python), local dashboard

Agency: Multi-client, branding, advanced scheduling

📜 License
MIT License.

🐞 Troubleshooting
“Keyword not found”: Check exact spelling/casing in HTML source. Set expect_keyword: null to disable.

Windows paths: Quote them if they contain spaces:

powershell
Copy code
--path "C:\My Folder\quickshield.yml"
Timeouts: If the site is slow/unreachable, QuickShield reports an error. Verify by visiting the site directly.