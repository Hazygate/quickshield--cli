from __future__ import annotations
from pathlib import Path
from typing import Any, Dict, List
import yaml

DEFAULT_CONFIG = """\
# QuickShield CE configuration
sites:
  - name: Araknitect
    url: https://example.com
    expect_keyword: null   # optional string; set to null to disable
    checks:
      uptime_every: "5m"
      ssl_every: "24h"
      headers_every: "24h"
      dns_every: "6h"

alerts:
  email:
    enabled: false
    smtp_host: smtp.example.com
    smtp_port: 587
    username: you@example.com
    from: alerts@example.com
    to: ["you@example.com"]
    use_tls: true

license:
  key: "CE"  # Community Edition
"""

def write_default_config(path: Path) -> None:
    path.write_text(DEFAULT_CONFIG, encoding="utf-8")

def load_config(path: Path) -> Dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Config root must be a mapping (YAML object).")
    return data

def basic_validate(cfg: Dict[str, Any]) -> List[str]:
    errors: List[str] = []
    sites = cfg.get("sites")
    if not isinstance(sites, list) or not sites:
        errors.append("`sites` must be a non-empty list.")
        return errors

    for i, s in enumerate(sites, start=1):
        if not isinstance(s, dict):
            errors.append(f"site #{i} must be a mapping.")
            continue
        if not s.get("name"):
            errors.append(f"site #{i} is missing `name`.")
        if not s.get("url"):
            errors.append(f"site #{i} is missing `url`.")
        if "checks" not in s or not isinstance(s["checks"], dict):
            errors.append(f"site #{i} is missing `checks` mapping.")

    # alerts and license are optional in CE; we just ensure types if present
    return errors
