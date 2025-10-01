from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional, Tuple
import httpx

@dataclass
class HeadersCheckResult:
    name: str
    url: str
    ok: bool
    grade: str
    issues: List[str]
    sample: Dict[str, str]  # a few key headers we care about
    error: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

def _lower_keys(headers: httpx.Headers) -> Dict[str, str]:
    # normalize to lowercase dict[str,str]
    return {k.lower(): v for k, v in headers.items()}

def _score(headers: Dict[str, str]) -> Tuple[str, List[str]]:
    issues: List[str] = []

    # --- Strict-Transport-Security (HSTS)
    hsts = headers.get("strict-transport-security")
    if not hsts:
        issues.append("Missing Strict-Transport-Security")
    else:
        # Simple parse: look for max-age >= 15552000 (~180 days)
        max_age_ok = False
        try:
            parts = [p.strip() for p in hsts.split(";")]
            for p in parts:
                if p.lower().startswith("max-age="):
                    val = int(p.split("=", 1)[1])
                    if val >= 15552000:
                        max_age_ok = True
                        break
            if not max_age_ok:
                issues.append("HSTS max-age < 15552000")
        except Exception:
            issues.append("HSTS not parseable")

    # --- Content-Security-Policy (CSP)
    csp = headers.get("content-security-policy")
    if not csp:
        issues.append("Missing Content-Security-Policy")

    # --- X-Content-Type-Options
    xcto = headers.get("x-content-type-options")
    if (xcto or "").lower() != "nosniff":
        issues.append("X-Content-Type-Options not 'nosniff'")

    # --- X-Frame-Options
    xfo = (headers.get("x-frame-options") or "").lower()
    if xfo not in ("deny", "sameorigin"):
        issues.append("X-Frame-Options not DENY/SAMEORIGIN")

    # --- Referrer-Policy
    rp = (headers.get("referrer-policy") or "").lower()
    good_rp = {
        "no-referrer",
        "no-referrer-when-downgrade",
        "strict-origin",
        "strict-origin-when-cross-origin",
        "same-origin",
        "origin",
        "origin-when-cross-origin",
    }
    if rp not in good_rp:
        issues.append("Referrer-Policy missing or lax")

    # --- Permissions-Policy (formerly Feature-Policy)
    pp = headers.get("permissions-policy") or headers.get("feature-policy")
    if not pp:
        issues.append("Missing Permissions-Policy")

    # Grade: A (0–1 issues), B (2–3), C (4–5), F (6+)
    n = len(issues)
    if n <= 1:
        grade = "A"
    elif n <= 3:
        grade = "B"
    elif n <= 5:
        grade = "C"
    else:
        grade = "F"

    return grade, issues

def run_headers_check(name: str, url: str) -> HeadersCheckResult:
    try:
        with httpx.Client(follow_redirects=True, timeout=httpx.Timeout(10.0, connect=5.0)) as client:
            # Prefer HEAD to avoid large bodies; fallback to GET if disallowed
            try:
                resp = client.head(url, headers={"User-Agent": "quickshield-ce/0.1"})
                if resp.status_code in (405, 501):  # method not allowed / not implemented
                    resp = client.get(url, headers={"User-Agent": "quickshield-ce/0.1"})
            except httpx.HTTPStatusError:
                # if .head(…, follow_redirects=True) raises, try GET
                resp = client.get(url, headers={"User-Agent": "quickshield-ce/0.1"})

        hdrs = _lower_keys(resp.headers)
        grade, issues = _score(hdrs)

        sample = {
            "strict-transport-security": hdrs.get("strict-transport-security", ""),
            "content-security-policy": hdrs.get("content-security-policy", ""),
            "x-content-type-options": hdrs.get("x-content-type-options", ""),
            "x-frame-options": hdrs.get("x-frame-options", ""),
            "referrer-policy": hdrs.get("referrer-policy", ""),
            "permissions-policy": hdrs.get("permissions-policy", hdrs.get("feature-policy", "")),
        }

        ok = grade in ("A", "B")  # treat C/F as not ok
        return HeadersCheckResult(
            name=name, url=url, ok=ok, grade=grade, issues=issues, sample=sample, error=None
        )
    except Exception as e:
        return HeadersCheckResult(
            name=name, url=url, ok=False, grade="F", issues=["exception"], sample={}, error=str(e)
        )
