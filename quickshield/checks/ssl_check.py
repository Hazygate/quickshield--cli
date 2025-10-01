from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any
import socket
import ssl
from datetime import datetime, timezone

@dataclass
class SslCheckResult:
    name: str
    host: str
    port: int
    ok: bool
    days_to_expiry: Optional[int]
    not_after: Optional[str]   # ISO8601 string
    issuer: Optional[str]
    error: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

def _parse_not_after(not_after_str: str) -> datetime:
    # Typical format from getpeercert(): 'Oct  1 12:00:00 2025 GMT'
    return datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)

def run_ssl_check(name: str, host: str, port: int = 443) -> SslCheckResult:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        # cert is a dict with fields like 'notAfter' and 'issuer'
        not_after_raw = cert.get("notAfter")
        if not not_after_raw:
            return SslCheckResult(name, host, port, False, None, None, None, "no notAfter in cert")

        not_after_dt = _parse_not_after(not_after_raw)
        now = datetime.now(timezone.utc)
        delta_days = (not_after_dt - now).days

        issuer_tuples = cert.get("issuer") or []
        # issuer is a tuple of ((('commonName', 'X'),), (('organizationName','Y'),) ...)
        issuer_parts = []
        for rdn in issuer_tuples:
            for k, v in rdn:
                if k.lower() in ("commonname", "organizationname", "countryname"):
                    issuer_parts.append(v)
        issuer_str = ", ".join(issuer_parts) if issuer_parts else None

        ok = delta_days >= 0
        return SslCheckResult(
            name=name,
            host=host,
            port=port,
            ok=ok,
            days_to_expiry=max(delta_days, 0) if delta_days is not None else None,
            not_after=not_after_dt.isoformat(),
            issuer=issuer_str,
            error=None if ok else "certificate expired",
        )
    except Exception as e:
        return SslCheckResult(name=name, host=host, port=port, ok=False,
                              days_to_expiry=None, not_after=None, issuer=None, error=str(e))
