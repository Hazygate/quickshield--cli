from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional
import hashlib
import dns.resolver

@dataclass
class DnsCheckResult:
    name: str
    host: str
    ok: bool
    records: Dict[str, List[str]]
    hash: Optional[str]
    error: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

def _resolve_records(host: str, record_type: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(host, record_type)
        return sorted([str(r).strip() for r in answers])
    except Exception:
        return []

def run_dns_check(name: str, host: str) -> DnsCheckResult:
    try:
        recs: Dict[str, List[str]] = {}
        for rtype in ("A", "AAAA", "CNAME", "MX"):
            recs[rtype] = _resolve_records(host, rtype)

        combined = []
        for k, v in sorted(recs.items()):
            combined.append(k + ":" + ",".join(v))
        combined_str = "|".join(combined)
        digest = hashlib.sha256(combined_str.encode("utf-8")).hexdigest()

        ok = any(recs.values())  # if at least one record resolves, we call it ok
        return DnsCheckResult(
            name=name,
            host=host,
            ok=ok,
            records=recs,
            hash=digest,
            error=None if ok else "No records resolved",
        )
    except Exception as e:
        return DnsCheckResult(name=name, host=host, ok=False, records={}, hash=None, error=str(e))
