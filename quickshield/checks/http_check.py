from __future__ import annotations
from dataclasses import dataclass, asdict
from time import monotonic
from typing import Optional, Dict, Any
import httpx

@dataclass
class HttpCheckResult:
    name: str
    url: str
    ok: bool
    status_code: Optional[int]
    latency_ms: Optional[int]
    error: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

def run_http_check(name: str, url: str, expect_keyword: Optional[str] = None) -> HttpCheckResult:
    start = monotonic()
    try:
        # Reasonable defaults: 10s total timeout, follow redirects
        with httpx.Client(follow_redirects=True, timeout=httpx.Timeout(10.0, connect=5.0)) as client:
            resp = client.get(url, headers={"User-Agent": "quickshield-ce/0.1"})
            latency_ms = int((monotonic() - start) * 1000)
            ok = 200 <= resp.status_code < 400

            if ok and expect_keyword:
                # If keyword is set, ensure it's present in the text
                if expect_keyword not in resp.text:
                    return HttpCheckResult(
                        name=name, url=url, ok=False, status_code=resp.status_code,
                        latency_ms=latency_ms, error=f"Keyword '{expect_keyword}' not found"
                    )

            return HttpCheckResult(
                name=name, url=url, ok=ok, status_code=resp.status_code,
                latency_ms=latency_ms, error=None if ok else "Non-OK status"
            )
    except Exception as e:
        latency_ms = int((monotonic() - start) * 1000)
        return HttpCheckResult(
            name=name, url=url, ok=False, status_code=None, latency_ms=latency_ms, error=str(e)
        )
