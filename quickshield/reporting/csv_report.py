from __future__ import annotations
from pathlib import Path
from typing import List, Dict, Any
import csv
import datetime as dt

# Flatten the JSON-y results into one row per site
def write_csv(results: List[Dict[str, Any]], outfile: Path) -> None:
    # Define a stable column order (add/remove fields as you like)
    fieldnames = [
        "timestamp_iso",
        "name", "url",
        "http_ok", "http_status", "http_latency_ms", "http_error",
        "ssl_ok", "ssl_days_to_expiry", "ssl_not_after", "ssl_issuer", "ssl_error",
        "headers_ok", "headers_grade", "headers_issues_count", "headers_error",
        "dns_ok", "dns_a_count", "dns_aaaa_count", "dns_cname_count", "dns_mx_count", "dns_hash", "dns_error",
    ]

    timestamp_iso = dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

    rows = []
    for r in results:
        http = r.get("http", {}) or {}
        ssl = r.get("ssl", {}) or {}
        hdr = r.get("headers", {}) or {}
        dns = r.get("dns", {}) or {}
        recs = dns.get("records", {}) or {}

        rows.append({
            "timestamp_iso": timestamp_iso,
            "name": r.get("name", ""),
            "url": r.get("url", ""),

            "http_ok": http.get("ok"),
            "http_status": http.get("status_code"),
            "http_latency_ms": http.get("latency_ms"),
            "http_error": http.get("error"),

            "ssl_ok": ssl.get("ok"),
            "ssl_days_to_expiry": ssl.get("days_to_expiry"),
            "ssl_not_after": ssl.get("not_after"),
            "ssl_issuer": ssl.get("issuer"),
            "ssl_error": ssl.get("error"),

            "headers_ok": hdr.get("ok"),
            "headers_grade": hdr.get("grade"),
            "headers_issues_count": len(hdr.get("issues", []) or []),
            "headers_error": hdr.get("error"),

            "dns_ok": dns.get("ok"),
            "dns_a_count": len(recs.get("A", []) or []),
            "dns_aaaa_count": len(recs.get("AAAA", []) or []),
            "dns_cname_count": len(recs.get("CNAME", []) or []),
            "dns_mx_count": len(recs.get("MX", []) or []),
            "dns_hash": dns.get("hash"),
            "dns_error": dns.get("error"),
        })

    outfile.parent.mkdir(parents=True, exist_ok=True)
    with outfile.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
