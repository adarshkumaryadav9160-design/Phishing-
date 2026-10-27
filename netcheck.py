"""Live network intelligence (all optional; each check fails soft and reports 'unavailable').
Domain age via RDAP, TLS certificate, DNS, and optional Google Safe Browsing (set GSB_API_KEY)."""
import datetime as dt
import os
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, wait
from urllib.parse import urlparse

import requests

from features import split_host
from fetcher import _is_public, fetch_html

DEADLINE = 8.5  # seconds, keeps the whole analysis under typical serverless limits


def _days_since(iso: str):
    try:
        t = dt.datetime.fromisoformat(iso.replace("Z", "+00:00"))
        if t.tzinfo is None:
            t = t.replace(tzinfo=dt.timezone.utc)
        return max((dt.datetime.now(dt.timezone.utc) - t).days, 0)
    except Exception:
        return None


def domain_age(reg_domain: str) -> dict:
    try:
        r = requests.get(f"https://rdap.org/domain/{reg_domain}", timeout=4, headers={"Accept": "application/rdap+json"})
        if r.status_code == 404:
            return {"status": "not_found"}
        r.raise_for_status()
        ev = {e.get("eventAction"): e.get("eventDate") for e in r.json().get("events", [])}
        age = _days_since(ev.get("registration", "")) if ev.get("registration") else None
        return {"status": "ok", "age_days": age, "registered": ev.get("registration"), "expires": ev.get("expiration")}
    except Exception as e:
        return {"status": "unavailable", "error": type(e).__name__}


def tls_info(host: str) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=3) as s:
            with ctx.wrap_socket(s, server_hostname=host) as t:
                c = t.getpeercert()
        issuer = dict(x[0] for x in c.get("issuer", ()))
        nb = ssl.cert_time_to_seconds(c["notBefore"])
        age = max(int((dt.datetime.now(dt.timezone.utc).timestamp() - nb) // 86400), 0)
        return {"status": "ok", "valid": True, "issuer": issuer.get("organizationName") or issuer.get("commonName"),
                "cert_age_days": age}
    except ssl.SSLCertVerificationError as e:
        return {"status": "ok", "valid": False, "error": (e.verify_message or "verification failed")}
    except Exception as e:
        return {"status": "unavailable", "error": type(e).__name__}


def dns_info(host: str) -> dict:
    try:
        ips = sorted({i[4][0] for i in socket.getaddrinfo(host, None)})
        return {"status": "ok", "resolves": True, "ips": ips[:4]}
    except socket.gaierror:
        return {"status": "ok", "resolves": False}


def safe_browsing(url: str) -> dict:
    key = os.environ.get("GSB_API_KEY")
    if not key:
        return {"status": "not_configured"}
    try:
        body = {"client": {"clientId": "phishscan", "clientVersion": "1.0"},
                "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                               "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"],
                               "threatEntries": [{"url": url}]}}
        r = requests.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={key}", json=body, timeout=4)
        r.raise_for_status()
        m = r.json().get("matches", [])
        return {"status": "ok", "flagged": bool(m), "threats": sorted({x["threatType"] for x in m})}
    except Exception as e:
        return {"status": "unavailable", "error": type(e).__name__}


def deep_check(url: str, fetch: bool = True) -> dict:
    """Runs all live checks in parallel under one deadline. Returns dict with html (if fetched)."""
    if "://" not in url:
        url = "http://" + url
    host = (urlparse(url).hostname or "").lower()
    _, reg, _ = split_host(host)
    out = {"dns": {"status": "unavailable"}, "tls": {"status": "unavailable"}, "age": {"status": "unavailable"},
           "gsb": {"status": "not_configured"}, "page": {"html": None, "error": "not fetched"}}
    if not host or not _is_public(host):
        out["dns"] = {"status": "ok", "resolves": False} if host else out["dns"]
        out["page"] = {"html": None, "error": "host not resolvable or not public"}
        return out
    ex = ThreadPoolExecutor(5)
    jobs = {"dns": ex.submit(dns_info, host), "tls": ex.submit(tls_info, host), "gsb": ex.submit(safe_browsing, url)}
    if reg:
        jobs["age"] = ex.submit(domain_age, reg)
    if fetch:
        jobs["page"] = ex.submit(fetch_html, url)
    done, _ = wait(jobs.values(), timeout=DEADLINE)
    for k, fut in jobs.items():
        if fut in done:
            try:
                out[k] = fut.result()
            except Exception as e:
                out[k] = {"status": "unavailable", "error": type(e).__name__}
    ex.shutdown(wait=False, cancel_futures=True)
    return out
