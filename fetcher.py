"""Safe page fetcher. The app fetches user-supplied URLs, so it must not become an SSRF proxy:
blocks private/loopback/link-local IPs (also after redirects), caps size and time, never executes JS."""
import ipaddress
import socket
import time
from urllib.parse import urljoin, urlparse

import requests

MAX_BYTES = 1_000_000
TIMEOUT = 6
MAX_REDIRECTS = 4
UA = "Mozilla/5.0 (compatible; PhishScan/1.0; research)"


def _is_public(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            return False
    return True


def fetch_html(url: str) -> dict:
    """Returns {html, final_url, redirects, status, error}. html is None on failure."""
    if "://" not in url:
        url = "http://" + url
    out = {"html": None, "final_url": url, "redirects": 0, "status": None, "error": None}
    try:
        cur, t0 = url, time.monotonic()
        for hop in range(MAX_REDIRECTS + 1):
            p = urlparse(cur)
            if p.scheme not in ("http", "https") or not p.hostname:
                out["error"] = "unsupported URL"
                return out
            if not _is_public(p.hostname):
                out["error"] = "blocked: host is not publicly routable"
                return out
            if time.monotonic() - t0 > 8:
                out["error"] = "fetch timed out"
                return out
            r = requests.get(cur, headers={"User-Agent": UA}, timeout=TIMEOUT, allow_redirects=False, stream=True)
            out["status"] = r.status_code
            if r.is_redirect and r.headers.get("Location"):
                cur = urljoin(cur, r.headers["Location"])
                out["redirects"] += 1
                out["final_url"] = cur
                r.close()
                continue
            body = b""
            for chunk in r.iter_content(8192):
                body += chunk
                if len(body) > MAX_BYTES:
                    break
            ctype = r.headers.get("Content-Type", "")
            if "html" in ctype.lower() or not ctype:
                out["html"] = body.decode(r.encoding or "utf-8", errors="ignore")
            else:
                out["error"] = f"non-HTML content ({ctype.split(';')[0]})"
            return out
        out["error"] = "too many redirects"
    except requests.RequestException as e:
        out["error"] = f"fetch failed: {type(e).__name__}"
    return out
