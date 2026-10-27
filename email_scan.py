"""Phishing analysis of pasted email text/headers/HTML: social-engineering language, sender spoofing, link mismatch, URLs."""
import re
from email.utils import parseaddr
from urllib.parse import urlparse

from bs4 import BeautifulSoup

import intel
from features import split_host

URL_RE = re.compile(r"https?://[^\s<>\"')\]]+|(?<![@\w.-])(?:www\.)[a-z0-9-]+(?:\.[a-z0-9-]+)+[^\s<>\"')\]]*", re.I)
WORDS = {
    "urgency": (.30, ["urgent", "immediately", "within 24", "act now", "final notice", "expires today", "last warning", "asap"]),
    "threat": (.25, ["suspended", "locked", "terminated", "deactivated", "legal action", "unauthorized", "unusual activity", "will be closed"]),
    "credentials": (.30, ["verify your", "confirm your", "password", "otp", "one-time", "cvv", "pin number", "card number", "login to", "sign in to", "update your account", "kyc"]),
    "lure": (.30, ["you have won", "lottery", "prize", "gift card", "refund", "claim your", "inheritance", "bitcoin", "crypto giveaway"]),
}
GENERIC = re.compile(r"dear (customer|user|member|client|account holder|valued)", re.I)


def extract_urls(text: str, limit=25):
    seen, out = set(), []
    for m in URL_RE.findall(text):
        u = m.rstrip(".,;:!?")
        if u.lower() not in seen:
            seen.add(u.lower())
            out.append(u)
    return out[:limit]


def text_signals(text: str):
    low = text.lower()
    sig = []
    for name, (w, words) in WORDS.items():
        n = [x for x in words if x in low]
        if len(n) >= (2 if name == "urgency" else 1):
            sig.append((w + (0.08 if len(n) >= 3 else 0), f"{name.title()} language: {', '.join(n[:3])}"))
    if GENERIC.search(text):
        sig.append((.20, "Generic greeting (real providers usually use your name)"))
    # sender checks
    m = re.search(r"^from:\s*(.+)$", text, re.I | re.M)
    if m:
        name, addr = parseaddr(m.group(1))
        dom = addr.split("@")[-1].lower() if "@" in addr else ""
        reg = split_host(dom)[1] if dom else ""
        for b in intel.brand_hits(name):
            if reg and not intel.is_official(b, reg):
                sig.append((.70, f"Sender name claims '{b}' but the email comes from {reg}"))
                break
        if reg and intel.typosquat(reg):
            sig.append((.60, f"Sender domain {reg} imitates a known brand"))
    r = re.search(r"^reply-to:\s*(.+)$", text, re.I | re.M)
    if m and r:
        a1, a2 = parseaddr(m.group(1))[1].split("@")[-1].lower(), parseaddr(r.group(1))[1].split("@")[-1].lower()
        if a1 and a2 and split_host(a1)[1] != split_host(a2)[1]:
            sig.append((.30, "Reply-To domain differs from the sender domain"))
    # visible link text vs real target
    if "<a" in low:
        try:
            for a in BeautifulSoup(text, "html.parser").find_all("a", href=True):
                shown = a.get_text(" ", strip=True)
                sm = URL_RE.search(shown)
                if sm:
                    sh = split_host((urlparse(sm.group(0) if "://" in sm.group(0) else "http://" + sm.group(0)).hostname or "").lower())[1]
                    th = split_host((urlparse(a["href"]).hostname or "").lower())[1]
                    if sh and th and sh != th:
                        sig.append((.65, f"Link text shows {sh} but actually goes to {th}"))
                        break
        except Exception:
            pass
    if re.search(r"\.(exe|scr|js|vbs|iso|docm|xlsm)\b", low):
        sig.append((.35, "Mentions a risky attachment type"))
    return sig


def analyze_email(text: str, analyzer, deep_fn=None) -> dict:
    sig = text_signals(text)
    keep = 1.0
    for w, _ in sig:
        keep *= 1 - w
    text_p = 1 - keep
    urls = extract_urls(text)
    results = []
    for i, u in enumerate(urls):
        net = deep_fn(u) if deep_fn and i < 3 else None
        r = analyzer.analyze(u, (net or {}).get("page", {}).get("html") if net else None,
                             (net or {}).get("page") if net else None, net)
        results.append({k: r[k] for k in ("url", "domain", "risk_score", "risk_level", "reasons", "known_domain")})
    worst = max((r["risk_score"] for r in results), default=0) / 100
    final = 1 - (1 - text_p) * (1 - 0.9 * worst)
    score = round(100 * final, 1)
    from risk import tier, ADVICE
    return {"risk_score": score, "risk_level": tier(score), "advice": ADVICE[tier(score)], "text_score": round(100 * text_p, 1),
            "text_signals": [m for _, m in sorted(sig, reverse=True)], "urls": results, "n_urls": len(urls)}
