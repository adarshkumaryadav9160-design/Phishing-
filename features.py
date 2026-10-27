"""Feature extraction: URL (lexical/host) features + page-content (HTML) features."""
import math
import re
from collections import Counter
from urllib.parse import urlparse

from bs4 import BeautifulSoup

import intel

SUSPICIOUS_TLDS = {"zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country",
                   "work", "support", "loan", "rest", "icu", "cam", "buzz", "monster"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly"}
BRAND_WORDS = ["paypal", "apple", "google", "microsoft", "amazon", "netflix", "facebook", "instagram",
               "bank", "hdfc", "sbi", "icici", "paytm", "binance", "coinbase", "dhl", "fedex", "irs"]
PHISH_WORDS = ["login", "signin", "verify", "update", "secure", "account", "password", "confirm",
               "billing", "wallet", "suspend", "unlock", "validate", "recover", "support", "alert"]
IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
# crude 2nd-level public suffixes so "evil.co.uk" -> registered domain "evil.co.uk"
SLD = {"co", "com", "org", "net", "gov", "ac", "edu"}


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(v / len(s) * math.log2(v / len(s)) for v in c.values())


def split_host(host: str):
    host = host.lower().strip(".")
    parts = host.split(".")
    if IP_RE.match(host) or len(parts) < 2:
        return "", host, ""
    n = 3 if len(parts) >= 3 and parts[-2] in SLD and len(parts[-1]) == 2 else 2
    reg = ".".join(parts[-n:])
    sub = ".".join(parts[:-n])
    return sub, reg, parts[-1]


URL_FEATURES = [
    "url_len", "host_len", "path_len", "query_len", "n_dots", "n_hyphens", "n_digits", "n_at",
    "n_special", "n_subdomains", "has_ip", "is_https", "has_port", "digit_ratio", "host_entropy",
    "url_entropy", "suspicious_tld", "is_shortener", "n_phish_words", "n_brand_in_sub_or_path",
    "brand_in_host_not_reg", "double_slash_in_path", "has_punycode", "hyphen_in_domain",
    "max_label_len", "n_params", "typosquat", "brand_in_regname", "free_host", "redirect_param",
    "n_pct_encoded", "suspicious_ext", "path_depth", "nonascii_host", "digits_in_regname",
]


def url_features(url: str) -> dict:
    if "://" not in url:
        url = "http://" + url
    p = urlparse(url)
    host = (p.hostname or "").lower()
    sub, reg, tld = split_host(host)
    low = url.lower()
    path_q = (p.path + "?" + p.query).lower()
    reg_name = reg.split(".")[0] if reg else ""
    hits_sub = intel.brand_hits(sub)
    hits_all = set(hits_sub) | set(intel.brand_hits(path_q))
    unofficial_all = [b for b in hits_all if not intel.is_official(b, reg)]
    squat = None if IP_RE.match(host) else intel.typosquat((host.split(".")[0] + ".com") if intel.is_free_host(host) else reg)
    f = {
        "url_len": len(url), "host_len": len(host), "path_len": len(p.path), "query_len": len(p.query),
        "n_dots": host.count("."), "n_hyphens": host.count("-"),
        "n_digits": sum(ch.isdigit() for ch in url),
        "n_at": url.count("@"),
        "n_special": sum(not ch.isalnum() and ch not in "./:-" for ch in url),
        "n_subdomains": len([s for s in sub.split(".") if s]),
        "has_ip": int(bool(IP_RE.match(host))),
        "is_https": int(p.scheme == "https"),
        "has_port": int(p.port not in (None, 80, 443)) if _safe_port(p) else 0,
        "digit_ratio": sum(ch.isdigit() for ch in url) / max(len(url), 1),
        "host_entropy": _entropy(host), "url_entropy": _entropy(url),
        "suspicious_tld": int(tld in SUSPICIOUS_TLDS),
        "is_shortener": int(host in SHORTENERS),
        "n_phish_words": sum(w in low for w in PHISH_WORDS),
        "n_brand_in_sub_or_path": len(unofficial_all),
        "brand_in_host_not_reg": int(any(not intel.is_official(b, reg) for b in hits_sub)),
        "double_slash_in_path": int("//" in p.path),
        "has_punycode": int("xn--" in host),
        "hyphen_in_domain": int("-" in reg_name),
        "max_label_len": max((len(x) for x in host.split(".")), default=0),
        "n_params": len([x for x in p.query.split("&") if x]),
        "typosquat": int(bool(squat and squat[0] in ("typosquat", "homoglyph"))),
        "brand_in_regname": int(bool(squat and squat[0] == "brand-in-domain")),
        "free_host": int(intel.is_free_host(host)),
        "redirect_param": int(bool(re.search(r"[?&](url|redirect|redir|next|goto|dest|target|continue|link)=https?(%3a|:)", low))),
        "n_pct_encoded": len(re.findall(r"%[0-9a-f]{2}", low)),
        "suspicious_ext": int(bool(re.search(r"\.(exe|apk|scr|zip|rar|msi|bat|js|jar|iso|docm|xlsm)(\?|$)", p.path.lower()))),
        "path_depth": len([x for x in p.path.split("/") if x]),
        "nonascii_host": int(any(ord(ch) > 127 for ch in host)),
        "digits_in_regname": int(sum(ch.isdigit() for ch in reg_name) >= 2 and any(ch.isalpha() for ch in reg_name)),
    }
    return f


def _safe_port(p):
    try:
        p.port
        return True
    except ValueError:
        return False


CONTENT_FEATURES = [
    "has_html", "n_forms", "n_password", "n_inputs", "n_iframes", "n_links", "ext_link_ratio",
    "null_link_ratio", "form_ext_action", "form_empty_action", "form_http_action", "has_hidden_iframe",
    "n_scripts", "has_onmouseover", "has_rightclick_block", "has_favicon_ext", "title_missing",
    "title_brand_mismatch", "ext_resource_ratio", "n_meta_refresh", "text_len", "has_mailto_form",
    "urgent_words", "popup_js",
]
URGENT = ["urgent", "immediately", "suspended", "verify your", "confirm your", "limited", "unusual activity",
          "expire", "within 24", "locked", "security alert"]


def _same_site(host_a: str, host_b: str) -> bool:
    return split_host(host_a)[1] == split_host(host_b)[1] or host_a == host_b


def content_features(html: str | None, url: str) -> dict:
    zero = {k: 0 for k in CONTENT_FEATURES}
    if not html:
        return zero
    if "://" not in url:
        url = "http://" + url
    host = (urlparse(url).hostname or "").lower()
    soup = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")
    links = [a.get("href", "") for a in soup.find_all("a")]
    null = sum(l.strip() in ("", "#", "javascript:void(0)", "javascript:;") or l.startswith("#") for l in links)
    ext = 0
    for l in links:
        h = urlparse(l).hostname
        if h and not _same_site(h, host):
            ext += 1
    res = [t.get("src") or t.get("href") or "" for t in soup.find_all(["img", "script", "link"])]
    ext_res = sum(1 for r in res if urlparse(r).hostname and not _same_site(urlparse(r).hostname, host))
    actions = [f.get("action", "").strip() for f in forms]
    text = soup.get_text(" ", strip=True).lower()
    title = (soup.title.string or "").lower() if soup.title and soup.title.string else ""
    reg_name = split_host(host)[1].split(".")[0]
    title_brand = intel.brand_hits(title)
    reg_full = split_host(host)[1]
    scripts = " ".join(s.get_text() for s in soup.find_all("script")).lower()
    icon = soup.find("link", rel=lambda r: r and "icon" in " ".join(r).lower() if isinstance(r, list) else r and "icon" in r.lower())
    return {
        "has_html": 1, "n_forms": len(forms),
        "n_password": len(soup.find_all("input", {"type": "password"})),
        "n_inputs": len(soup.find_all("input")), "n_iframes": len(soup.find_all("iframe")),
        "n_links": len(links), "ext_link_ratio": ext / max(len(links), 1),
        "null_link_ratio": null / max(len(links), 1),
        "form_ext_action": int(any(urlparse(a).hostname and not _same_site(urlparse(a).hostname, host) for a in actions)),
        "form_empty_action": int(any(a in ("", "#", "about:blank") for a in actions)),
        "form_http_action": int(any(a.startswith("http://") for a in actions)),
        "has_hidden_iframe": int(any("display:none" in (i.get("style", "").replace(" ", "").lower()) or i.get("width") == "0"
                                      or i.get("height") == "0" for i in soup.find_all("iframe"))),
        "n_scripts": len(soup.find_all("script")),
        "has_onmouseover": int("onmouseover" in html.lower()),
        "has_rightclick_block": int("contextmenu" in scripts or "event.button==2" in scripts.replace(" ", "")),
        "has_favicon_ext": int(bool(icon and urlparse(icon.get("href", "")).hostname
                                    and not _same_site(urlparse(icon.get("href", "")).hostname, host))),
        "title_missing": int(not title),
        "title_brand_mismatch": int(bool(title_brand) and not any(intel.is_official(b, reg_full) for b in title_brand)),
        "ext_resource_ratio": ext_res / max(len(res), 1),
        "n_meta_refresh": len(soup.find_all("meta", attrs={"http-equiv": re.compile("refresh", re.I)})),
        "text_len": len(text),
        "has_mailto_form": int(any(a.startswith("mailto:") for a in actions)),
        "urgent_words": sum(w in text for w in URGENT),
        "popup_js": int("window.open" in scripts or "prompt(" in scripts),
    }


ALL_FEATURES = URL_FEATURES + CONTENT_FEATURES


def extract(url: str, html: str | None = None) -> dict:
    return {**url_features(url), **content_features(html, url)}
