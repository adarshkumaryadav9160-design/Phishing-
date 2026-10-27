"""Risk analysis: calibrated ML probability + weighted, explainable signals (URL, domain, content, network)
-> 0-100 score, tier, evidence list, positives, and advice."""
import warnings
from urllib.parse import urlparse

import joblib
import numpy as np

import intel
from features import extract, split_host

warnings.filterwarnings("ignore", message="X does not have valid feature names")

# (category, weight 0..0.95 = how strongly this alone suggests phishing, test, message)
SIGNALS = [
    ("URL", .45, lambda f, c: f["has_ip"], "Host is a raw IP address instead of a domain name"),
    ("URL", .35, lambda f, c: f["n_at"], "URL contains '@' (can hide the real destination)"),
    ("URL", .40, lambda f, c: f["has_punycode"] or f["nonascii_host"], "Internationalised/punycode domain (possible look-alike characters)"),
    ("Domain", .75, lambda f, c: f["typosquat"], "Domain imitates a well-known brand (typosquatting / look-alike characters)"),
    ("Domain", .60, lambda f, c: f["brand_in_regname"], "Brand name embedded in an unrelated domain (e.g. brand-secure-login.xyz)"),
    ("Domain", .70, lambda f, c: f["brand_in_host_not_reg"], "Brand name in a subdomain, but the real domain belongs to someone else"),
    ("URL", .30, lambda f, c: f["n_brand_in_sub_or_path"] and not f["brand_in_host_not_reg"] and not f["brand_in_regname"] and not f["typosquat"], "Brand name in the URL path of an unrelated domain"),
    ("Domain", .20, lambda f, c: f["suspicious_tld"], "Top-level domain frequently abused for throwaway sites"),
    ("Domain", .20, lambda f, c: f["free_host"], "Hosted on a free/shared hosting platform that anyone can use"),
    ("URL", .25, lambda f, c: f["is_shortener"], "URL shortener hides the final destination"),
    ("URL", .30, lambda f, c: f["n_phish_words"] >= 2, "Several credential-lure words in URL (login, verify, secure, update...)"),
    ("URL", .30, lambda f, c: f["free_host"] and f["n_phish_words"] >= 1, "Login/verification wording on a free hosting platform"),
    ("URL", .20, lambda f, c: f["n_subdomains"] >= 4, "Unusually many subdomains"),
    ("URL", .10, lambda f, c: f["url_len"] > 100, "Very long URL"),
    ("URL", .10, lambda f, c: not f["is_https"], "Not using HTTPS (HTTPS alone does not prove a site is safe)"),
    ("URL", .20, lambda f, c: f["has_port"], "Non-standard port"),
    ("Domain", .20, lambda f, c: f["host_entropy"] > 3.7 and f["host_len"] > 16 and not f["free_host"], "Random-looking domain name"),
    ("URL", .30, lambda f, c: f["redirect_param"], "URL passes another web address as a redirect parameter (open-redirect trick)"),
    ("URL", .40, lambda f, c: f["suspicious_ext"], "URL points to an executable/archive file"),
    ("URL", .15, lambda f, c: f["n_pct_encoded"] >= 6, "Heavy percent-encoding (often used to obscure URLs)"),
    ("Domain", .10, lambda f, c: f["digits_in_regname"], "Digits mixed into the domain name"),
    # page content
    ("Content", .70, lambda f, c: f["n_password"] and f["form_ext_action"], "Password form submits to a different domain"),
    ("Content", .35, lambda f, c: f["n_password"] and f["form_empty_action"], "Password form with empty/placeholder action"),
    ("Content", .30, lambda f, c: f["n_password"] and f["form_http_action"], "Password form posts over insecure HTTP"),
    ("Content", .30, lambda f, c: f["n_password"] and not f["is_https"], "Login form on a page without HTTPS"),
    ("Content", .30, lambda f, c: f["n_password"] and f["free_host"], "Login form on a free hosting platform"),
    ("Content", .50, lambda f, c: f["has_mailto_form"], "Form sends data via mailto:"),
    ("Content", .40, lambda f, c: f["has_hidden_iframe"], "Hidden iframe on the page"),
    ("Content", .60, lambda f, c: f["title_brand_mismatch"], "Page title claims a brand that does not match the domain"),
    ("Content", .25, lambda f, c: f["has_favicon_ext"], "Favicon loaded from another domain (brand cloning)"),
    ("Content", .25, lambda f, c: f["null_link_ratio"] > .5 and f["n_links"] >= 3, "Most links are empty/placeholder"),
    ("Content", .30, lambda f, c: f["urgent_words"] >= 2, "Urgency / account-threat language in page text"),
    ("Content", .25, lambda f, c: f["has_rightclick_block"] or f["popup_js"], "Page script blocks right-click or opens popups"),
    ("Content", .20, lambda f, c: f["n_meta_refresh"], "Meta-refresh redirect"),
    # live network intelligence
    ("Network", .65, lambda f, c: (c["age"] is not None and c["age"] < 7), "Domain registered less than 7 days ago"),
    ("Network", .50, lambda f, c: (c["age"] is not None and 7 <= c["age"] < 30), "Domain registered less than 30 days ago"),
    ("Network", .25, lambda f, c: (c["age"] is not None and 30 <= c["age"] < 90), "Domain registered less than 90 days ago"),
    ("Network", .08, lambda f, c: (c["age"] is not None and 90 <= c["age"] < 365), "Domain is less than a year old"),
    ("Network", .35, lambda f, c: c["tls_invalid"], "TLS certificate is invalid (expired, self-signed or wrong host)"),
    ("Network", .12, lambda f, c: (c["cert_age"] is not None and c["cert_age"] < 7 and (c["age"] is None or c["age"] < 90)), "Brand-new TLS certificate on a young domain"),
    ("Network", .30, lambda f, c: c["dns_dead"], "Domain does not resolve (dead or never-registered host)"),
    ("Network", .25, lambda f, c: c["cross_redirect"], "Redirects to a different registered domain"),
    ("Network", .20, lambda f, c: c["many_redirects"], "Long redirect chain"),
    ("Network", .95, lambda f, c: c["gsb"], "Flagged by Google Safe Browsing"),
]

ADVICE = {
    "Low": "No strong phishing indicators found. Still avoid entering credentials unless you navigated to the site yourself.",
    "Medium": "Some suspicious traits. Do not enter credentials; verify the domain through an official channel first.",
    "High": "Likely phishing. Do not interact with it; report it to your IT/security team or the impersonated brand.",
    "Critical": "Very likely phishing. Block the URL, do not open it, and report it.",
}


def tier(score: float) -> str:
    return "Low" if score < 25 else "Medium" if score < 50 else "High" if score < 75 else "Critical"


def sev(w: float) -> str:
    return "high" if w >= .55 else "medium" if w >= .25 else "low"


def _ctx(url: str, net: dict | None, fetch_info: dict | None) -> dict:
    net = net or {}
    age = (net.get("age") or {}).get("age_days")
    tls = net.get("tls") or {}
    host = (urlparse(url if "://" in url else "http://" + url).hostname or "").lower()
    fin = (fetch_info or (net.get("page") or {})).get("final_url") or ""
    fin_reg = split_host((urlparse(fin).hostname or "").lower())[1] if fin else ""
    return {
        "age": age, "tls_invalid": tls.get("status") == "ok" and tls.get("valid") is False,
        "cert_age": tls.get("cert_age_days"),
        "dns_dead": (net.get("dns") or {}).get("resolves") is False,
        "cross_redirect": bool(fin_reg) and fin_reg != split_host(host)[1] and bool(split_host(host)[1]),
        "many_redirects": ((fetch_info or net.get("page") or {}).get("redirects") or 0) >= 3,
        "gsb": bool((net.get("gsb") or {}).get("flagged")),
    }


class Analyzer:
    def __init__(self, path="models/model.joblib"):
        b = joblib.load(path)
        self.model, self.cols, self.imp = b["model"], b["features"], b["importances"]
        self.baseline, self.model_name = b["legit_median"], b["name"]

    def analyze(self, url: str, html: str | None = None, fetch_info: dict | None = None, net: dict | None = None) -> dict:
        f = extract(url, html)
        c = _ctx(url, net, fetch_info)
        p = float(self.model.predict_proba(np.array([[f[k] for k in self.cols]], dtype=float))[:, 1][0])
        hits = [(w, cat, m) for cat, w, t, m in SIGNALS if t(f, c)]
        keep = 1.0
        for w, _, _ in hits:
            keep *= 1 - w
        rule_p = 1 - keep
        positives = []
        host = (urlparse(url if "://" in url else "http://" + url).hostname or "").lower()
        reg = split_host(host)[1]
        if c["age"] is not None and c["age"] >= 1825:
            p *= .6
            positives.append(f"Domain is established (registered about {c['age'] // 365} years ago)")
        if net and (net.get("tls") or {}).get("valid"):
            positives.append("Valid TLS certificate")
        # the model was trained on limited data, so it can add suspicion but never alone reaches 'Critical'
        final = 1 - (1 - rule_p) * (1 - .6 * p)
        score = round(100 * final, 1)
        known = intel.is_popular(reg) and not f["free_host"] and not f["has_ip"] and not f["has_punycode"]
        if known:
            score = min(score, 12.0)
            positives.insert(0, "Well-known, established domain")
        drivers = sorted(((self.imp.get(k, 0) * abs(f[k] - self.baseline.get(k, 0)) / (abs(self.baseline.get(k, 0)) + 1), k)
                          for k in self.cols), reverse=True)[:5]
        signals = [{"category": cat, "severity": sev(w), "message": m} for w, cat, m in sorted(hits, reverse=True)]
        return {
            "url": url, "domain": reg or host, "risk_score": score, "risk_level": tier(score),
            "ml_probability": round(p, 4), "rule_score": round(100 * rule_p, 1), "advice": ADVICE[tier(score)],
            "signals": signals, "reasons": [s["message"] for s in signals], "positives": positives,
            "top_model_drivers": [{"feature": k, "value": round(f[k], 3)} for w, k in drivers if w > 0],
            "content_analyzed": bool(html), "known_domain": known,
            "network": {k: v for k, v in (net or {}).items() if k != "page"},
            "fetch": fetch_info or {}, "model": self.model_name,
        }
