"""Risk analysis: ML probability + explainable rule signals -> 0-100 score, tier, reasons."""
import warnings

import joblib
import numpy as np

from features import extract

warnings.filterwarnings("ignore", message="X does not have valid feature names")

# (feature test, severity 1-5, message)
RULES = [
    (lambda f: f["has_ip"], 4, "Host is a raw IP address instead of a domain name"),
    (lambda f: f["n_at"], 3, "URL contains '@' (can hide the real destination)"),
    (lambda f: f["has_punycode"], 3, "Punycode domain (possible look-alike characters)"),
    (lambda f: f["suspicious_tld"], 2, "Top-level domain is often abused for throwaway sites"),
    (lambda f: f["is_shortener"], 2, "URL shortener hides the final destination"),
    (lambda f: f["brand_in_host_not_reg"], 5, "Brand name used in a subdomain, but the real domain is different"),
    (lambda f: f["n_brand_in_sub_or_path"] and not f["brand_in_host_not_reg"], 2, "Brand name appears in subdomain/path"),
    (lambda f: f["n_phish_words"] >= 2, 3, "Multiple credential-lure words in URL (login/verify/secure...)"),
    (lambda f: f["n_subdomains"] >= 3, 2, "Unusually many subdomains"),
    (lambda f: f["url_len"] > 90, 1, "Very long URL"),
    (lambda f: not f["is_https"], 1, "Not using HTTPS (note: HTTPS alone does not prove safety)"),
    (lambda f: f["has_port"], 2, "Non-standard port"),
    (lambda f: f["host_entropy"] > 3.8 and f["host_len"] > 14, 2, "Random-looking domain name"),
    (lambda f: f["n_password"] and f["form_ext_action"], 5, "Password form submits to a different domain"),
    (lambda f: f["n_password"] and f["form_empty_action"], 3, "Password form with empty/placeholder action"),
    (lambda f: f["form_http_action"] and f["n_password"], 3, "Password form posts over insecure HTTP"),
    (lambda f: f["has_mailto_form"], 4, "Form sends data via mailto:"),
    (lambda f: f["has_hidden_iframe"], 4, "Hidden iframe on page"),
    (lambda f: f["title_brand_mismatch"], 4, "Page title claims a brand that does not match the domain"),
    (lambda f: f["has_favicon_ext"], 2, "Favicon loaded from another domain (brand cloning)"),
    (lambda f: f["null_link_ratio"] > 0.5 and f["n_links"] >= 3, 2, "Most links are empty/placeholder"),
    (lambda f: f["urgent_words"] >= 2, 3, "Urgency / account-threat language in page text"),
    (lambda f: f["has_rightclick_block"] or f["popup_js"], 2, "Page script blocks right-click or opens popups"),
    (lambda f: f["n_meta_refresh"], 2, "Meta-refresh redirect"),
]
MAX_RULE = sum(s for _, s, _ in RULES)


def tier(score: float) -> str:
    return "Low" if score < 25 else "Medium" if score < 50 else "High" if score < 75 else "Critical"


ADVICE = {
    "Low": "No strong phishing indicators. Still avoid entering credentials unless you reached the site yourself.",
    "Medium": "Some suspicious traits. Do not enter credentials; verify the domain through an official channel.",
    "High": "Likely phishing. Do not interact; report it to your IT/security team or the impersonated brand.",
    "Critical": "Very likely phishing. Block the URL, do not open it, and report it.",
}


class Analyzer:
    def __init__(self, path="models/model.joblib"):
        b = joblib.load(path)
        self.model, self.cols, self.imp = b["model"], b["features"], b["importances"]
        self.baseline, self.model_name = b["legit_median"], b["name"]

    def analyze(self, url: str, html: str | None = None, fetch_info: dict | None = None) -> dict:
        f = extract(url, html)
        p = float(self.model.predict_proba(np.array([[f[c] for c in self.cols]], dtype=float))[:, 1][0])
        hits = [(s, m) for t, s, m in RULES if t(f)]
        rule_pts = min(sum(s for s, _ in hits), 15) / 15  # saturate: 15 severity points = max
        score = round(100 * (0.75 * p + 0.25 * rule_pts), 1)
        # an overwhelming rule combo should not be diluted by a confident-but-wrong model
        if any(s >= 5 for s, _ in hits) and len(hits) >= 3:
            score = max(score, 60.0)
        drivers = sorted(((self.imp.get(k, 0) * abs(f[k] - self.baseline.get(k, 0)) / (abs(self.baseline.get(k, 0)) + 1), k)
                          for k in self.cols), reverse=True)[:5]
        return {
            "url": url, "risk_score": score, "risk_level": tier(score), "ml_probability": round(p, 4),
            "advice": ADVICE[tier(score)],
            "reasons": [m for s, m in sorted(hits, reverse=True)],
            "top_model_drivers": [{"feature": k, "value": round(f[k], 3)} for w, k in drivers if w > 0],
            "content_analyzed": bool(html), "fetch": fetch_info or {}, "model": self.model_name,
        }
