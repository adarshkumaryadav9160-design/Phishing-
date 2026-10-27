"""Flask app.
POST /api/analyze {"url","deep":true}   POST /api/batch {"urls":[...]}   POST /api/email {"text","deep":false}   GET /health"""
import os
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor

from flask import Flask, jsonify, render_template, request

import netcheck
from email_scan import analyze_email
from fetcher import fetch_html
from risk import Analyzer

BASE = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__, template_folder=os.path.join(BASE, "templates"))
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024
analyzer = Analyzer(os.environ.get("MODEL_PATH", os.path.join(BASE, "models", "model.joblib")))

RATE = int(os.environ.get("RATE_LIMIT_PER_MIN", "30"))
_hits = defaultdict(deque)  # best-effort per-instance limiter (serverless instances do not share memory)


@app.before_request
def limiter():
    if request.path.startswith("/api/"):
        ip = (request.headers.get("x-forwarded-for") or request.remote_addr or "?").split(",")[0].strip()
        q, now = _hits[ip], time.time()
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= RATE:
            return jsonify(error="Rate limit reached, try again in a minute."), 429
        q.append(now)


def _valid(url):
    return bool(url) and len(url) <= 2048 and not any(c.isspace() for c in url)


def _analyze(url, deep):
    if not deep:
        return analyzer.analyze(url)
    net = netcheck.deep_check(url, fetch=True)
    page = net.get("page") or {}
    return analyzer.analyze(url, page.get("html"), {k: v for k, v in page.items() if k != "html"}, net)


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/analyze")
def analyze():
    d = request.get_json(silent=True) or {}
    url = (d.get("url") or "").strip()
    if not _valid(url):
        return jsonify(error="Provide a valid 'url' (max 2048 chars, no spaces)."), 400
    return jsonify(_analyze(url, bool(d.get("deep", d.get("fetch", True)))))


@app.post("/api/batch")
def batch():
    d = request.get_json(silent=True) or {}
    urls = [u.strip() for u in (d.get("urls") or []) if isinstance(u, str) and _valid(u.strip())][:25]
    if not urls:
        return jsonify(error="Provide 'urls': a list of 1-25 valid URLs."), 400
    with ThreadPoolExecutor(8) as ex:
        res = list(ex.map(lambda u: analyzer.analyze(u), urls))
    res.sort(key=lambda r: -r["risk_score"])
    slim = [{k: r[k] for k in ("url", "domain", "risk_score", "risk_level", "reasons", "known_domain")} for r in res]
    return jsonify({"count": len(slim), "results": slim,
                    "summary": {lv: sum(r["risk_level"] == lv for r in slim) for lv in ("Low", "Medium", "High", "Critical")}})


@app.post("/api/email")
def email():
    d = request.get_json(silent=True) or {}
    text = (d.get("text") or "").strip()
    if len(text) < 10:
        return jsonify(error="Paste the email text (and headers/HTML if you have them)."), 400
    deep_fn = (lambda u: netcheck.deep_check(u, fetch=True)) if d.get("deep") else None
    return jsonify(analyze_email(text, analyzer, deep_fn))


@app.get("/health")
def health():
    return {"status": "ok", "model": analyzer.model_name, "safe_browsing": bool(os.environ.get("GSB_API_KEY"))}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
