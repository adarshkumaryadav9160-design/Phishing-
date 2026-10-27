"""Flask app: POST /api/analyze {"url": "...", "fetch": true}  |  UI at /"""
import os

from flask import Flask, jsonify, render_template, request

from fetcher import fetch_html
from risk import Analyzer

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
analyzer = Analyzer(os.environ.get("MODEL_PATH", "models/model.joblib"))


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/analyze")
def analyze():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    if not url or len(url) > 2048 or any(c.isspace() for c in url):
        return jsonify(error="Provide a valid 'url' (max 2048 chars, no spaces)."), 400
    html, info = None, {}
    if data.get("fetch", True):
        r = fetch_html(url)
        html, info = r.pop("html"), r
    return jsonify(analyzer.analyze(url, html, info))


@app.get("/health")
def health():
    return {"status": "ok", "model": analyzer.model_name}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
