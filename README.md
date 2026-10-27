# PhishScan: ML phishing detection + risk analysis

## Features
- **URL scan**: 59 URL/domain/page features + calibrated ML model + weighted, explainable evidence (URL, Domain, Content, Network).
- **Brand-impersonation checks**: official-domain map, typosquat/homoglyph detection (paypa1, gooogle, arnazon), brand-in-subdomain, free-hosting abuse (web.app, pages.dev, github.io...).
- **Live deep scan** (works on Vercel, needs outbound internet): page fetch (SSRF-safe), domain age via RDAP, TLS certificate, DNS, redirect chain.
- **Google Safe Browsing** (optional): set env var `GSB_API_KEY`.
- **Email scan** (`POST /api/email`): urgency/threat/credential language, sender spoofing, Reply-To mismatch, link text vs real target, plus every link scored.
- **Batch scan** (`POST /api/batch`, up to 25 URLs), JSON report download, per-IP rate limit (`RATE_LIMIT_PER_MIN`, default 30).
- Well-known domains (allowlist in `intel.py`) are capped at a low score to avoid false alarms.


URL + page-content features -> calibrated classifier (RandomForest / GradientBoosting / XGBoost, best by ROC-AUC)
-> blended 0-100 risk score (75% ML probability, 25% explainable rule signals) -> tier + human-readable reasons.

## Run
    pip install -r requirements-train.txt
    python synth_data.py && python train.py        # demo data, pipeline smoke test only
    python app.py                                  # http://127.0.0.1:5000
    curl -XPOST localhost:5000/api/analyze -H 'Content-Type: application/json' -d '{"url":"http://x.example/login"}'

## IMPORTANT: train on real data
The bundled synthetic data is for testing the pipeline; its perfect scores are meaningless.
1. Phishing URLs: PhishTank or OpenPhish feeds. Legit URLs: Tranco top list (include login pages of legit sites!).
2. Make `urls.csv` (`url,label`; 1 = phishing), balance/sample realistically.
3. `python collect.py urls.csv data/real.csv` (fetches HTML; run quickly, phishing pages die fast)
4. `python train.py data/real.csv` - splits by domain to avoid leakage; also prints a URL-only ablation.
Alternatively use UCI/Kaggle phishing datasets, but they only hold pre-computed features (would need adapting `features.py`).

## Layout
features.py (50 URL+content features) · fetcher.py (SSRF-safe fetch) · train.py · risk.py (score + reasons) · app.py + templates/

## Sanity check
`python tests/sanity_cases.py` scores 20 realistic legitimate URLs and 20 phishing-style URLs (static analysis only).
These cases were written by hand alongside the rules, so treat them as a regression test, not a benchmark.

## Known limits / next steps
- Real phishing is ~1% of traffic; tune the threshold for precision on realistic base rates, not balanced accuracy.
- Add WHOIS/domain age, TLS cert age, DNS and Tranco-rank features (need network) for a big accuracy gain.
- Pages that cloak (serve benign content to scanners) or are already taken down fall back to URL-only analysis.
- Retrain regularly; phishing patterns drift. Run behind auth/rate limiting before exposing publicly.

## Deploy on Vercel
    npm i -g vercel
    vercel login && vercel --prod        # run from this folder; commit models/model.joblib (it is needed at runtime)
Vercel auto-detects the Flask `app` in `app.py` (no vercel.json needed).
`requirements.txt` holds runtime deps only (training deps are in `requirements-train.txt`). Retrain locally, then redeploy.
