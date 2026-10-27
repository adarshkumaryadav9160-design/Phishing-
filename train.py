"""Train + evaluate. Usage: python train.py [data.csv]   (columns: url, label[, html])
Splits by registered domain so near-duplicate URLs from one domain never leak between train and test."""
import json
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score, average_precision_score, confusion_matrix
from sklearn.model_selection import GroupShuffleSplit
from sklearn.calibration import CalibratedClassifierCV

from features import ALL_FEATURES, extract, split_host
from urllib.parse import urlparse

try:
    from xgboost import XGBClassifier
except Exception:  # optional dependency
    XGBClassifier = None


def build_matrix(df):
    rows = [extract(u, h if isinstance(h, str) and h else None) for u, h in zip(df["url"], df.get("html", [None] * len(df)))]
    return pd.DataFrame(rows)[ALL_FEATURES]


def main(path="data/synthetic.csv"):
    df = pd.read_csv(path).dropna(subset=["url", "label"]).reset_index(drop=True)
    X, y = build_matrix(df), df["label"].astype(int).values
    groups = df["url"].map(lambda u: split_host(urlparse(u if "://" in u else "http://" + u).hostname or "")[1] or u)
    tr, te = next(GroupShuffleSplit(1, test_size=0.25, random_state=7).split(X, y, groups))

    cands = {"random_forest": RandomForestClassifier(400, min_samples_leaf=2, n_jobs=-1, random_state=7),
             "gradient_boosting": GradientBoostingClassifier(random_state=7)}
    if XGBClassifier:
        cands["xgboost"] = XGBClassifier(n_estimators=300, max_depth=5, learning_rate=0.08, subsample=0.9,
                                         eval_metric="logloss", random_state=7)
    best, best_auc, report = None, -1, {}
    for name, m in cands.items():
        m.fit(X.iloc[tr], y[tr])
        p = m.predict_proba(X.iloc[te])[:, 1]
        auc = roc_auc_score(y[te], p)
        report[name] = {"roc_auc": round(auc, 4), "pr_auc": round(average_precision_score(y[te], p), 4)}
        print(f"{name}: ROC-AUC={auc:.4f}")
        if auc > best_auc:
            best, best_auc, best_name = m, auc, name
    # calibrate so probabilities are meaningful for risk tiers
    cal = CalibratedClassifierCV(best, method="isotonic", cv=3).fit(X.iloc[tr], y[tr])
    p = cal.predict_proba(X.iloc[te])[:, 1]
    print(f"\nBest: {best_name} (calibrated) on held-out domains")
    print(classification_report(y[te], p > 0.5, target_names=["legit", "phishing"], digits=3))
    print("confusion matrix [[TN FP][FN TP]]:\n", confusion_matrix(y[te], p > 0.5))

    # URL-only ablation: how much does page content add?
    url_cols = [c for c in ALL_FEATURES if c not in __import__("features").CONTENT_FEATURES]
    ab = RandomForestClassifier(300, n_jobs=-1, random_state=7).fit(X.iloc[tr][url_cols], y[tr])
    ab_auc = roc_auc_score(y[te], ab.predict_proba(X.iloc[te][url_cols])[:, 1])
    print(f"URL-only ablation ROC-AUC={ab_auc:.4f}")

    # global importances from an uncalibrated fit (used for explanations)
    imp = getattr(best, "feature_importances_", np.zeros(len(ALL_FEATURES)))
    medians = X.iloc[tr][y[tr] == 0].median().to_dict()  # "typical legit" baseline for explanations
    joblib.dump({"model": cal, "features": ALL_FEATURES, "legit_median": medians,
                 "importances": dict(zip(ALL_FEATURES, map(float, imp))), "name": best_name}, "models/model.joblib")
    json.dump({"models": report, "best": best_name, "url_only_auc": round(ab_auc, 4), "n_train": int(len(tr)),
               "n_test": int(len(te)), "data": path}, open("models/metrics.json", "w"), indent=2)
    print("saved models/model.joblib")


if __name__ == "__main__":
    main(*sys.argv[1:])
