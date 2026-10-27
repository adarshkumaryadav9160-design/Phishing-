"""Build a real training CSV: python collect.py urls.csv data/real.csv
urls.csv columns: url,label (1=phishing from PhishTank/OpenPhish, 0=legit from Tranco/Alexa-like lists).
Fetches HTML safely (timeouts, size cap, SSRF guard) and stores it in an 'html' column.
Run it from a network-enabled machine. Phishing pages go offline fast: fetch soon after downloading the feed."""
import sys
from concurrent.futures import ThreadPoolExecutor

import pandas as pd

from fetcher import fetch_html


def main(src, dst):
    df = pd.read_csv(src)
    with ThreadPoolExecutor(16) as ex:
        res = list(ex.map(lambda u: fetch_html(u).get("html") or "", df["url"]))
    df["html"] = res
    df.to_csv(dst, index=False)
    print(f"saved {len(df)} rows, {sum(bool(x) for x in res)} with HTML -> {dst}")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
