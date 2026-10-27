"""Synthetic DEMO data generator (URL + HTML). Only for smoke-testing the pipeline.
Real accuracy requires real data: see collect.py and README."""
import random

import pandas as pd

WORDS = ["shop", "news", "blog", "garden", "travel", "music", "photo", "recipe", "sports", "tech", "learn",
         "city", "books", "health", "cars", "movies", "games", "forum", "design", "studio"]
LEGIT_TLD = ["com", "org", "net", "edu", "in", "co.uk", "io"]
BAD_TLD = ["xyz", "top", "tk", "ml", "click", "icu", "support", "work", "com", "net"]
BRANDS = ["paypal", "apple", "google", "microsoft", "amazon", "netflix", "hdfc", "sbi", "paytm", "binance"]
PW = ["login", "verify", "secure", "update", "account", "confirm", "signin", "wallet"]


def _rs(r, n):
    return "".join(r.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))


POP = ["google.com", "github.com", "wikipedia.org", "amazon.in", "microsoft.com", "apple.com", "bbc.co.uk", "nic.in",
       "stackoverflow.com", "medium.com", "paypal.com", "linkedin.com", "sbi.co.in", "hdfcbank.com", "flipkart.com"]
SUBS = ["www", "docs", "support", "accounts", "mail", "login", "shop", "en", "help", "api", "m", "blog"]
FREE = ["weebly.com", "wixsite.com", "web.app", "pages.dev", "netlify.app", "github.io", "blogspot.com", "firebaseapp.com", "workers.dev"]
TYPO = {"paypal": ["paypa1", "paypai", "peypal", "paypall"], "google": ["gooogle", "g00gle", "googIe"], "amazon": ["arnazon", "amaz0n", "amazom"],
        "microsoft": ["micr0soft", "rnicrosoft", "microsoflt"], "apple": ["appie", "app1e", "aple"], "netflix": ["netfIix", "netfliix"]}


def legit_popular(r):
    d = r.choice(POP)
    host = f"{r.choice(SUBS)}.{d}" if r.random() < .7 else d
    path = "/" + "/".join(_rs(r, r.randint(3, 10)) if r.random() < .4 else r.choice(WORDS) for _ in range(r.randint(0, 5)))
    q = "?" + "&".join(f"{r.choice(['utm_source','ref','id','q','lang'])}={_rs(r, r.randint(2, 20))}" for _ in range(r.randint(1, 5))) if r.random() < .45 else ""
    url = f"https://{host}{path}{q}"
    login = r.random() < .35
    html = ("<html><head><title>%s</title><link rel='icon' href='/favicon.ico'></head><body>" % d.split(".")[0].title()
            + "".join(f"<a href='/{r.choice(WORDS)}'>x</a>" for _ in range(r.randint(8, 40)))
            + ("<form action='/session' method='post'><input name=u><input type=password></form>" if login else "")
            + f"<p>{' '.join(r.choice(WORDS) for _ in range(r.randint(60, 300)))}</p></body></html>")
    return url, html


def legit(r):
    if r.random() < .4:
        return legit_popular(r)
    w = r.choice(WORDS) + r.choice(["", "-" + r.choice(WORDS)] if r.random() < .15 else [""])
    host = f"{'www.' if r.random() < .6 else ''}{w}.{r.choice(LEGIT_TLD)}"
    if r.random() < .15:
        host = f"{r.choice(BRANDS)}.com"
    path = "/" + "/".join(r.choice(WORDS) for _ in range(r.randint(0, 3)))
    if r.random() < .25:
        path += f"/{r.choice(['login','account'])}"  # legit sites have login paths too
    url = f"https://{host}{path}" + (f"?id={r.randint(1, 999)}" if r.random() < .3 else "")
    ext = lambda: f"https://cdn.{r.choice(WORDS)}.net/a.js"
    login = "/login" in url
    html = (f"<html><head><title>{r.choice(WORDS).title()}</title><link rel='icon' href='/favicon.ico'></head><body>"
            + "".join(f"<a href='/{r.choice(WORDS)}'>x</a>" for _ in range(r.randint(5, 30)))
            + (f"<a href='https://{r.choice(WORDS)}.org'>ext</a>" if r.random() < .5 else "")
            + (f"<form action='/session' method='post'><input name=u><input type=password></form>" if login else "")
            + f"<script src='{ext()}'></script><p>{' '.join(r.choice(WORDS) for _ in range(r.randint(50, 300)))}</p></body></html>")
    return url, html


def phish(r):
    b = r.choice(BRANDS)
    kind = r.random()
    if kind < .18:
        host = f"{r.choice(TYPO[r.choice(list(TYPO))])}.{r.choice(BAD_TLD + ['com', 'net', 'in'])}"
        if r.random() < .4:
            host = f"{r.choice(['secure', 'login', 'my'])}-{host}"
    elif kind < .36:
        host = f"{b}-{r.choice(PW)}-{_rs(r, r.randint(2, 5))}.{r.choice(FREE)}"
    elif kind < .45:
        host = ".".join(str(r.randint(1, 254)) for _ in range(4))
    elif kind < .6:
        host = f"{b}.{r.choice(PW)}-{_rs(r, r.randint(3, 8))}.{r.choice(BAD_TLD)}"
    elif kind < .85:
        host = f"{b}-{r.choice(PW)}.{r.choice(BAD_TLD)}"
    elif kind < .93:
        host = f"{r.choice(PW)}.{b}.com.{_rs(r, 6)}.{r.choice(BAD_TLD)}"
    else:
        host = f"{_rs(r, r.randint(8, 16))}.{r.choice(BAD_TLD)}"
    path = f"/{r.choice(PW)}/{_rs(r, r.randint(4, 12))}" + (f"/{b}" if r.random() < .5 else "")
    scheme = "https" if r.random() < .45 else "http"
    url = f"{scheme}://{host}{path}" + (f"?session={_rs(r, 12)}" if r.random() < .6 else "")
    login = r.random() < .85
    html = (f"<html><head><title>{b.title() if r.random() < .7 else ''}</title>"
            + ("<link rel='icon' href='https://%s.com/favicon.ico'>" % b if r.random() < .5 else "") + "</head><body>"
            + "".join(f"<a href='#'>x</a>" for _ in range(r.randint(0, 6)))
            + (f"<a href='https://{b}.com/help'>help</a>" if r.random() < .5 else "")
            + (f"<form action='{r.choice(['', '#', 'http://%s.ru/post.php' % _rs(r, 6), 'mailto:a@b.c'])}'><input name=u><input type=password></form>" if login else "")
            + ("<iframe src='http://x.ru' style='display:none'></iframe>" if r.random() < .3 else "")
            + (f"<p>{r.choice(['Urgent: your account is suspended', 'Verify your identity immediately', 'Unusual activity detected'])}</p>" if r.random() < .7 else "")
            + f"<img src='https://{b}.com/logo.png'></body></html>")
    return url, html


def make(n=4000, seed=42):
    r = random.Random(seed)
    rows = []
    for i in range(n):
        u, h = (phish(r) if i % 2 else legit(r))
        rows.append({"url": u, "html": h if r.random() < .8 else "", "label": i % 2})  # 20% missing html
    return pd.DataFrame(rows).sample(frac=1, random_state=seed).reset_index(drop=True)


if __name__ == "__main__":
    import os
    os.makedirs("data", exist_ok=True)
    make().to_csv("data/synthetic.csv", index=False)
    print("wrote data/synthetic.csv")
