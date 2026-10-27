"""Static threat intelligence: official brand domains, popular domains, free-hosting abuse, typosquat detection."""
import re

# brand -> registered domains that legitimately belong to it
OFFICIAL = {
    "paypal": {"paypal.com", "paypal.me"}, "apple": {"apple.com", "icloud.com"},
    "google": {"google.com", "gmail.com", "youtube.com", "goo.gl", "google.co.in", "googleusercontent.com", "gstatic.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com", "office365.com", "msn.com", "bing.com", "azure.com", "windows.com", "sharepoint.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazonaws.com", "amazon.ca", "aws.amazon.com"},
    "netflix": {"netflix.com"}, "facebook": {"facebook.com", "fb.com", "meta.com", "messenger.com"},
    "instagram": {"instagram.com"}, "whatsapp": {"whatsapp.com", "whatsapp.net"},
    "linkedin": {"linkedin.com"}, "twitter": {"twitter.com", "x.com", "t.co"},
    "github": {"github.com", "github.io", "githubusercontent.com"}, "dropbox": {"dropbox.com"},
    "adobe": {"adobe.com"}, "docusign": {"docusign.com", "docusign.net"}, "ebay": {"ebay.com", "ebay.in", "ebay.co.uk"},
    "hdfc": {"hdfcbank.com", "hdfc.com", "hdfclife.com"}, "hdfcbank": {"hdfcbank.com"},
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbicard.com", "sbilife.co.in"},
    "icici": {"icicibank.com", "icicidirect.com", "icicilombard.com"}, "axis": {"axisbank.com"},
    "kotak": {"kotak.com", "kotakbank.com"}, "paytm": {"paytm.com", "paytmbank.com"}, "phonepe": {"phonepe.com"},
    "flipkart": {"flipkart.com"}, "binance": {"binance.com", "binance.us"}, "coinbase": {"coinbase.com"},
    "metamask": {"metamask.io"}, "dhl": {"dhl.com", "dhl.de"}, "fedex": {"fedex.com"}, "ups": {"ups.com"},
    "irs": {"irs.gov"}, "chase": {"chase.com"}, "wellsfargo": {"wellsfargo.com"}, "bankofamerica": {"bankofamerica.com"},
    "citibank": {"citibank.com", "citi.com"}, "airtel": {"airtel.in", "airtel.com"}, "jio": {"jio.com"},
    "spotify": {"spotify.com"}, "steam": {"steampowered.com", "steamcommunity.com"}, "roblox": {"roblox.com"},
    "zoom": {"zoom.us"}, "telegram": {"telegram.org", "t.me"}, "outlook": {"outlook.com", "live.com", "office.com"},
}
BRANDS = sorted(OFFICIAL)

POPULAR = {  # well-known registered domains (allowlist, reduces false positives)
    "google.com", "youtube.com", "facebook.com", "wikipedia.org", "amazon.com", "twitter.com", "x.com", "instagram.com",
    "linkedin.com", "microsoft.com", "apple.com", "netflix.com", "github.com", "stackoverflow.com", "reddit.com",
    "yahoo.com", "bing.com", "live.com", "office.com", "outlook.com", "whatsapp.com", "zoom.us", "cloudflare.com",
    "adobe.com", "dropbox.com", "paypal.com", "ebay.com", "spotify.com", "twitch.tv", "pinterest.com", "tumblr.com",
    "medium.com", "bbc.com", "bbc.co.uk", "cnn.com", "nytimes.com", "theguardian.com", "forbes.com", "bloomberg.com",
    "reuters.com", "quora.com", "imdb.com", "mozilla.org", "python.org", "npmjs.com", "pypi.org", "docker.com",
    "gitlab.com", "atlassian.com", "slack.com", "notion.so", "figma.com", "canva.com", "shopify.com", "wordpress.com",
    "wordpress.org", "w3schools.com", "coursera.org", "udemy.com", "khanacademy.org", "edx.org", "salesforce.com",
    "oracle.com", "ibm.com", "intel.com", "nvidia.com", "samsung.com", "sony.com", "walmart.com", "target.com",
    "bestbuy.com", "etsy.com", "aliexpress.com", "alibaba.com", "booking.com", "airbnb.com", "tripadvisor.com",
    "uber.com", "icloud.com", "gmail.com", "telegram.org", "discord.com", "tiktok.com", "snapchat.com",
    "flipkart.com", "amazon.in", "google.co.in", "irctc.co.in", "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com",
    "icicibank.com", "axisbank.com", "kotak.com", "paytm.com", "phonepe.com", "zomato.com", "swiggy.com",
    "makemytrip.com", "nic.in", "gov.in", "india.gov.in", "isro.gov.in", "timesofindia.indiatimes.com",
    "indiatimes.com", "ndtv.com", "hindustantimes.com", "thehindu.com", "irs.gov", "usa.gov", "nih.gov", "cdc.gov",
    "who.int", "un.org", "europa.eu", "gov.uk", "nhs.uk", "mit.edu", "stanford.edu", "harvard.edu", "ox.ac.uk",
    "cam.ac.uk", "arxiv.org", "nature.com", "sciencedirect.com", "springer.com", "ieee.org", "acm.org",
    "microsoftonline.com", "sharepoint.com", "azure.com", "windows.com", "msn.com", "amazonaws.com", "fb.com",
    "meta.com", "binance.com", "coinbase.com", "chase.com", "wellsfargo.com", "bankofamerica.com", "citi.com",
    "dhl.com", "fedex.com", "ups.com", "docusign.com", "docusign.net", "openai.com", "anthropic.com", "claude.ai",
    "vercel.com", "vercel.app", "netlify.com", "heroku.com", "stripe.com", "square.com", "wise.com",
}

# platforms where anyone can host a page; frequently abused for phishing (brand kits are cheap there)
FREE_HOSTS = {
    "weebly.com", "wixsite.com", "wix.com", "blogspot.com", "000webhostapp.com", "web.app", "firebaseapp.com",
    "pages.dev", "workers.dev", "netlify.app", "herokuapp.com", "glitch.me", "repl.co", "replit.app",
    "github.io", "gitlab.io", "godaddysites.com", "sites.google.com", "forms.gle", "ipfs.io", "dweb.link",
    "r2.dev", "web.core.windows.net", "azurewebsites.net", "s3.amazonaws.com", "storage.googleapis.com",
    "square.site", "webflow.io", "carrd.co", "typedream.app", "framer.website", "notion.site", "mystrikingly.com",
    "vercel.app", "onrender.com", "fly.dev", "surge.sh", "infinityfreeapp.com", "rf.gd", "epizy.com", "ngrok.io",
    "ngrok-free.app", "trycloudflare.com", "lovestoblog.com", "wuaze.com",
}
FREE_HOST_SUFFIXES = tuple("." + h for h in FREE_HOSTS)

_HOMO = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "$": "s", "@": "a",
                       "і": "i", "ο": "o", "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "ѕ": "s", "ԁ": "d", "ɡ": "g"})


def normalize_homoglyphs(s: str) -> str:
    s = s.lower().translate(_HOMO)
    return s.replace("rn", "m").replace("vv", "w")


def lev(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 2:
        return 3
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def tokens(text: str):
    return [t for t in re.split(r"[^a-z0-9]+", text.lower()) if t]


def brand_hits(text: str):
    """Brands mentioned as whole tokens (or long brand inside a token). 'first' will not match 'irs'."""
    toks = tokens(text)
    out = []
    for b in BRANDS:
        if any(t == b or (len(b) >= 5 and b in t) for t in toks):
            out.append(b)
    return out


def is_official(brand: str, reg_domain: str) -> bool:
    return reg_domain in OFFICIAL.get(brand, set()) or reg_domain in POPULAR and brand in reg_domain


def is_popular(reg_domain: str) -> bool:
    return reg_domain in POPULAR


def is_free_host(host: str) -> bool:
    return host in FREE_HOSTS or host.endswith(FREE_HOST_SUFFIXES)


def typosquat(reg_domain: str):
    """Returns (kind, brand) if the registered domain imitates a known brand/popular domain, else None."""
    if not reg_domain or reg_domain in POPULAR or any(reg_domain in v for v in OFFICIAL.values()):
        return None
    label = reg_domain.split(".")[0]
    norm = normalize_homoglyphs(label)
    cands = {b: b for b in BRANDS}
    cands.update({p.split(".")[0]: p.split(".")[0] for p in POPULAR if len(p.split(".")[0]) >= 5})
    parts = [(norm, label)] + [(normalize_homoglyphs(t), t) for t in re.split(r"[^a-z0-9]+", label) if len(t) >= 5 and t != label]
    for n_, raw in parts:
        for name in cands:
            if len(name) < 4:
                continue
            if n_ == name and raw != name:
                return "homoglyph", name
            if len(name) >= 5 and 0 < lev(n_, name) <= 1 and abs(len(n_) - len(name)) <= 1:
                return "typosquat", name
    toks = tokens(label)
    for b in BRANDS:
        if any(t == b or (len(b) >= 5 and b in t) for t in toks) or (len(b) >= 5 and b in norm.replace("-", "")):
            return "brand-in-domain", b
    return None
