"""Hand-written realistic cases (static URL analysis only, no network). Run: python tests/sanity_cases.py
Legit = common real-world URL shapes; phish = patterns seen in real campaigns (domains here are invented)."""
import os, sys, warnings
warnings.filterwarnings("ignore")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from risk import Analyzer

LEGIT = [
    "https://www.google.com/search?q=weather+today&hl=en", "https://accounts.google.com/signin/v2/identifier",
    "https://github.com/login", "https://docs.google.com/document/d/1AbCdEfGhIjKlMnOpQrStUvWxYz/edit",
    "https://www.amazon.in/dp/B09XYZ1234?ref=sr_1_3&th=1", "https://www.sbi.co.in/", "https://netbanking.hdfcbank.com/netbanking/",
    "https://en.wikipedia.org/wiki/Phishing", "https://stackoverflow.com/questions/12345/how-to-parse-json",
    "https://www.irctc.co.in/nget/train-search", "https://login.microsoftonline.com/common/oauth2/authorize",
    "https://www.bbc.co.uk/news/world-asia-india-12345678", "https://www.nytimes.com/2026/10/01/world/asia/story.html",
    "https://example.com/blog/how-to-bake-bread", "https://www.firstcitizens.com/personal/login", "https://medium.com/@someone/my-story-7a8b9c",
    "https://support.apple.com/en-in/HT201994", "https://www.paypal.com/signin", "https://mail.google.com/mail/u/0/#inbox",
    "https://www.flipkart.com/mobiles/pr?sid=tyy,4io&otracker=categorytree",
]
PHISH = [
    "http://paypa1-secure-login.top/signin/verify?session=a8f3k29", "https://secure-appleid.verify-account.xyz/auth/login",
    "http://hdfcbank-netbanking-update.com/login.php", "https://login-microsoftonline.com.verify.workers.dev/",
    "http://amazon-support.account-locked.icu/ap/signin", "https://sbi-online-kyc-update.xyz/customer/login",
    "http://192.0.2.45/paypal/login/index.php", "https://netfIix-billing.com/update-payment", "https://gooogle-drive-share.web.app/view",
    "http://bit.ly/3xYzAbC", "https://www.paypal.com.security-check.top/webapps/mpp/login", "https://apple-id-locked.weebly.com/login",
    "https://microsofft.com/office365/login", "http://secure.bankofamerica.com.session-4821.cfd/login", "https://binance-wallet-verify.pages.dev/connect",
    "http://amaz0n-delivery-fee.top/pay?id=8812", "https://dhl-parcel-tracking.click/pay-customs", "https://irs-refund-claim.top/verify",
    "https://x.com@evil-login.xyz/session", "https://metamask-wallet-restore.github.io/import",
]
a = Analyzer(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models", "model.joblib"))
fp = [(u, a.analyze(u)) for u in LEGIT]
fn = [(u, a.analyze(u)) for u in PHISH]
for name, rows, bad in (("LEGIT", fp, lambda r: r["risk_level"] != "Low"), ("PHISH", fn, lambda r: r["risk_level"] == "Low")):
    print(f"\n{name}")
    for u, r in rows:
        print(f"  {'!!' if bad(r) else 'ok'} {r['risk_score']:5.1f} {r['risk_level']:8s} {u}")
print(f"\nlegit flagged (not Low): {sum(r['risk_level']!='Low' for _,r in fp)}/{len(fp)}   phishing missed (Low): {sum(r['risk_level']=='Low' for _,r in fn)}/{len(fn)}")
print(f"phishing at High/Critical: {sum(r['risk_level'] in ('High','Critical') for _,r in fn)}/{len(fn)}")
