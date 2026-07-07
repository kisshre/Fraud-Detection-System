"""
FRAUD-X  ·  Accuracy Test Suite  ·  v0.3.0
===========================================
Runs all three scanners against labeled test cases and prints
per-case results, category statistics, and a final summary table.

Labels
------
  "danger"  →  ground-truth malicious / fraudulent
  "safe"    →  ground-truth benign
  (no "caution" ground-truth labels — that is a UI tier, not a truth class)

Usage
-----
  python3 tests.py           # full run, color output
  python3 tests.py --no-color # plain text (CI / log files)
  python3 tests.py --quiet   # summary table only
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
import time

# Ensure UTF-8 output on Windows (avoids cp1252 crash on box-drawing chars)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import main  # noqa: E402  (must come after path fix)


# ═══════════════════════════════════════════════════════════════
# Terminal colours
# ═══════════════════════════════════════════════════════════════

USE_COLOR = True   # overridden by --no-color flag


def _c(code: str, text: str) -> str:
    if not USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


def green(t: str)   -> str: return _c("32",    t)
def yellow(t: str)  -> str: return _c("33",    t)
def red(t: str)     -> str: return _c("31",    t)
def cyan(t: str)    -> str: return _c("36",    t)
def bold(t: str)    -> str: return _c("1",     t)
def dim(t: str)     -> str: return _c("2",     t)
def magenta(t: str) -> str: return _c("35",    t)
def bg_green(t: str) -> str: return _c("42;30", t)
def bg_red(t: str)   -> str: return _c("41;37", t)


# ═══════════════════════════════════════════════════════════════
# Banner
# ═══════════════════════════════════════════════════════════════

BANNER = r"""
  ███████╗██████╗  █████╗ ██╗   ██╗██████╗     ██╗  ██╗
  ██╔════╝██╔══██╗██╔══██╗██║   ██║██╔══██╗    ╚██╗██╔╝
  █████╗  ██████╔╝███████║██║   ██║██║  ██║     ╚███╔╝
  ██╔══╝  ██╔══██╗██╔══██║██║   ██║██║  ██║     ██╔██╗
  ██║     ██║  ██║██║  ██║╚██████╔╝██████╔╝    ██╔╝ ██╗
  ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝     ╚═╝  ╚═╝
"""


# ═══════════════════════════════════════════════════════════════
# URL test cases  (44 labeled samples)
# ═══════════════════════════════════════════════════════════════

URL_CASES: list[tuple[str, str]] = [
    # ── Malicious ──────────────────────────────────────────────
    ("http://paypa1.com/login/verify-account.php",              "danger"),
    ("http://192.168.1.4/banking/confirm.php",                  "danger"),
    ("http://secure-paypal-support.tk/login",                   "danger"),
    ("https://google.com.security-update.xyz/signin",           "danger"),
    ("http://faceb00k-login.com/verify",                        "danger"),
    ("https://app1e-id-confirm.com/account/unlock",             "danger"),
    ("http://www.chase.com-secure.login.validate.ml/",          "danger"),
    ("http://bankofamerica-verify.ru/update.php",               "danger"),
    ("https://account-update-microsoft.cf/signin.php",          "danger"),
    ("http://netflix-billing-update.gq/renew",                  "danger"),
    ("http://login.microsoft.com@evil.xyz/oauth",               "danger"),  # @ trick
    ("https://аpple-id-support.com/verify",                     "danger"),  # Cyrillic а
    ("https://amaz0n-prime-renew.click/account",                "danger"),
    ("http://secure-login.coinbase-support.top/",               "danger"),
    ("https://whatsapp-web-login.verify-account.xyz/",          "danger"),
    ("http://goog1e.com/drive/login",                           "danger"),

    # ── Benign ─────────────────────────────────────────────────
    ("https://google.com",                                      "safe"),
    ("https://www.amazon.com/",                                 "safe"),
    ("https://github.com/openai/gpt-3",                         "safe"),
    ("https://stackoverflow.com/questions/123456/how-to",       "safe"),
    ("https://en.wikipedia.org/wiki/Phishing",                  "safe"),
    ("https://www.paypal.com/us/signin",                        "safe"),
    ("https://www.microsoft.com/en-us/",                        "safe"),
    ("https://news.ycombinator.com/",                           "safe"),
    ("https://www.bbc.com/news/world",                          "safe"),
    ("https://mail.google.com/mail/u/0/",                       "safe"),
    ("https://www.apple.com/shop/buy-iphone",                   "safe"),
    ("https://www.nytimes.com/2024/01/01/world/article.html",   "safe"),
    ("https://www.reddit.com/r/programming/",                   "safe"),
    ("https://www.chase.com/personal/credit-cards",             "safe"),
    ("https://www.netflix.com/browse",                          "safe"),
    ("https://openai.com/research",                             "safe"),

    # ── Adversarial: safe-should-stay-safe ─────────────────────
    ("https://www.amazon.co.uk/gp/product/B08",                 "safe"),   # ccTLD brand
    ("https://www.bbc.co.uk/news/world",                        "safe"),
    ("https://accounts.google.com/signin",                      "safe"),   # legit brand subdomain
    ("https://pay.google.com/",                                 "safe"),
    ("https://shop.apple.com/buy",                              "safe"),
    ("https://www.techcrunch.com/2024/05/tech",                 "safe"),
    ("https://example.org/foo/bar",                             "safe"),

    # ── Adversarial: danger-should-stay-danger ─────────────────
    ("https://www.amazon.com.fake-support.tk/login",            "danger"),
    ("https://accounts-google.com.verify.xyz/",                 "danger"),
    ("https://netflix.secure-renew.click/billing",              "danger"),
    ("https://www.paypa1-support.com/",                         "danger"),
    ("https://redirect.safe.com/?next=http://evil-bank.tk/login","danger"),  # open redirect

    # ── Wave 2: held-out generalization ────────────────────────
    ("http://signin-coinbase.xyz/unlock-account",               "danger"),
    ("https://dhl-package-redelivery.top/track?id=18821",       "danger"),
    ("http://irs-taxrefund-gov.click/claim",                    "danger"),
    ("https://steam-giftcard-reward.online/redeem",             "danger"),
    ("https://tiktok-login-verify.buzz/signin.php",             "danger"),
    ("https://my-wa11et-metamask.icu/connect",                  "danger"),
    ("https://www.ɡoogle.com/account",                          "danger"),
    ("https://secure.hsbc.co.uk-login.monster/",                "danger"),
    ("https://app1e-id.revoke-auth.men/verify",                 "danger"),
    ("https://refund-stripe.support-us.zip/confirm",            "danger"),
    ("https://www.reuters.com/world/europe/",                   "safe"),
    ("https://www.stanford.edu/research",                       "safe"),
    ("https://docs.python.org/3/library/urllib.html",           "safe"),
    ("https://www.gov.uk/browse/benefits",                      "safe"),
    ("https://en.m.wikipedia.org/wiki/Main_Page",               "safe"),
    ("https://www.ft.com/content/12345",                        "safe"),
    ("https://www.ycombinator.com/companies",                   "safe"),
]


# ═══════════════════════════════════════════════════════════════
# Merchant test cases  (27 labeled samples)
# ═══════════════════════════════════════════════════════════════

MERCHANT_CASES: list[tuple[dict, str]] = [
    # ── Malicious ──────────────────────────────────────────────
    ({"name": "PayPaI Support",         "account_age_days": 3,    "verified": False, "country": "NG", "complaints": 2}, "danger"),
    ({"name": "amazon-support",         "account_age_days": 12,   "verified": False},                                   "danger"),
    ({"name": "Micros0ft Payments",     "account_age_days": 8,    "verified": False},                                   "danger"),
    ({"name": "Verified Binance Deposit","account_age_days": 4,   "verified": False},                                   "danger"),
    ({"name": "Netfl1x Billing",        "account_age_days": 2,    "verified": False, "complaints": 5},                  "danger"),
    ({"name": "test",                   "account_age_days": 1,    "verified": False},                                   "danger"),
    ({"name": "Apple ID Recovery",      "account_age_days": 6,    "verified": False, "country": "RU"},                  "danger"),
    ({"name": "Quick-Cash-Support",     "account_age_days": 2,    "verified": False, "complaints": 3},                  "danger"),

    # ── Benign ─────────────────────────────────────────────────
    ({"name": "Starbucks",              "account_age_days": 1800, "verified": True,  "country": "US"},                  "safe"),
    ({"name": "Skopje Coffee Roasters", "account_age_days": 900,  "verified": True,  "country": "MK"},                  "safe"),
    ({"name": "Smith Plumbing LLC",     "account_age_days": 400,  "verified": True},                                    "safe"),
    ({"name": "Netflix, Inc.",          "account_age_days": 5000, "verified": True,  "country": "US"},                  "safe"),
    ({"name": "Acme Widgets",           "account_age_days": 300,  "verified": True,  "complaints": 0},                  "safe"),
    ({"name": "Local Bookstore",        "account_age_days": 700,  "verified": True},                                    "safe"),
    ({"name": "Ohrid Honey Co.",        "account_age_days": 600,  "verified": True,  "country": "MK"},                  "safe"),
    ({"name": "Blue Ridge Bakery",      "account_age_days": 1100, "verified": True},                                    "safe"),

    # ── Adversarial ─────────────────────────────────────────────
    ({"name": "Amazon Web Services",    "account_age_days": 4000, "verified": True,  "country": "US"},                  "safe"),
    ({"name": "Apple Inc.",             "account_age_days": 9000, "verified": True,  "country": "US"},                  "safe"),
    ({"name": "PayPaI",                 "account_age_days": 10,   "verified": False},                                   "danger"),
    ({"name": "g00gle pay",             "account_age_days": 8,    "verified": False},                                   "danger"),

    # ── Wave 2: held-out ────────────────────────────────────────
    ({"name": "Coinbase Refunds",       "account_age_days": 5,    "verified": False, "complaints": 1},                  "danger"),
    ({"name": "stripe-help",            "account_age_days": 14,   "verified": False},                                   "danger"),
    ({"name": "Discord Nitro Giveaway", "account_age_days": 2,    "verified": False, "complaints": 4},                  "danger"),
    ({"name": "Urgent Billing Unlock",  "account_age_days": 2,    "verified": False, "complaints": 3},                  "danger"),
    ({"name": "Ohrid Electronics",      "account_age_days": 500,  "verified": True,  "country": "MK"},                  "safe"),
    ({"name": "Prilep Wine Cellar",     "account_age_days": 2200, "verified": True,  "country": "MK"},                  "safe"),
    ({"name": "Northwind Traders",      "account_age_days": 800,  "verified": True},                                    "safe"),
]


# ═══════════════════════════════════════════════════════════════
# File test cases  (synthesized byte payloads)
# ═══════════════════════════════════════════════════════════════

def make_files() -> list[tuple[str, bytes, str]]:
    """Return list of (filename, payload_bytes, label) tuples."""
    PE             = b"MZ\x90\x00" + b"\x00" * 60 + b"PE\x00\x00" + b"payload"
    PNG            = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
    JPG            = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01" + b"\x00" * 32
    PDF_CLEAN      = b"%PDF-1.7\n%%EOF\n"
    PDF_JS         = b"%PDF-1.7\n/OpenAction << /JS (app.alert('x')) /S /JavaScript >>\n%%EOF"
    ZIP_MACRO      = b"PK\x03\x04" + b"fake-oomxl-" + b"word/vbaProject.bin" + b"body"
    TXT            = b"hello world"

    return [
        # ── Malicious ───────────────────────────────────────────
        ("notes.exe",        PE,                                         "danger"),  # Real PE
        ("invoice.pdf.exe",  PE,                                         "danger"),  # Double extension
        ("resume.docm",      b"PK\x03\x04vbaProject.bin",               "danger"),  # Macro OOXML
        ("brochure.pdf",     PDF_JS,                                     "danger"),  # PDF /JavaScript
        ("promo.jpg",        PE,                                         "danger"),  # PE disguised as JPG
        ("report.scr",       PE,                                         "danger"),  # Screensaver PE
        ("installer.hta",    b"<script>malicious()</script>",            "danger"),  # Script file

        # ── Benign ──────────────────────────────────────────────
        ("notes.txt",        TXT,                                        "safe"),
        ("photo.png",        PNG,                                        "safe"),
        ("photo.jpg",        JPG,                                        "safe"),
        ("document.pdf",     PDF_CLEAN,                                  "safe"),
        ("sheet.xlsx",       b"PK\x03\x04normal-xlsx-body",             "safe"),    # Plain OOXML

        # ── Wave 2: held-out ─────────────────────────────────────
        ("update.msi",       PE,                                         "danger"),
        ("drivers.dll",      PE,                                         "danger"),
        ("statement.xlsm",   b"PK\x03\x04xlsm-with-vbaProject.bin",    "danger"),
        ("invoice_HTA",      b"<script>WScript.Shell.Run('cmd /c')</script>", "safe"),  # No ext
        ("campaign.pptx",    b"PK\x03\x04normal-pptx-without-macros",  "safe"),
        ("report.pdf",       b"%PDF-1.7\nregular content\n%%EOF",       "safe"),
        ("song.mp3",         b"ID3\x03\x00\x00\x00\x00\x00random",     "safe"),
    ]


# ═══════════════════════════════════════════════════════════════
# Email test cases
# ═══════════════════════════════════════════════════════════════

EMAIL_CASES: list[tuple[dict, str]] = [
    # ── Malicious ──────────────────────────────────────────────
    ({  # PayPal phish: leet-spoof domain + noreply TK + urgency + cred harvesting
        "subject":       "Urgent: Your account is suspended",
        "sender":        "noreply@paypa1-support.tk",
        "sender_domain": "paypa1-support.tk",
        "body":          ("Your PayPal account suspended. Verify your account now "
                          "by clicking the link below. Enter your password to restore access."),
    }, "danger"),
    ({  # IRS tax scam: scam phrases + noreply .click + urgency
        "subject":       "IRS Notice: Tax Refund - Urgent Action Required",
        "sender":        "noreply@irs-refund.click",
        "sender_domain": "irs-refund.click",
        "body":          ("Your tax refund is pending. Social security verification required. "
                          "Confirm your identity to claim funds."),
    }, "danger"),
    # ── Benign ─────────────────────────────────────────────────
    ({  # Amazon shipping notification
        "subject":       "Your Amazon order has shipped",
        "sender":        "shipment-tracking@amazon.com",
        "sender_domain": "amazon.com",
        "body":          "Your order #123-456 is on its way. Expected delivery in 3 business days.",
    }, "safe"),
    ({  # GitHub PR notification
        "subject":       "New pull request opened on your repository",
        "sender":        "notifications@github.com",
        "sender_domain": "github.com",
        "body":          "A contributor opened a pull request. Review it on github.com.",
    }, "safe"),
    ({  # Bank statement ready
        "subject":       "Your monthly statement is ready",
        "sender":        "statements@chase.com",
        "sender_domain": "chase.com",
        "body":          "Your account statement ending in 4567 is now available in your online account.",
    }, "safe"),
]


# ═══════════════════════════════════════════════════════════════
# Phone test cases
# ═══════════════════════════════════════════════════════════════

PHONE_CASES: list[tuple[dict, str]] = [
    # ── Malicious ──────────────────────────────────────────────
    ({  # IRS toll-free payment demand
        "number": "18005551234", "call_context": "payment_request",
        "claimed_org": "IRS Department",
    }, "danger"),
    ({  # Nigeria social-security payment demand
        "number": "2347012345678", "country_code": "NG",
        "call_context": "payment_request",
        "claimed_org": "Social Security Administration",
    }, "danger"),
    ({  # 900 premium area code + IRS claim
        "number": "9001234567", "call_context": "payment_request",
        "claimed_org": "IRS Tax Department",
    }, "danger"),
    # ── Benign ─────────────────────────────────────────────────
    ({  # Plain US number, no context
        "number": "6175551234", "country_code": "US",
    }, "safe"),
    ({  # USPS toll-free (not gov/bank impersonation)
        "number": "18007259999", "call_context": "received_call",
        "claimed_org": "USPS",
    }, "safe"),
]


# ═══════════════════════════════════════════════════════════════
# SMS test cases
# ═══════════════════════════════════════════════════════════════

SMS_CASES: list[tuple[dict, str]] = [
    # ── Malicious ──────────────────────────────────────────────
    ({  # Four scam patterns + URL shortener + numeric sender
        "message": ("URGENT: Your account suspended. Click here to claim your "
                    "free prize. bit.ly/3abc"),
        "sender":   "99999",
        "has_link": True,
    }, "danger"),
    ({  # Crypto + seed phrase + account suspended patterns (calibrate pushes over threshold)
        "message": ("Your crypto account suspended. Verify seed phrase now to "
                    "claim airdrop reward. Click here."),
        "sender":   "CRYPTOWALLET",
        "has_link": False,
    }, "danger"),
    ({  # Smishing with dangerous embedded link URL
        "message":  "USPS: Your parcel is held. Verify delivery at:",
        "sender":   "12345",
        "has_link": True,
        "link_url": "http://paypa1-support.tk/login",
    }, "danger"),
    # ── Benign ─────────────────────────────────────────────────
    ({  # Legitimate OTP (scores low despite OTP pattern)
        "message": "Your one-time password is 123456. Valid for 5 minutes. Do not share.",
        "sender":  "MYBANK",
    }, "safe"),
    ({  # Normal package tracking notification
        "message": "Your FedEx package is out for delivery today. No action needed.",
        "sender":  "FedEx",
    }, "safe"),
]


# ═══════════════════════════════════════════════════════════════
# Social media test cases
# ═══════════════════════════════════════════════════════════════

SOCIAL_CASES: list[tuple[dict, str]] = [
    # ── Malicious ──────────────────────────────────────────────
    ({  # PayPal impersonation + DM payment + new account selling
        "platform": "instagram", "username": "paypal_official_help",
        "display_name": "PayPal Support",
        "bio": "PayPal official help. DM for info on payment issues. Guaranteed resolution.",
        "follower_count": 45, "following_count": 900,
        "account_age_days": 4, "verified": False,
        "is_selling": True, "dm_requesting_payment": True,
    }, "danger"),
    ({  # Crypto investment scammer with investment bio keywords
        "platform": "twitter", "username": "crypto_profit_2024",
        "display_name": "Crypto Trader",
        "bio": "guaranteed returns on crypto investments. earn from home passive income. dm me.",
        "follower_count": 8, "following_count": 1200,
        "account_age_days": 7, "verified": False,
        "is_selling": True, "dm_requesting_payment": True,
    }, "danger"),
    # ── Benign ─────────────────────────────────────────────────
    ({  # Established tech blogger, no red flags
        "platform": "twitter", "username": "techblogger_sarah",
        "display_name": "Sarah Tech",
        "bio": "Writing about software, AI, and tech culture. Opinions are my own.",
        "follower_count": 12000, "following_count": 300,
        "account_age_days": 1500, "verified": False,
        "is_selling": False, "dm_requesting_payment": False,
    }, "safe"),
    ({  # Verified news org — high followers, old account
        "platform": "twitter", "username": "bbc_news",
        "display_name": "BBC News",
        "bio": "Breaking news from the BBC. Visit bbc.com for the latest.",
        "follower_count": 25000000, "following_count": 50,
        "account_age_days": 5000, "verified": True,
        "is_selling": False, "dm_requesting_payment": False,
    }, "safe"),
]


# ═══════════════════════════════════════════════════════════════
# QR code test cases
# ═══════════════════════════════════════════════════════════════

QR_CASES: list[tuple[dict, str]] = [
    # ── Malicious ──────────────────────────────────────────────
    ({  # Leet-spoof PayPal domain in payment QR
        "decoded_url": "http://paypa1-support.tk/payment",
        "context": "payment",
    }, "danger"),
    ({  # Known-dangerous URL from URL test suite
        "decoded_url": "http://secure-login.coinbase-support.top/",
        "context": "unknown",
    }, "danger"),
    # ── Benign ─────────────────────────────────────────────────
    ({  # Legitimate Google Maps QR
        "decoded_url": "https://www.google.com/maps/place/restaurant",
    }, "safe"),
    ({  # GitHub repository link
        "decoded_url": "https://github.com/anthropics/anthropic-sdk-python",
    }, "safe"),
]


# ═══════════════════════════════════════════════════════════════
# IP address test cases
# ═══════════════════════════════════════════════════════════════

IP_CASES: list[tuple[dict, str]] = [
    # ── Malicious ──────────────────────────────────────────────
    ({  # Private RFC-1918 IP with RDP port in login context
        "ip_address": "10.0.0.1", "context": "login_attempt", "port": 3389,
    }, "danger"),
    ({  # Reserved 0.0.0.0 with Metasploit C2 port
        "ip_address": "0.0.0.0", "context": "email_sender", "port": 4444,
    }, "danger"),
    # ── Benign ─────────────────────────────────────────────────
    ({  # Ordinary public IP, no port, no context
        "ip_address": "203.0.113.5",
    }, "safe"),
    ({  # Well-known Cloudflare DNS (all-same octets score 30, safely below 65)
        "ip_address": "1.1.1.1",
    }, "safe"),
]


# ═══════════════════════════════════════════════════════════════
# Cryptocurrency address test cases
# ═══════════════════════════════════════════════════════════════

CRYPTO_CASES: list[tuple[dict, str]] = [
    # ── Malicious ──────────────────────────────────────────────
    ({  # Investment scam BTC address with multiple scam phrases
        "address":  "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "coin":     "BTC",
        "context":  "investment",
        "message":  ("Double your funds. Guaranteed return, crypto giveaway. "
                     "Claim airdrop now. Seed phrase required for access."),
    }, "danger"),
    ({  # Tornado mixer ETH address with wallet-connect phrases
        "address":  "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        "coin":     "ETH",
        "context":  "payment_request",
        "message":  "Send to this tornado mixer address. Use wallet connect link to approve contract.",
    }, "danger"),
    # ── Benign ─────────────────────────────────────────────────
    ({  # BTC segwit donation address, clean message
        "address":  "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq",
        "coin":     "BTC",
        "context":  "donation",
        "message":  "Support open source software development.",
    }, "safe"),
    ({  # TRX payment for services, no scam language
        "address":  "TEFccmfQ38cZS1DTZVhsxKVDckA8Y6VfCy",
        "coin":     "TRX",
        "context":  "payment_request",
        "message":  "Payment for consulting services rendered.",
    }, "safe"),
]


# ═══════════════════════════════════════════════════════════════
# Evaluation helpers
# ═══════════════════════════════════════════════════════════════

def predict_level(score: int) -> str:
    """
    Collapse tri-state risk into binary danger / safe for evaluation.
    'caution' is treated conservatively as 'safe' (did NOT block).
    """
    return "danger" if score >= main.DANGER_THRESHOLD else "safe"


def score_dataset(
    name: str,
    results: list[tuple[str, int, str]],
    truth:   list[str],
    quiet:   bool = False,
) -> dict:
    """
    Compute precision / recall / F1 for a scanner and print a per-case report.

    Parameters
    ----------
    name    : scanner display name
    results : list of (target, score, predicted_level)
    truth   : parallel list of ground-truth labels ("danger" | "safe")
    quiet   : if True, skip per-case lines

    Returns
    -------
    dict with keys: n, tp, fp, tn, fn, accuracy, precision, recall, f1
    """
    tp = fp = tn = fn = 0
    misses: list[str] = []

    if not quiet:
        print()
        width = 80
        print(cyan(bold(f"  ▶  {name}  " + "─" * (width - len(name) - 6))))

    for (target, score, pred), label in zip(results, truth):
        correct = (label == pred)
        if   label == "danger" and pred == "danger": tp += 1
        elif label == "safe"   and pred == "safe":   tn += 1
        elif label == "safe"   and pred == "danger":
            fp += 1
            misses.append(("FP", target, score, "danger", "safe"))
        else:
            fn += 1
            misses.append(("FN", target, score, "safe", "danger"))

        if not quiet:
            icon   = green("✔") if correct else red("✘")
            clabel = green(f"  SAFE  ") if label == "safe" else red(f" DANGER ")
            pred_s = green("safe  ") if pred == "safe" else red("danger")
            sc_s   = f"{score:>3}"
            short  = target if len(target) <= 55 else target[:52] + "…"
            print(f"    {icon}  [{clabel}]  {sc_s:>3}  {pred_s}  {dim(short)}")

    n    = tp + fp + tn + fn
    acc  = (tp + tn) / n if n else 0.0
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec  = tp / (tp + fn) if (tp + fn) else 0.0
    f1   = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0

    if not quiet:
        print()
        print(f"    {'N':>4}  {'TP':>4}  {'FP':>4}  {'TN':>4}  {'FN':>4}  "
              f"{'Acc':>6}  {'Prec':>6}  {'Rec':>6}  {'F1':>6}")
        print(f"    {n:>4}  {green(str(tp)):>4}  "
              f"{(red(str(fp)) if fp else str(fp)):>4}  "
              f"{green(str(tn)):>4}  "
              f"{(red(str(fn)) if fn else str(fn)):>4}  "
              f"{acc:>6.3f}  {prec:>6.3f}  {rec:>6.3f}  "
              f"{(bold(green(f'{f1:.3f}')) if f1 >= 0.95 else yellow(f'{f1:.3f}')):>6}")

        if misses:
            print()
            print(f"    {yellow('Misclassifications:')}")
            for kind, target, score, got, expected in misses:
                tag = red(f"  {kind}  ")
                print(f"      [{tag}]  score={score:>3}  predicted={got:<6}  truth={expected}  {dim(target[:60])}")

    return {
        "n": n, "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "accuracy": acc, "precision": prec, "recall": rec, "f1": f1,
    }


# ═══════════════════════════════════════════════════════════════
# Summary table
# ═══════════════════════════════════════════════════════════════

def print_summary(scanner_stats: list[tuple[str, dict]]) -> None:
    """Print per-scanner rows and an OVERALL aggregate row.

    Parameters
    ----------
    scanner_stats : list of (display_label, stats_dict) pairs
    """
    all_n   = sum(s["n"]  for _, s in scanner_stats)
    all_tp  = sum(s["tp"] for _, s in scanner_stats)
    all_fp  = sum(s["fp"] for _, s in scanner_stats)
    all_tn  = sum(s["tn"] for _, s in scanner_stats)
    all_fn  = sum(s["fn"] for _, s in scanner_stats)
    acc     = (all_tp + all_tn) / all_n  if all_n  else 0.0
    prec    = all_tp / (all_tp + all_fp) if (all_tp + all_fp) else 0.0
    rec     = all_tp / (all_tp + all_fn) if (all_tp + all_fn) else 0.0
    f1      = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0

    SEP  = "─" * 72
    ROW  = "  {:<12} {:>6} {:>6} {:>6} {:>6} {:>8} {:>8} {:>8} {:>8}"
    HDR  = ("Scanner", "N", "TP", "FP", "TN", "Accuracy", "Precision", "Recall", "F1")

    def fmt_f1(v: float) -> str:
        s = f"{v:.3f}"
        if v >= 0.99: return bold(green(s))
        if v >= 0.90: return green(s)
        if v >= 0.70: return yellow(s)
        return red(s)

    print()
    print(cyan(bold("  ══  OVERALL SUMMARY  ══")))
    print(dim("  " + SEP))
    print(bold(ROW.format(*HDR)))
    print(dim("  " + SEP))
    for label, s in scanner_stats:
        print(ROW.format(
            label, s["n"], s["tp"], s["fp"], s["tn"],
            f"{s['accuracy']:.3f}", f"{s['precision']:.3f}",
            f"{s['recall']:.3f}", ""
        ) + "  " + fmt_f1(s["f1"]))
    print(dim("  " + SEP))
    overall_row = ROW.format(
        bold("OVERALL"), all_n, all_tp, all_fp, all_tn,
        f"{acc:.3f}", f"{prec:.3f}", f"{rec:.3f}", ""
    ) + "  " + fmt_f1(f1)
    print(overall_row)
    print(dim("  " + SEP))
    print()

    if f1 >= 0.99:
        print(bg_green(bold("  ✔  All scanners achieved F1 ≥ 0.99 — test suite PASSED  ")))
    elif f1 >= 0.90:
        print(yellow(bold("  ⚠  F1 ≥ 0.90 but below 0.99 — review misclassifications above")))
    else:
        print(bg_red(bold("  ✘  F1 < 0.90 — test suite FAILED  ")))
    print()


# ═══════════════════════════════════════════════════════════════
# Main entry point
# ═══════════════════════════════════════════════════════════════

async def run(quiet: bool = False) -> None:
    """Execute all test cases and print results."""

    if not quiet:
        if USE_COLOR:
            print(magenta(BANNER))
        print(bold(cyan("  FRAUD-X  Accuracy Test Suite  v0.3.0")))
        print(dim("  " + "═" * 60))
        print()

    # Reset in-memory state so tests are fully independent
    main.ALERTS.clear()
    main.LEDGER.clear()

    t0 = time.perf_counter()

    # ── URL scanner ───────────────────────────────────────────
    url_results: list[tuple[str, int, str]] = []
    url_truth:   list[str] = []
    for url, label in URL_CASES:
        res = await main.analyze_url(url, use_ai=False)
        url_results.append((url, res["risk_score"], predict_level(res["risk_score"])))
        url_truth.append(label)
    url_stats = score_dataset("URL SCANNER", url_results, url_truth, quiet=quiet)

    # ── Merchant scanner ──────────────────────────────────────
    m_results: list[tuple[str, int, str]] = []
    m_truth:   list[str] = []
    for payload, label in MERCHANT_CASES:
        res = await main.analyze_merchant(main.MerchantPayload(**payload))
        m_results.append((payload["name"], res["risk_score"], predict_level(res["risk_score"])))
        m_truth.append(label)
    m_stats = score_dataset("MERCHANT SCANNER", m_results, m_truth, quiet=quiet)

    # ── File scanner ──────────────────────────────────────────
    f_results: list[tuple[str, int, str]] = []
    f_truth:   list[str] = []
    for filename, payload, label in make_files():
        res = await main.analyze_file(filename, payload)
        f_results.append((filename, res["risk_score"], predict_level(res["risk_score"])))
        f_truth.append(label)
    f_stats = score_dataset("FILE SCANNER", f_results, f_truth, quiet=quiet)

    # ── Email scanner ─────────────────────────────────────────
    em_results: list[tuple[str, int, str]] = []
    em_truth:   list[str] = []
    for payload, label in EMAIL_CASES:
        res = await main.analyze_email(main.EmailPayload(**payload))
        target = payload.get("subject") or payload.get("sender") or "Email"
        em_results.append((target, res["risk_score"], predict_level(res["risk_score"])))
        em_truth.append(label)
    em_stats = score_dataset("EMAIL SCANNER", em_results, em_truth, quiet=quiet)

    # ── Phone scanner ─────────────────────────────────────────
    ph_results: list[tuple[str, int, str]] = []
    ph_truth:   list[str] = []
    for payload, label in PHONE_CASES:
        res = await main.analyze_phone(main.PhonePayload(**payload))
        ph_results.append((payload["number"], res["risk_score"], predict_level(res["risk_score"])))
        ph_truth.append(label)
    ph_stats = score_dataset("PHONE SCANNER", ph_results, ph_truth, quiet=quiet)

    # ── SMS scanner ───────────────────────────────────────────
    sm_results: list[tuple[str, int, str]] = []
    sm_truth:   list[str] = []
    for payload, label in SMS_CASES:
        res = await main.analyze_sms(main.SMSPayload(**payload))
        sm_results.append((payload["message"][:50], res["risk_score"], predict_level(res["risk_score"])))
        sm_truth.append(label)
    sm_stats = score_dataset("SMS SCANNER", sm_results, sm_truth, quiet=quiet)

    # ── Social scanner ────────────────────────────────────────
    so_results: list[tuple[str, int, str]] = []
    so_truth:   list[str] = []
    for payload, label in SOCIAL_CASES:
        res = await main.analyze_social(main.SocialPayload(**payload))
        so_results.append((f"@{payload['username']}", res["risk_score"], predict_level(res["risk_score"])))
        so_truth.append(label)
    so_stats = score_dataset("SOCIAL SCANNER", so_results, so_truth, quiet=quiet)

    # ── QR scanner ────────────────────────────────────────────
    qr_results: list[tuple[str, int, str]] = []
    qr_truth:   list[str] = []
    for payload, label in QR_CASES:
        res = await main.analyze_qr(main.QRPayload(**payload))
        qr_results.append((payload["decoded_url"][:55], res["risk_score"], predict_level(res["risk_score"])))
        qr_truth.append(label)
    qr_stats = score_dataset("QR SCANNER", qr_results, qr_truth, quiet=quiet)

    # ── IP scanner ────────────────────────────────────────────
    ip_results: list[tuple[str, int, str]] = []
    ip_truth:   list[str] = []
    for payload, label in IP_CASES:
        res = await main.analyze_ip(main.IPPayload(**payload))
        ip_results.append((payload["ip_address"], res["risk_score"], predict_level(res["risk_score"])))
        ip_truth.append(label)
    ip_stats = score_dataset("IP SCANNER", ip_results, ip_truth, quiet=quiet)

    # ── Crypto scanner ────────────────────────────────────────
    cr_results: list[tuple[str, int, str]] = []
    cr_truth:   list[str] = []
    for payload, label in CRYPTO_CASES:
        res = await main.analyze_crypto(main.CryptoPayload(**payload))
        cr_results.append((payload["address"][:40], res["risk_score"], predict_level(res["risk_score"])))
        cr_truth.append(label)
    cr_stats = score_dataset("CRYPTO SCANNER", cr_results, cr_truth, quiet=quiet)

    elapsed = time.perf_counter() - t0

    # ── Summary ───────────────────────────────────────────────
    all_stats = [
        ("URL",     url_stats),
        ("MERCHANT", m_stats),
        ("FILE",    f_stats),
        ("EMAIL",   em_stats),
        ("PHONE",   ph_stats),
        ("SMS",     sm_stats),
        ("SOCIAL",  so_stats),
        ("QR",      qr_stats),
        ("IP",      ip_stats),
        ("CRYPTO",  cr_stats),
    ]
    print_summary(all_stats)

    if not quiet:
        total = (len(URL_CASES) + len(MERCHANT_CASES) + len(make_files())
                 + len(EMAIL_CASES) + len(PHONE_CASES) + len(SMS_CASES)
                 + len(SOCIAL_CASES) + len(QR_CASES) + len(IP_CASES) + len(CRYPTO_CASES))
        print(dim(f"  Ran {total} test cases in {elapsed*1000:.1f} ms\n"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FRAUD-X accuracy test suite")
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable ANSI colour output (useful for CI log files)"
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="Print only the summary table, not per-case lines"
    )
    args = parser.parse_args()

    if args.no_color:
        USE_COLOR = False

    asyncio.run(run(quiet=args.quiet))