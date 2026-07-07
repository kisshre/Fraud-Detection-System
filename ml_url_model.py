"""
FRAUD-X  ·  URL Machine Learning Model
=======================================
Random Forest classifier trained on 22 hand-crafted URL features.
Self-contained: no imports from main.py to avoid circular dependencies.

Usage
-----
  from ml_url_model import url_ml_model
  prob, conf = url_ml_model.predict(url)   # 0-100, "high"|"medium"|"low"
  url_ml_model.load()                       # load from disk (called at startup)

Training
--------
  python train_model.py            # full 2 000-sample dataset
  python train_model.py --csv mydata.csv   # real phishing dataset
"""

from __future__ import annotations

import logging
import math
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlparse

logger = logging.getLogger("fraudx.ml")

MODEL_PATH = Path(__file__).parent / "url_model.pkl"

# ── Replicated constants (keep in sync with main.py) ────────────

_SUSPICIOUS_TLDS: frozenset = frozenset({
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "click", "loan",
    "work", "men", "bid", "party", "trade", "country", "kim", "cam",
    "zip", "mov", "rest", "quest", "monster", "best", "live",
    "icu", "fit", "buzz", "cyou", "shop", "online", "site", "store",
    "info", "host", "website", "space", "fun", "pw", "cc", "ws",
})

_URL_SHORTENERS: frozenset = frozenset({
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "shorte.st", "rebrand.ly", "cutt.ly",
    "t.ly", "rb.gy", "shorturl.at", "lnkd.in", "tiny.cc",
})

_PHISH_KEYWORDS: Tuple[str, ...] = (
    "login", "verify", "secure", "account", "update", "confirm",
    "banking", "wallet", "password", "signin", "webscr", "support",
    "recovery", "unlock", "suspended", "billing", "invoice",
    "giftcard", "crypto", "airdrop", "kyc", "renew", "reset",
    "urgent", "validate", "authorize", "connect", "claim", "mint",
    "nft", "seed", "mnemonic", "approve", "metamask",
)

_REDIRECT_PARAMS: frozenset = frozenset({
    "url", "redirect", "next", "dest", "target", "goto", "return",
})

_CONSONANTS: frozenset = frozenset("bcdfghjklmnpqrstvwxyz")

_TWO_LEVEL_TLDS: frozenset = frozenset({
    "co", "com", "org", "net", "gov", "edu", "ac", "or", "ne",
})

_POPULAR_BRANDS: Tuple[str, ...] = (
    "paypal", "google", "amazon", "apple", "microsoft", "netflix",
    "facebook", "instagram", "twitter", "chase", "wellsfargo",
    "binance", "coinbase", "stripe", "visa", "mastercard", "ebay",
    "linkedin", "youtube", "discord", "whatsapp", "spotify",
    "dropbox", "adobe", "salesforce", "shopify", "etsy",
)


# ── Feature extraction ───────────────────────────────────────────

FEATURE_NAMES: List[str] = [
    "url_length",           # 0
    "host_length",          # 1
    "path_length",          # 2
    "num_dots",             # 3
    "num_hyphens",          # 4
    "has_at_sign",          # 5  (binary)
    "num_digits_in_host",   # 6
    "num_subdomains",       # 7
    "url_depth",            # 8  (slashes in path)
    "num_query_params",     # 9
    "has_ip_host",          # 10 (binary)
    "is_https",             # 11 (binary)
    "has_punycode",         # 12 (binary)
    "is_url_shortener",     # 13 (binary)
    "has_suspicious_tld",   # 14 (binary)
    "has_redirect_param",   # 15 (binary)
    "digit_ratio",          # 16 (0-1)
    "special_char_ratio",   # 17 (0-1)
    "domain_entropy",       # 18 (bits)
    "dga_consonant_ratio",  # 19 (0-1)
    "phish_keyword_count",  # 20
    "brand_min_levenshtein",# 21 (capped at 6)
]

_NUM_FEATURES = len(FEATURE_NAMES)  # 22


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    t = len(s)
    return -sum((v / t) * math.log2(v / t) for v in freq.values())


def _lev(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(prev[j] + 1, curr[-1] + 1, prev[j - 1] + int(ca != cb)))
        prev = curr
    return prev[-1]


def _core_and_subdomains(host: str) -> Tuple[str, int]:
    """Return (registrable_core, n_subdomains)."""
    labels = host.split(".")
    if len(labels) >= 3 and labels[-2] in _TWO_LEVEL_TLDS and len(labels[-1]) == 2:
        # e.g. co.uk, com.au
        core = labels[-3] if len(labels) >= 3 else ""
        subs = max(0, len(labels) - 3)
    else:
        core = labels[-2] if len(labels) >= 2 else (labels[0] if labels else "")
        subs = max(0, len(labels) - 2)
    return core, subs


def extract_features(url: str) -> List[float]:
    """
    Extract exactly 22 numerical features from a raw URL string.
    Safe: never raises; returns a zero vector on parse failure.
    """
    if not url:
        return [0.0] * _NUM_FEATURES

    raw = url.strip()
    if not re.match(r"^[a-zA-Z]+://", raw):
        raw = "http://" + raw

    try:
        p      = urlparse(raw)
        host   = (p.hostname or "").lower().rstrip(".")
        path   = p.path or ""
        netloc = p.netloc or ""
        scheme = p.scheme.lower()
        query  = p.query or ""
    except Exception:
        return [0.0] * _NUM_FEATURES

    # ── Derived values ───────────────────────────────────────────
    labels  = host.split(".")
    tld     = labels[-1] if labels else ""
    core, n_subs = _core_and_subdomains(host)

    is_ip = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))

    num_digits_host = sum(c.isdigit() for c in host)
    digit_ratio     = num_digits_host / max(len(host), 1)

    alpha_core    = sum(1 for c in core if c.isalpha())
    consonants    = sum(1 for c in core.lower() if c in _CONSONANTS)
    consonant_r   = consonants / max(alpha_core, 1)

    url_lower     = raw.lower()
    kw_count      = sum(1 for kw in _PHISH_KEYWORDS if kw in url_lower)

    has_redirect  = int(any(k.lower() in _REDIRECT_PARAMS for k, _ in parse_qsl(query)))

    special       = sum(1 for c in raw if c in "-@!~_=&%")
    special_r     = special / max(len(raw), 1)

    if core and not is_ip:
        dists         = [_lev(core.lower(), b) for b in _POPULAR_BRANDS]
        brand_min     = min(dists) if dists else 6
        brand_min     = min(brand_min, 6)
    else:
        brand_min = 6

    n_query = len(parse_qsl(query))

    return [
        float(len(raw)),                                # 0
        float(len(host)),                               # 1
        float(len(path)),                               # 2
        float(raw.count(".")),                          # 3
        float(host.count("-")),                         # 4
        float(1 if "@" in netloc else 0),               # 5
        float(num_digits_host),                         # 6
        float(n_subs),                                  # 7
        float(path.count("/")),                         # 8
        float(n_query),                                 # 9
        float(1 if is_ip else 0),                       # 10
        float(1 if scheme == "https" else 0),           # 11
        float(1 if "xn--" in host else 0),              # 12
        float(1 if host in _URL_SHORTENERS else 0),     # 13
        float(1 if tld in _SUSPICIOUS_TLDS else 0),     # 14
        float(has_redirect),                            # 15
        float(digit_ratio),                             # 16
        float(special_r),                               # 17
        float(_entropy(core)),                          # 18
        float(consonant_r),                             # 19
        float(kw_count),                                # 20
        float(brand_min),                               # 21
    ]


# ── Model wrapper ────────────────────────────────────────────────

class URLFraudModel:
    """
    Thin wrapper around a trained sklearn RandomForestClassifier.

    Lifecycle
    ---------
      1. App startup calls  load()         → loads pkl if it exists
      2. If no pkl exists,  auto_train()   → trains on synthetic data (~3 s)
      3. analyze_url() calls predict()     → returns (prob_0_100, confidence)
    """

    def __init__(self) -> None:
        self._clf  = None
        self._ready = False

    # ── Public API ───────────────────────────────────────────────

    def load(self, path: Path = MODEL_PATH) -> bool:
        """Load a pre-trained model from disk. Returns True on success."""
        try:
            import joblib
            if not path.exists():
                return False
            self._clf   = joblib.load(str(path))
            self._ready = True
            logger.info("[ML] Model loaded from %s", path.name)
            return True
        except Exception as exc:
            logger.warning("[ML] Load failed: %s", exc)
            return False

    def save(self, path: Path = MODEL_PATH) -> None:
        import joblib
        joblib.dump(self._clf, str(path))
        logger.info("[ML] Model saved to %s", path.name)

    def train(self, X: List[List[float]], y: List[int]) -> Dict:
        """
        Train a RandomForestClassifier.  X is a list of feature vectors,
        y is a list of labels (0 = legit, 1 = phishing).
        Returns a dict of training metrics.
        """
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import cross_val_score
        from sklearn.metrics import classification_report
        import numpy as np

        Xarr = np.array(X, dtype=float)
        yarr = np.array(y, dtype=int)

        clf = RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )
        cv_scores = cross_val_score(clf, Xarr, yarr, cv=5, scoring="f1")
        clf.fit(Xarr, yarr)
        preds = clf.predict(Xarr)
        report = classification_report(yarr, preds, output_dict=True)

        self._clf   = clf
        self._ready = True

        return {
            "samples": len(yarr),
            "phishing": int(yarr.sum()),
            "legit": int((yarr == 0).sum()),
            "cv_f1_mean": round(float(cv_scores.mean()), 4),
            "cv_f1_std":  round(float(cv_scores.std()),  4),
            "train_accuracy": round(float(report["accuracy"]), 4),
            "precision_phishing": round(float(report["1"]["precision"]), 4),
            "recall_phishing":    round(float(report["1"]["recall"]),    4),
        }

    def auto_train(self) -> Dict:
        """Train on the built-in synthetic dataset and save to disk."""
        X, y = _build_synthetic_dataset()
        metrics = self.train(X, y)
        self.save()
        logger.info("[ML] Auto-trained. cv_f1=%.3f  acc=%.3f",
                    metrics["cv_f1_mean"], metrics["train_accuracy"])
        return metrics

    @property
    def is_ready(self) -> bool:
        return self._ready and self._clf is not None

    def predict(self, url: str) -> Tuple[float, str]:
        """
        Returns (fraud_probability: 0–100, confidence: "high"|"medium"|"low"|"unavailable").
        """
        if not self.is_ready:
            return 0.0, "unavailable"
        try:
            import numpy as np
            feats = extract_features(url)
            prob  = float(self._clf.predict_proba([feats])[0][1]) * 100
            # Confidence = how far from the 50% decision boundary
            margin = abs(prob - 50) / 50          # 0 → uncertain, 1 → certain
            conf   = "high" if margin > 0.55 else "medium" if margin > 0.25 else "low"
            return round(prob, 1), conf
        except Exception as exc:
            logger.debug("[ML] predict error: %s", exc)
            return 0.0, "error"

    def feature_importance(self) -> Dict[str, float]:
        """Return feature → importance, sorted descending (RF only)."""
        if not self.is_ready:
            return {}
        try:
            imp = self._clf.feature_importances_
            return dict(sorted(zip(FEATURE_NAMES, imp), key=lambda kv: -kv[1]))
        except AttributeError:
            return {}

    def status(self) -> Dict:
        """Status dict surfaced by /api/ml/status."""
        if not self.is_ready:
            return {"ready": False, "model_file": str(MODEL_PATH)}
        return {
            "ready":        True,
            "model_file":   str(MODEL_PATH),
            "model_type":   type(self._clf).__name__,
            "n_features":   _NUM_FEATURES,
            "feature_names": FEATURE_NAMES,
            "top_features": dict(list(self.feature_importance().items())[:8]),
        }


# ── Synthetic dataset builder ────────────────────────────────────

def _build_synthetic_dataset(n_phish: int = 1000, n_legit: int = 1000
                              ) -> Tuple[List[List[float]], List[int]]:
    """
    Generate a balanced synthetic URL dataset.
    Labels: 1 = phishing, 0 = legitimate.
    """
    import random
    rng = random.Random(2024)

    X: List[List[float]] = []
    y: List[int]         = []

    # ── Phishing URL generators ──────────────────────────────────

    phish_brands = [
        "paypal", "apple", "google", "amazon", "microsoft", "netflix",
        "facebook", "instagram", "chase", "wellsfargo", "coinbase",
        "binance", "metamask", "irs", "usps", "amazon", "linkedin",
    ]
    susp_tlds = ["tk", "ml", "xyz", "click", "top", "icu", "pw", "cc", "buzz", "live"]
    phish_paths = [
        "/login", "/signin", "/verify", "/account/update",
        "/secure/confirm", "/banking/auth", "/wallet/connect",
        "/kyc/verify", "/password/reset", "/account/suspended",
        "/claim/airdrop", "/seed/confirm", "/nft/mint",
    ]
    ip_segments = [
        "192.168.{}.{}".format(rng.randint(1, 254), rng.randint(1, 254))
        for _ in range(50)
    ]

    def _rnd_dga(length: int = 12) -> str:
        consonants = "bcdfghjklmnpqrstvwxyz"
        vowels     = "aeiou"
        result = ""
        for i in range(length):
            result += rng.choice(consonants if i % 3 != 1 else vowels)
        return result

    def _typo(brand: str) -> str:
        ops = [
            lambda s: s[:-1] + rng.choice("0123456789"),
            lambda s: s + rng.choice(["s", "x", "z"]),
            lambda s: s.replace("a", "4").replace("o", "0").replace("l", "1"),
            lambda s: s + "-" + rng.choice(["secure", "verify", "official"]),
            lambda s: s[0] + s[1:].replace(rng.choice(s[1:]), rng.choice("qwxyz"), 1),
        ]
        return rng.choice(ops)(brand)

    phish_generators = [
        # IP-based phishing
        lambda: "http://{}/{}{}".format(
            rng.choice(ip_segments),
            rng.choice(["banking", "account", "verify", "login"]),
            rng.choice(phish_paths),
        ),
        # Typosquat + suspicious TLD
        lambda: "http://{}.{}{}" .format(
            _typo(rng.choice(phish_brands)),
            rng.choice(susp_tlds),
            rng.choice(phish_paths),
        ),
        # Brand-in-subdomain
        lambda: "http://{}.{}.{}{}" .format(
            rng.choice(phish_brands),
            _rnd_dga(rng.randint(5, 9)),
            rng.choice(susp_tlds),
            rng.choice(phish_paths),
        ),
        # Legitimate-looking TLD but long keyword-stuffed path
        lambda: "https://{}-{}-{}.com{}?token={}".format(
            rng.choice(phish_brands),
            rng.choice(["secure", "support", "update", "official"]),
            rng.choice(["login", "verify", "auth"]),
            rng.choice(phish_paths),
            _rnd_dga(16),
        ),
        # DGA domain + suspicious TLD
        lambda: "http://{}.{}{}".format(
            _rnd_dga(rng.randint(8, 14)),
            rng.choice(susp_tlds),
            rng.choice(phish_paths),
        ),
        # URL shortener
        lambda: "http://bit.ly/{}".format(_rnd_dga(rng.randint(6, 10))),
        # @ in URL (user:password@host)
        lambda: "http://{}@{}.{}{}".format(
            rng.choice(phish_brands),
            _rnd_dga(8),
            rng.choice(susp_tlds),
            rng.choice(phish_paths),
        ),
        # Punycode homograph
        lambda: "http://xn--{}.com{}".format(_rnd_dga(8), rng.choice(phish_paths)),
        # Open redirect phishing
        lambda: "https://{}.com/redirect?url=http://{}.{}/steal".format(
            rng.choice(phish_brands),
            _rnd_dga(7),
            rng.choice(susp_tlds),
        ),
        # Many subdomains
        lambda: "http://{}.{}.{}.{}.{}{}".format(
            rng.choice(phish_brands),
            _rnd_dga(5), _rnd_dga(5), _rnd_dga(5),
            rng.choice(susp_tlds),
            rng.choice(phish_paths),
        ),
    ]

    for _ in range(n_phish):
        url = rng.choice(phish_generators)()
        X.append(extract_features(url))
        y.append(1)

    # ── Legitimate URL generators ────────────────────────────────

    legit_brands = {
        "google": ["google.com", "mail.google.com", "drive.google.com"],
        "amazon": ["amazon.com", "aws.amazon.com", "smile.amazon.com"],
        "microsoft": ["microsoft.com", "office.com", "live.com", "azure.com"],
        "apple": ["apple.com", "icloud.com", "developer.apple.com"],
        "netflix": ["netflix.com", "help.netflix.com"],
        "github": ["github.com", "gist.github.com"],
        "linkedin": ["linkedin.com", "www.linkedin.com"],
        "twitter": ["twitter.com", "x.com"],
        "facebook": ["facebook.com", "instagram.com", "whatsapp.com"],
        "paypal": ["paypal.com", "www.paypal.com"],
        "wikipedia": ["wikipedia.org", "en.wikipedia.org"],
        "reddit": ["reddit.com", "www.reddit.com", "old.reddit.com"],
        "stackoverflow": ["stackoverflow.com", "serverfault.com"],
        "bbc": ["bbc.com", "bbc.co.uk", "news.bbc.co.uk"],
        "nytimes": ["nytimes.com", "www.nytimes.com"],
    }

    legit_paths = [
        "", "/", "/about", "/contact", "/products", "/services",
        "/en-us/", "/en-us/about", "/help", "/support",
        "/news/tech", "/login", "/account",  # login is fine on real brands
        "/search?q=test", "/blog/2024", "/docs/api",
        "/pricing", "/features", "/download", "/faq",
        "/en/signin",  # real brand sign-in pages
    ]

    legit_generators = [
        # Major brand
        lambda: "https://{}{}".format(
            rng.choice(rng.choice(list(legit_brands.values()))),
            rng.choice(legit_paths),
        ),
        # Normal business website
        lambda: "https://www.{}-{}.com{}".format(
            rng.choice(["acme", "westfield", "brightside", "summit", "coastal",
                        "premier", "horizon", "blue", "green", "red", "global"]),
            rng.choice(["solutions", "tech", "corp", "group", "digital",
                        "consulting", "services", "systems", "labs"]),
            rng.choice(legit_paths),
        ),
        # News site
        lambda: "https://www.{}.{}/news/{}/{}".format(
            rng.choice(["theguardian", "reuters", "apnews", "wsj", "forbes",
                        "bloomberg", "techcrunch", "wired", "arstechnica"]),
            rng.choice(["com", "co.uk", "org"]),
            rng.randint(2020, 2024),
            rng.choice(["technology", "business", "world", "science"]),
        ),
        # E-commerce
        lambda: "https://www.{}.com/product/{}?ref=search".format(
            rng.choice(["shopify", "etsy", "ebay", "walmart", "target",
                        "bestbuy", "newegg", "wayfair"]),
            "-".join([rng.choice(["blue", "red", "small", "large", "new", "best"])
                      for _ in range(rng.randint(2, 4))]),
        ),
        # API / developer
        lambda: "https://api.{}.com/v{}/{}".format(
            rng.choice(["stripe", "twilio", "sendgrid", "cloudflare", "github",
                        "slack", "discord", "notion"]),
            rng.randint(1, 3),
            rng.choice(["users", "accounts", "payments", "messages", "data"]),
        ),
        # CDN / static assets
        lambda: "https://cdn.{}.com/assets/{}_{}.{}".format(
            rng.choice(["cloudflare", "fastly", "amazonaws", "azure", "gstatic"]),
            rng.choice(["main", "vendor", "app", "styles"]),
            rng.randint(1000, 9999),
            rng.choice(["js", "css", "png", "woff2"]),
        ),
    ]

    for _ in range(n_legit):
        url = rng.choice(legit_generators)()
        X.append(extract_features(url))
        y.append(0)

    return X, y


# ── Singleton ────────────────────────────────────────────────────

url_ml_model = URLFraudModel()
