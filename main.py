"""
FRAUD-X  ·  Real-Time Fraud Detection System  ·  v2.0.0
=========================================================
AI-augmented, multi-layer fraud, phishing and malware detection.
Dashboard: Fraud Detection System — served at GET /

Layers
------
  Layer 1 — Heuristic Engine          : 100+ multi-signal scoring
  Layer 2 — AI Semantic Analysis      : Gemini 2.0 Flash deep reasoning
  Layer 3 — Cybersecurity IDS         : magic-byte, hash, TLD, DGA checks
  Layer 4 — Blockchain Ledger         : SHA-256 chained append-only audit log
  Layer 5 — Early Warning System      : tri-state alert (safe / caution / danger)

Scanners
--------
  URL · Email · Phone · SMS · File · Merchant · Social · QR · IP · Crypto · Bulk

Endpoints
---------
  GET  /                        → Serves dashboard
  POST /api/scan/url            → Phishing URL analysis
  POST /api/scan/email          → Email scam / phishing analysis
  POST /api/scan/phone          → Phone number fraud scoring
  POST /api/scan/merchant       → Merchant / payment receiver
  POST /api/scan/file           → File malware scanning
  POST /api/scan/social         → Social media profile analysis
  POST /api/scan/sms            → SMS / text message scam
  POST /api/scan/qr             → QR code URL analysis
  POST /api/scan/ip             → IP address reputation check
  POST /api/scan/crypto         → Cryptocurrency address analysis
  POST /api/scan/bulk           → Bulk URL scan (up to 20)
  GET  /api/alerts              → Recent scan events
  GET  /api/ledger              → Chained ledger + integrity
  GET  /api/stats               → Aggregate statistics
  GET  /api/stats/trend         → 6-hour scan trend buckets
  GET  /api/export              → Export alerts as CSV
  GET  /api/health              → Health probe
  POST /api/alerts/clear        → Reset demo state
"""

from __future__ import annotations

# Load .env before anything else reads os.environ
from dotenv import load_dotenv
load_dotenv()

import asyncio
import csv
import hashlib
import hmac
import io
import json
import math
import os
import re
import secrets
import sqlite3
import time
import uuid
from collections import deque
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List, Optional
from urllib.parse import parse_qsl, unquote, urlparse

import bcrypt
import httpx
from fastapi import Depends, FastAPI, File, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# ── New engines ───────────────────────────────────────────────
from database import (
    init_db, save_alert, get_db_stats, get_trend_from_db,
    get_target_history, get_entity_graph, add_entity_link,
    get_alerts_paginated, get_alert_by_id, delete_alert,
    clear_all_alerts, update_alert_notes,
    get_score_distribution, get_top_targets, get_kind_timeline,
    save_ledger_block, load_ledger_blocks,
)
from graph_engine import (
    fraud_graph,
    link_url_scan, link_email_scan, link_phone_scan,
    link_ip_scan, link_crypto_scan, link_sms_scan,
)
from behavior_engine import behavior_engine
from ml_url_model import url_ml_model
from scoring_engine import scoring_engine
from xai_engine import xai_engine
from payment_gateway_analyzer import payment_analyzer

# ── Phase-2 Enterprise Engines ────────────────────────────────
from event_correlation_engine import event_correlation_engine, CorrelationInput
from window_analytics         import window_analytics, FraudEvent as WindowFraudEvent
from ato_engine               import ato_engine, ATOInput
from session_intelligence     import session_intelligence
from memory_engine            import memory_engine
from campaign_detector        import campaign_detector
from confidence_fusion        import confidence_fusion, SourceSignal
from drift_monitor            import drift_monitor
from signature_engine         import signature_engine
from multi_agent_orchestrator import multi_agent_orchestrator
from simulation_engine        import simulation_engine, ScenarioType
from auth_service             import (
    verify_password, create_access_token, create_refresh_token,
    decode_token, revoke_session, is_session_revoked,
    generate_mfa_secret, enable_mfa, get_mfa_secret, verify_totp,
    create_mfa_challenge, resolve_mfa_challenge,
    create_user, get_user_by_id, list_users, update_user_role, deactivate_user,
    update_last_login, audit, get_audit_log, ROLES,
)


# ═══════════════════════════════════════════════════════════════
# ①  Heuristic Knowledge Base
# ═══════════════════════════════════════════════════════════════

POPULAR_BRANDS: list[str] = [
    # Payments & Banking
    "paypal", "venmo", "cashapp", "zelle", "stripe", "square", "revolut",
    "wise", "transferwise", "klarna", "afterpay", "affirm",
    "chase", "wellsfargo", "bankofamerica", "citibank", "hsbc", "barclays",
    "lloyds", "santander", "natwest", "monzo", "nationwide", "td", "rbc",
    "scotiabank", "bmo", "cibc", "westpac", "commbank", "anz", "nab",
    "ing", "bnp", "deutsche", "unicredit", "intesa", "bbva", "caixabank",
    "truist", "pnc", "capitalonebank", "ally",
    # Investment / Brokerage
    "coinbase", "binance", "kraken", "bybit", "okx", "kucoin", "gemini",
    "robinhood", "etrade", "schwab", "fidelity", "vanguard", "webull",
    "tdameritrade", "interactivebrokers",
    # Crypto / DeFi / NFT
    "metamask", "trustwallet", "phantom", "ledger", "opensea", "rarible",
    "uniswap", "pancakeswap", "sushiswap", "aave", "compound", "curve",
    "polygon", "solana", "cardano", "avalanche", "chainlink", "dydx",
    "crypto", "blockchain", "nft", "defi",
    # Big Tech / Cloud
    "apple", "icloud", "itunes", "google", "gmail", "youtube", "microsoft",
    "outlook", "office365", "azure", "aws", "amazon", "dropbox", "adobe",
    "docusign", "salesforce", "oracle", "sap", "servicenow", "hubspot",
    "shopify", "bigcommerce", "magento", "woocommerce", "etsy",
    # Social / Messaging
    "facebook", "instagram", "whatsapp", "twitter", "x", "tiktok",
    "snapchat", "pinterest", "linkedin", "reddit", "discord", "telegram",
    "signal", "viber", "skype", "teams", "zoom", "slack", "notion",
    "figma", "canva",
    # Streaming / Entertainment
    "netflix", "spotify", "hulu", "disney", "paramount", "hbo", "peacock",
    "steam", "roblox", "epicgames", "nintendo", "playstation", "xbox",
    "blizzard", "battlenet",
    # E-commerce / Delivery
    "ebay", "walmart", "target", "aliexpress", "alibaba", "lazada",
    "shopee", "tokopedia", "doordash", "ubereats", "grubhub", "instacart",
    # Shipping / Government
    "fedex", "ups", "dhl", "usps", "irs", "hmrc",
    # Travel
    "booking", "airbnb", "tripadvisor", "expedia", "kayak",
    # Security
    "norton", "mcafee", "kaspersky", "avast", "bitdefender",
    # Cards
    "visa", "mastercard", "amex", "discover", "unionpay",
    # Mobile brands
    "samsung", "huawei", "xiaomi", "oppo",
    # Dev / Hosting
    "github", "gitlab", "bitbucket", "vercel", "netlify", "heroku",
    "cloudflare", "digitalocean", "linode", "vultr", "ovh",
]

SUSPICIOUS_TLDS: set[str] = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "click", "loan",
    "work", "men", "bid", "party", "trade", "country", "kim", "cam",
    "zip", "mov", "rest", "quest", "monster", "best", "live",
    "icu", "fit", "buzz", "cyou", "shop", "online", "site", "store",
    "info", "host", "website", "space", "fun", "pw", "cc", "ws",
}

URL_SHORTENERS: set[str] = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "shorte.st", "rebrand.ly", "cutt.ly",
    "t.ly", "rb.gy", "shorturl.at", "lnkd.in", "tiny.cc",
    "v.gd", "trib.al", "qr.ae", "x.co", "s.id", "short.io",
}

PHISH_KEYWORDS: list[str] = [
    "login", "verify", "secure", "account", "update", "confirm",
    "banking", "wallet", "password", "signin", "webscr", "support",
    "recovery", "unlock", "suspended", "billing", "invoice",
    "giftcard", "crypto", "airdrop", "kyc", "renew", "reset",
    "urgent", "validate", "authorize", "connect", "claim", "mint",
    "nft", "defi", "revoke", "approve", "metamask", "seed", "mnemonic",
    "verification", "authenticate", "credentials", "access", "token",
]

SAFE_REGISTRABLE_DOMAINS: set[str] = {
    "google.com", "youtube.com", "gmail.com", "amazon.com", "apple.com",
    "microsoft.com", "live.com", "office.com", "bing.com", "outlook.com",
    "facebook.com", "instagram.com", "whatsapp.com", "linkedin.com",
    "twitter.com", "x.com", "tiktok.com", "reddit.com", "stackoverflow.com",
    "stackexchange.com", "github.com", "gitlab.com", "bitbucket.org",
    "paypal.com", "chase.com", "bankofamerica.com", "wellsfargo.com",
    "citibank.com", "hsbc.com", "coinbase.com", "binance.com",
    "stripe.com", "square.com", "venmo.com", "cashapp.com",
    "netflix.com", "spotify.com", "adobe.com", "dropbox.com",
    "wikipedia.org", "bbc.com", "nytimes.com", "cnn.com", "reuters.com",
    "ycombinator.com", "openai.com", "anthropic.com", "mozilla.org",
    "cloudflare.com", "aws.amazon.com", "azure.com", "gov.uk",
    "irs.gov", "usps.com", "fedex.com", "ups.com", "dhl.com",
    "discord.com", "twitch.tv", "zoom.us", "slack.com", "notion.so",
    "figma.com", "vercel.com", "netlify.com", "heroku.com",
}

KNOWN_MALWARE_HASHES: set[str] = set()

DANGEROUS_EXTENSIONS: set[str] = {
    "exe", "scr", "bat", "cmd", "com", "pif", "vbs", "vbe", "js",
    "jse", "wsf", "wsh", "ps1", "msi", "jar", "hta", "cpl", "lnk",
    "reg", "dll", "apk", "iso", "img",
}

MACRO_ENABLED_EXTENSIONS: set[str] = {
    "docm", "xlsm", "pptm", "xlsb", "dotm", "xltm", "potm",
}

MACRO_CAPABLE_EXTENSIONS: set[str] = (
    {"doc", "xls", "ppt", "pdf"} | MACRO_ENABLED_EXTENSIONS
)

FILE_MAGIC: list[tuple[bytes, str]] = [
    (b"MZ",                    "pe"),
    (b"\x7fELF",               "elf"),
    (b"\x89PNG\r\n\x1a\n",     "png"),
    (b"\xff\xd8\xff",          "jpeg"),
    (b"GIF87a",                "gif"),
    (b"GIF89a",                "gif"),
    (b"%PDF-",                  "pdf"),
    (b"PK\x03\x04",            "zip"),
    (b"PK\x05\x06",            "zip"),
    (b"Rar!\x1a\x07",          "rar"),
    (b"\x1f\x8b",              "gzip"),
    (b"7z\xbc\xaf\x27\x1c",   "7z"),
    (b"\x00\x00\x00\x18ftyp",  "mp4"),
]

EXT_TO_TYPE: dict[str, str] = {
    "exe": "pe", "dll": "pe", "scr": "pe", "com": "pe", "cpl": "pe", "sys": "pe",
    "png": "png", "jpg": "jpeg", "jpeg": "jpeg", "gif": "gif",
    "pdf": "pdf",
    "docx": "zip", "xlsx": "zip", "pptx": "zip",
    "docm": "zip", "xlsm": "zip", "pptm": "zip", "xlsb": "zip",
    "zip": "zip", "jar": "zip", "apk": "zip", "ipa": "zip",
    "rar": "rar", "7z": "7z", "gz": "gzip",
    "mp4": "mp4",
}

HIGH_RISK_COUNTRIES: set[str] = {"NG", "RU", "KP", "IR", "BY", "VE", "UA", "CN", "PK"}

_PDF_RISKY_TOKENS: dict[bytes, int] = {
    b"/JavaScript": 55, b"/JS": 30, b"/OpenAction": 40,
    b"/Launch": 45, b"/EmbeddedFile": 20, b"/RichMedia": 15,
    b"app.alert": 35, b"eval(": 30,
}

_SCRIPT_INDICATORS: list[bytes] = [
    b"wscript.shell", b"powershell", b"cmd.exe",
    b"mshta.exe", b"cscript", b"createobject",
    b"shell.application", b"shellexecute",
    b"<script", b"<hta:", b"activexobject",
    b"document.write", b"eval(",
]

EMAIL_SCAM_PHRASES: list[str] = [
    "urgent action required", "verify your account", "click here immediately",
    "account suspended", "confirm your identity", "your account has been",
    "you have won", "congratulations you", "claim your prize",
    "wire transfer", "bitcoin payment", "gift card", "itunes card",
    "advance fee", "nigerian prince", "million dollars", "inheritance",
    "irs notice", "tax refund", "social security", "warrant for arrest",
    "final notice", "last warning", "legal action", "lawsuit",
    "password expired", "unusual sign-in", "suspicious activity detected",
    "update payment", "your package", "delivery failed", "shipment held",
    "crypto investment", "guaranteed returns", "limited time offer",
    "act now", "don't ignore", "sensitive information",
    # Extended wave 2
    "verify your wallet", "connect your metamask", "seed phrase",
    "approve transaction", "nft claim", "airdrop reward",
    "unclaimed funds", "dormant account reactivation",
    "kyc verification required", "account termination notice",
    "invoice attached", "document requires your signature",
    "your device has been compromised", "remote access needed",
]

VOIP_PREFIXES: set[str] = {
    "202", "646", "347", "929", "718", "917",
}

SMS_SCAM_PATTERNS: list[str] = [
    r"free\s+(prize|gift|reward|iphone|samsung)",
    r"click\s+(here|this|link|now)",
    r"urgent[:\s]",
    r"account\s+(suspended|locked|compromised)",
    r"verify\s+now",
    r"limited\s+time",
    r"claim\s+(your|now)",
    r"you\s+have\s+(won|been\s+selected)",
    r"tax\s+refund",
    r"parcel.*held",
    r"bitcoin|crypto|nft",
    r"\$\d+.*reward",
    r"otp|one.time.password",
    # Extended crypto / seed phrase patterns
    r"seed\s+phrase",
    r"airdrop.*claim|claim.*airdrop",
    r"wallet\s+connect",
    r"nft\s+(drop|claim|mint)",
    r"metamask.*verify|verify.*metamask",
    r"defi.*staking|staking.*reward",
    r"presale.*token|token.*presale",
    r"whitelist.*spot|spot.*whitelist",
]

# ── IP Address threat data ──────────────────────────────────────
PRIVATE_IP_PREFIXES: tuple[str, ...] = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "127.", "169.254.",
    "0.0.0.0", "255.255.255.255",
)

RISKY_PORTS: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    110: "POP3", 143: "IMAP", 445: "SMB", 1433: "MSSQL",
    1521: "Oracle", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5900: "VNC", 6379: "Redis", 8080: "Alt-HTTP",
    8443: "Alt-HTTPS", 9200: "Elasticsearch", 27017: "MongoDB",
    4444: "Metasploit", 1080: "SOCKS proxy", 8888: "Alt proxy",
}

DATACENTER_FIRST_OCTETS: set[str] = {
    "167", "45", "51", "88", "78", "64", "188",
    "185", "95", "37", "217", "198", "104", "172",
}

# ── Cryptocurrency detection ────────────────────────────────────
CRYPTO_ADDRESS_PATTERNS: dict[str, str] = {
    "btc_legacy":  r"^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$",
    "btc_segwit":  r"^bc1[a-z0-9]{6,87}$",
    "eth":         r"^0x[0-9a-fA-F]{40}$",
    "ltc_legacy":  r"^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$",
    "ltc_segwit":  r"^ltc1[a-z0-9]{6,87}$",
    "xmr":         r"^4[0-9AB][0-9a-zA-Z]{93}$",
    "trx":         r"^T[1-9A-HJ-NP-Za-km-z]{33}$",
    "sol":         r"^[1-9A-HJ-NP-Za-km-z]{32,44}$",
    "bnb":         r"^bnb1[0-9a-z]{38}$",
}

CRYPTO_MIXER_LABELS: set[str] = {
    "tornado", "wasabi", "coinjoin", "mixer", "tumbler",
    "chipmixer", "blender", "anonymix", "cryptomixer", "helix",
}

CRYPTO_SCAM_PHRASES: list[str] = [
    "send to double", "send btc to receive", "elon giveaway",
    "crypto giveaway", "nft airdrop claim", "connect wallet",
    "approve contract", "seed phrase", "recovery phrase",
    "12 words", "24 words", "private key", "wallet connect",
    "claim airdrop", "free crypto", "guaranteed return",
    "100x return", "mining pool reward", "staking reward claim",
    "flash loan", "rug pull opportunity", "presale whitelist",
]

# ── Email header injection patterns ────────────────────────────
EMAIL_HEADER_INJECTION: list[str] = [
    r"(\r|\n|%0d|%0a|%0D|%0A)",
    r"content-type\s*:",
    r"\bbcc\s*:",
    r"\bcc\s*:.*@",
]

EMAIL_ENCODING_OBFUSCATION: list[str] = [
    r"=\?utf-8\?[bq]\?",
    r"&#x[0-9a-f]+;",
    r"%[0-9a-f]{2}%[0-9a-f]{2}",
]

# ── DGA detection thresholds ────────────────────────────────────
_DGA_CONSONANTS: set[str] = set("bcdfghjklmnpqrstvwxyz")
_DGA_MIN_LEN: int = 8
_DGA_ENTROPY_THRESH: float = 3.5
_DGA_CONSONANT_THRESH: float = 0.65

# ── Premium / scam phone area codes ────────────────────────────
PREMIUM_AREA_CODES: set[str] = {
    "268", "284", "473", "649", "664", "767", "784", "809", "829", "849",
    "876", "900", "976", "242", "246", "441", "345", "658", "721", "758",
}

# ── Known sender IDs for SMS impersonation check ───────────────
KNOWN_SENDER_IDS: set[str] = {
    "amazon", "paypal", "apple", "google", "usps", "fedex", "ups", "dhl",
    "irs", "hmrc", "bank", "netflix", "spotify", "chase", "wellsfargo",
}


# ═══════════════════════════════════════════════════════════════
# ②  In-Memory Stores
# ═══════════════════════════════════════════════════════════════

@dataclass
class Alert:
    id:          str
    kind:        str
    target:      str
    risk_score:  int
    risk_level:  str
    reasons:     list[str]
    timestamp:   float
    ledger_hash: str = ""
    ai_analysis: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


ALERTS: deque[Alert] = deque(maxlen=500)


# ═══════════════════════════════════════════════════════════════
# WebSocket broadcast manager
# ═══════════════════════════════════════════════════════════════

class _WSManager:
    def __init__(self) -> None:
        self._sockets: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._sockets.append(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self._sockets = [s for s in self._sockets if s is not ws]

    async def broadcast(self, data: dict) -> None:
        dead: list[WebSocket] = []
        for ws in self._sockets:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


ws_manager = _WSManager()


# ═══════════════════════════════════════════════════════════════
# ③  Blockchain Ledger
# ═══════════════════════════════════════════════════════════════

@dataclass
class LedgerBlock:
    index:        int
    timestamp:    float
    alert_id:     str
    payload_hash: str
    prev_hash:    str
    block_hash:   str


LEDGER: list[LedgerBlock] = []


def _sha256(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def append_to_ledger(alert: Alert) -> str:
    prev_hash    = LEDGER[-1].block_hash if LEDGER else "GENESIS"
    raw_payload  = f"{alert.id}|{alert.kind}|{alert.target}|{alert.risk_score}|{alert.timestamp}"
    payload_hash = _sha256(raw_payload)
    idx          = len(LEDGER)
    block_hash   = _sha256(f"{idx}|{prev_hash}|{payload_hash}")
    block = LedgerBlock(
        index=idx, timestamp=alert.timestamp, alert_id=alert.id,
        payload_hash=payload_hash, prev_hash=prev_hash, block_hash=block_hash,
    )
    LEDGER.append(block)
    save_ledger_block(idx, alert.timestamp, alert.id, payload_hash, prev_hash, block_hash)
    return block_hash


def verify_ledger() -> bool:
    prev = "GENESIS"
    for i, b in enumerate(LEDGER):
        if b.prev_hash != prev or b.index != i:
            return False
        if _sha256(f"{i}|{b.prev_hash}|{b.payload_hash}") != b.block_hash:
            return False
        prev = b.block_hash
    return True


def record_alert(
    kind: str, target: str, score: int, level: str, reasons: list[str],
    ai_analysis: str = ""
) -> Alert:
    alert = Alert(
        id=str(uuid.uuid4()), kind=kind, target=target,
        risk_score=score, risk_level=level, reasons=reasons,
        timestamp=time.time(), ai_analysis=ai_analysis,
    )
    alert.ledger_hash = append_to_ledger(alert)
    ALERTS.appendleft(alert)
    # Persist to SQLite
    save_alert(
        alert.id, kind, target, score, level, reasons,
        ai_analysis, alert.ledger_hash, alert.timestamp,
    )
    # Behavioral engine: record then check for campaign promotion
    behavior_engine.record(kind, target, score)
    behavior_engine.post_alert(kind, target, score, alert.id)
    # Scoring engine: update dynamic threshold EMA + session window
    scoring_engine.record(kind, target, score)
    # Push to all connected dashboard WebSocket clients (non-blocking)
    try:
        asyncio.get_running_loop().create_task(ws_manager.broadcast(alert.to_dict()))
    except RuntimeError:
        pass  # no running loop (test context)
    return alert


# ═══════════════════════════════════════════════════════════════
# ④  Scoring Helpers
# ═══════════════════════════════════════════════════════════════

DANGER_THRESHOLD:  int = 65
CAUTION_THRESHOLD: int = 30


def level_for(score: int, kind: str = "url") -> str:
    return scoring_engine.level_for(score, kind)


def levenshtein(a: str, b: str) -> int:
    if a == b:   return 0
    if not a:    return len(b)
    if not b:    return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = curr
    return prev[-1]


def shannon_entropy(s: str) -> float:
    if not s: return 0.0
    freq: dict[str, int] = {}
    for ch in s: freq[ch] = freq.get(ch, 0) + 1
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


_LEET_MAP = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a",
    "5": "s", "7": "t", "8": "b", "9": "g",
    "@": "a", "$": "s", "!": "i", "|": "l",
})


def leet_normalize(s: str) -> str:
    return s.lower().translate(_LEET_MAP)


_TWO_LEVEL_EFFECTIVE_TLDS: set[str] = {
    "co", "com", "org", "net", "gov", "edu", "ac", "or", "ne", "go", "web", "mil",
}


def _split_public_suffix(labels: list[str]) -> tuple[list[str], list[str]]:
    if (len(labels) >= 3 and labels[-2] in _TWO_LEVEL_EFFECTIVE_TLDS and len(labels[-1]) == 2):
        return labels[:-2], labels[-2:]
    if labels:
        return labels[:-1], labels[-1:]
    return [], []


def registrable_core(host: str) -> str:
    name, _ = _split_public_suffix(host.split("."))
    return name[-1] if name else host


def registrable_domain(host: str) -> str:
    name, suffix = _split_public_suffix(host.split("."))
    if not name: return host
    return ".".join([name[-1]] + suffix)


def subdomain_labels(host: str) -> list[str]:
    name, _ = _split_public_suffix(host.split("."))
    return name[:-1] if len(name) >= 1 else []


def has_mixed_scripts(s: str) -> list[str]:
    scripts: set[str] = set()
    for ch in s:
        if "a" <= ch.lower() <= "z": scripts.add("Latin")
        elif "Ѐ" <= ch <= "ӿ": scripts.add("Cyrillic")
        elif "Ͱ" <= ch <= "Ͽ": scripts.add("Greek")
        elif "֐" <= ch <= "׿": scripts.add("Hebrew")
        elif "؀" <= ch <= "ۿ": scripts.add("Arabic")
    return sorted(scripts) if len(scripts) >= 2 else []


def detect_magic(data: bytes) -> str | None:
    for magic, kind in FILE_MAGIC:
        if data[:len(magic)] == magic:
            return kind
    return None


def dga_score(core: str, entropy: float) -> int:
    if len(core) < _DGA_MIN_LEN:
        return 0
    consonant_count = sum(1 for c in core.lower() if c in _DGA_CONSONANTS)
    total_alpha = sum(1 for c in core if c.isalpha())
    if total_alpha == 0:
        return 0
    consonant_ratio = consonant_count / total_alpha
    if entropy > 3.8 and consonant_ratio > 0.70:
        return 35
    if entropy > _DGA_ENTROPY_THRESH and consonant_ratio > _DGA_CONSONANT_THRESH:
        return 20
    return 0


# ═══════════════════════════════════════════════════════════════
# ⑤  Gemini AI Deep Analysis
# ═══════════════════════════════════════════════════════════════

GEMINI_MODEL   = "gemini-2.0-flash"
GEMINI_API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"


async def ai_analyze(scan_type: str, content: str, heuristic_score: int, heuristic_reasons: list[str]) -> tuple[int, str, list[str]]:
    system_prompt = """You are an expert cybersecurity analyst specializing in fraud detection.
Analyze the provided content and return a JSON response with this exact structure:
{
  "score_adjustment": <integer from -20 to +40>,
  "confidence": <"low"|"medium"|"high">,
  "summary": "<1-2 sentence AI analysis summary>",
  "additional_signals": ["<signal1>", "<signal2>"],
  "verdict": "<safe|caution|danger>"
}

score_adjustment: how much to adjust the heuristic score (negative = safer, positive = more dangerous)
additional_signals: new signals the AI found that heuristics missed (max 3)
Be precise and technical. Only flag genuine threats. Do not be overly cautious."""

    user_content = f"""Scan Type: {scan_type}
Target: {content[:500]}
Heuristic Score: {heuristic_score}/100
Heuristic Signals Found: {'; '.join(heuristic_reasons[:5])}

Analyze for fraud/phishing/scam indicators. Return only the JSON object, no other text."""

    api_key = os.environ.get("GEMINI_API_KEY", "")
    if not api_key:
        return 0, "AI analysis unavailable (no GEMINI_API_KEY)", []

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{GEMINI_API_URL}?key={api_key}",
                headers={"Content-Type": "application/json"},
                json={
                    "systemInstruction": {"parts": [{"text": system_prompt}]},
                    "contents": [{"parts": [{"text": user_content}]}],
                    "generationConfig": {"maxOutputTokens": 400, "temperature": 0.1},
                },
            )
            if resp.status_code != 200:
                return 0, "AI analysis unavailable", []

            data = resp.json()
            text = data["candidates"][0]["content"]["parts"][0]["text"].strip()
            text = re.sub(r"```json|```", "", text).strip()
            parsed = json.loads(text)

            adjustment = int(parsed.get("score_adjustment", 0))
            adjustment = max(-20, min(40, adjustment))
            summary    = parsed.get("summary", "")
            signals    = parsed.get("additional_signals", [])[:3]

            return adjustment, summary, signals

    except Exception:
        return 0, "AI analysis unavailable (offline mode)", []


# ═══════════════════════════════════════════════════════════════
# ⑥  URL Analyzer
# ═══════════════════════════════════════════════════════════════

_REDIRECT_PARAMS: set[str] = {
    "url", "redirect", "next", "dest", "target", "goto", "return", "continue",
}


async def analyze_url(raw: str, _depth: int = 0, use_ai: bool = True) -> dict:
    raw = raw.strip()
    if not raw:
        raise HTTPException(status_code=400, detail="URL is required")
    if not re.match(r"^[a-zA-Z]+://", raw):
        raw = "http://" + raw

    parsed = urlparse(raw)
    host   = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        raise HTTPException(status_code=400, detail="Could not parse URL")

    reasons: list[str] = []
    score = 0
    labels    = host.split(".")
    tld       = labels[-1] if labels else ""
    core      = registrable_core(host)
    norm_core = leet_normalize(core)
    reg_domain = registrable_domain(host)

    is_safe_known = (
        reg_domain in SAFE_REGISTRABLE_DOMAINS
        or (core in POPULAR_BRANDS and core == norm_core and tld not in SUSPICIOUS_TLDS)
    )

    # Hard indicators
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        score += 45
        reasons.append("Hostname is a raw IP address — very unusual for legitimate sites.")

    scripts = has_mixed_scripts(host)
    if scripts:
        score += 55
        reasons.append(f"Hostname mixes {' + '.join(scripts)} characters — likely homograph attack.")

    if "xn--" in host:
        score += 30
        reasons.append("Hostname uses punycode (xn--) — possible Unicode homograph.")

    if "@" in (parsed.netloc or ""):
        score += 40
        reasons.append("URL contains '@' which can hide the real destination host.")

    if parsed.port and parsed.port not in (80, 443):
        score += 15
        reasons.append(f"Unusual port :{parsed.port} for {parsed.scheme.upper()}.")

    # Brand impersonation
    if not is_safe_known and labels:
        sld_parts  = re.split(r"[-_]+", core)
        norm_parts = [leet_normalize(p) for p in sld_parts]
        sub_labels = subdomain_labels(host)
        sub_norms  = [leet_normalize(lbl) for lbl in sub_labels]

        for brand in POPULAR_BRANDS:
            if core == brand: break
            if norm_core == brand and core != brand:
                score += 55
                reasons.append(f"Domain '{core}' is a leet-speak spoof of brand '{brand}'.")
                break
            d = levenshtein(norm_core, brand)
            if 0 < d <= 2 and len(brand) >= 5:
                pts = 60 if d == 1 else 50
                score += pts
                reasons.append(f"Domain '{core}' is {d} edit(s) from brand '{brand}' — possible typosquat.")
                break
            if brand in sld_parts:
                score += 50
                reasons.append(f"SLD '{core}' contains brand '{brand}' as a hyphenated segment.")
                break
            if brand in norm_parts:
                score += 65
                reasons.append(f"SLD '{core}' contains leet-spoof of brand '{brand}'.")
                break
            if brand in sub_labels or brand in sub_norms:
                score += 55
                reasons.append(f"Brand '{brand}' appears as a subdomain while real domain is '{reg_domain}'.")
                break
            for lbl in sub_labels:
                sub_parts = re.split(r"[-_]+", lbl)
                sub_parts_norm = [leet_normalize(p) for p in sub_parts]
                if brand in sub_parts or brand in sub_parts_norm:
                    score += 50
                    reasons.append(f"Brand '{brand}' appears as a hyphenated segment of subdomain '{lbl}'.")
                    break
            else:
                continue
            break

    # Secondary signals
    if parsed.scheme == "http":
        score += 12
        reasons.append("Uses unencrypted HTTP instead of HTTPS.")

    if not is_safe_known and tld in SUSPICIOUS_TLDS:
        score += 30
        reasons.append(f"TLD '.{tld}' is a free/abuse-prone domain commonly used for phishing.")

    if host in URL_SHORTENERS:
        score += 35
        reasons.append(f"'{host}' is a URL shortener — the real destination is hidden.")

    path_lower = (parsed.path + "?" + parsed.query).lower()
    kw_hits = [k for k in PHISH_KEYWORDS if k in path_lower]
    if kw_hits:
        score += min(30, len(kw_hits) * 10)
        reasons.append(f"Phishing keywords in URL: {', '.join(kw_hits[:4])}.")

    if len(labels) >= 5:
        score += 15
        reasons.append(f"Hostname has {len(labels)} subdomain levels — unusually deep nesting.")

    if len(host) > 50:
        score += 10
        reasons.append(f"Very long hostname ({len(host)} chars).")

    ent = shannon_entropy(core)
    if ent > 4.0:
        score += 20
        reasons.append(f"High domain entropy ({ent:.2f} bits) — looks algorithmically generated.")
    elif ent > 3.5:
        score += 10
        reasons.append(f"Elevated domain entropy ({ent:.2f} bits).")

    # DGA detection
    dga = dga_score(core, ent)
    if dga > 0:
        cr = sum(1 for c in core.lower() if c in _DGA_CONSONANTS) / max(len(core), 1)
        score += dga
        reasons.append(
            f"Domain '{core}' shows DGA characteristics (entropy={ent:.2f}, "
            f"consonant ratio={cr:.0%}) — likely algorithmically generated."
        )

    # Redirect depth indicator
    if _depth >= 1:
        score += 10
        reasons.append(f"URL is a nested redirect (depth {_depth}) — layered misdirection.")

    # Open redirect check
    if _depth < 2:
        for key, val in parse_qsl(parsed.query):
            if key.lower() in _REDIRECT_PARAMS:
                dest = unquote(val)
                if re.match(r"^[a-zA-Z]+://", dest) or dest.startswith("//"):
                    try:
                        inner = await analyze_url(dest, _depth=_depth + 1, use_ai=False)
                        inner_score = inner.get("risk_score", 0)
                        if inner_score >= DANGER_THRESHOLD:
                            score += 65
                            reasons.append(f"Open redirect to a dangerous destination ({inner_score}/100).")
                        elif inner_score >= CAUTION_THRESHOLD:
                            score += 55
                            reasons.append(f"Open redirect to a suspicious destination ({inner_score}/100).")
                    except Exception:
                        pass

    # Safe-domain cap
    if is_safe_known and score < DANGER_THRESHOLD:
        score = min(score, 15)
        reasons.append("Domain is on the trusted whitelist — capped at low risk.")

    if not reasons:
        reasons.append("No strong phishing signals detected.")

    score = max(0, min(score, 100))

    ai_summary = ""
    adjustment = 0
    ml_score: Optional[float] = None
    if use_ai and _depth == 0:
        # ── Random Forest ML score ───────────────────────────
        if url_ml_model.is_ready:
            ml_prob, ml_conf = url_ml_model.predict(raw)
            ml_score = ml_prob
            if ml_prob >= 75:
                score += 15
                reasons.insert(0,
                    f"[ML] Random Forest: {ml_prob:.0f}% phishing probability "
                    f"({ml_conf} confidence) — independent of heuristics."
                )
            elif ml_prob >= 50:
                score += 7
                reasons.insert(0,
                    f"[ML] Random Forest: moderate phishing risk "
                    f"({ml_prob:.0f}%, {ml_conf} confidence)."
                )
            elif ml_prob <= 15 and score < 40:
                score = max(0, score - 5)
                reasons.append(
                    f"[ML] Random Forest: low phishing probability ({ml_prob:.0f}%) "
                    f"— reduces false-positive risk."
                )
            score = max(0, min(100, score))

        # ── Behavioral analysis ──────────────────────────────
        beh_adj, beh_signals = behavior_engine.analyze("url", raw, score)
        if beh_signals:
            reasons.extend(beh_signals)
            score = max(0, min(100, score + beh_adj))

        # ── Graph: frequency repeat-offender scoring ─────────
        for _etype, _eval in [("url", raw), ("domain", host)]:
            _freq_adj, _freq_sigs = fraud_graph.get_entity_risk_adjustment(_etype, _eval)
            if _freq_sigs:
                reasons.extend(_freq_sigs)
                score = max(0, min(100, score + _freq_adj))

        # ── Graph: BFS guilt-by-association propagation ──────
        graph_adj, graph_signals = fraud_graph.connected_risk("url", raw)
        if graph_signals:
            reasons.extend(graph_signals)
            score = max(0, min(100, score + graph_adj))

        # ── Link entities into graph ─────────────────────────
        link_url_scan(raw, host, float(score))
        add_entity_link("url", raw, "domain", host, "resolves_to")

        # ── Weighted signal calibration ───────────────────────
        score, _ = scoring_engine.calibrate(score, "url", reasons)

        # ── Context-aware cross-entity boost ─────────────────
        ctx_adj, ctx_sigs = scoring_engine.context_adjust("url", raw, score, reasons)
        if ctx_sigs:
            reasons.extend(ctx_sigs)
            score = max(0, min(100, score + ctx_adj))

        # ── Claude AI semantic analysis ──────────────────────
        adjustment, ai_summary, ai_signals = await ai_analyze("URL", raw, score, reasons)
        if ai_signals:
            reasons.extend([f"[AI] {s}" for s in ai_signals])
        score = max(0, min(100, score + adjustment))

    level = level_for(score, "url")
    alert = record_alert("url", raw, score, level, reasons, ai_summary)

    # ── XAI explanation ──────────────────────────────────────
    xai = xai_engine.explain(score, level, reasons, "url", ml_score, adjustment) if _depth == 0 else {}

    return {
        "alert_id": alert.id, "target": raw, "host": host,
        "registrable": reg_domain, "tld": tld,
        "risk_score": score, "risk_level": level, "reasons": reasons,
        "ai_analysis": ai_summary, "ledger_hash": alert.ledger_hash,
        "recommendation": recommendation(level, "url"),
        "ml_score": ml_score,
        "explanation": xai,
    }


# ═══════════════════════════════════════════════════════════════
# ⑦  Payment Gateway Analyzer
# ═══════════════════════════════════════════════════════════════

async def analyze_payment(payload: PaymentPayload) -> dict:
    """
    Two-phase payment page analysis:
      Phase A — base URL heuristics (reuses analyze_url internals)
      Phase B — payment-specific layer (payment_gateway_analyzer)
    Then runs the full engine pipeline (ML → Graph → Behavioral →
    Scoring calibration → Context → Claude AI) and records a
    kind="payment" alert for the ledger.
    """
    raw   = payload.url.strip()
    if not raw:
        raise HTTPException(status_code=400, detail="URL is required.")
    if not re.match(r"^[a-zA-Z]+://", raw):
        raw = "https://" + raw

    parsed    = urlparse(raw)
    host      = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        raise HTTPException(status_code=400, detail="Could not parse URL host.")

    # ── Phase A: URL heuristics ──────────────────────────────────
    # We run analyze_url with use_ai=False (no ML/graph/AI yet) to
    # get the base heuristic score + reasons cheaply.  A separate
    # "url" alert IS recorded by analyze_url — this is intentional
    # and provides the raw URL baseline in the ledger.
    base      = await analyze_url(raw, use_ai=False)
    score:    int       = base["risk_score"]
    reasons:  list[str] = list(base["reasons"])

    # ── Phase B: Payment-specific signals ────────────────────────
    context = {
        "page_title":       payload.page_title,
        "merchant_name":    payload.merchant_name,
        "has_payment_form": payload.has_payment_form,
        "form_action_url":  payload.form_action_url,
        "form_field_names": payload.form_field_names or [],
    }
    pg_delta, pg_reasons, gateway_info = payment_analyzer.analyze(raw, host, context)
    if pg_reasons:
        reasons.extend(pg_reasons)
        score = max(0, min(100, score + pg_delta))

    # ── ML Random Forest ─────────────────────────────────────────
    ml_score: Optional[float] = None
    if url_ml_model.is_ready:
        ml_prob, ml_conf = url_ml_model.predict(raw)
        ml_score = ml_prob
        if ml_prob >= 75:
            score += 15
            reasons.insert(0,
                f"[ML] Random Forest: {ml_prob:.0f}% phishing probability "
                f"({ml_conf} confidence) — independent URL classifier."
            )
        elif ml_prob >= 50:
            score += 7
            reasons.insert(0,
                f"[ML] Random Forest: moderate phishing probability ({ml_prob:.0f}%)."
            )
        elif ml_prob <= 15 and score < 40:
            score = max(0, score - 5)
            reasons.append(
                f"[ML] Random Forest: low phishing probability ({ml_prob:.0f}%) "
                f"— reduces false-positive risk."
            )
        score = max(0, min(100, score))

    # ── Behavioral engine ────────────────────────────────────────
    beh_adj, beh_signals = behavior_engine.analyze("payment", raw, score)
    if beh_signals:
        reasons.extend(beh_signals)
        score = max(0, min(100, score + beh_adj))

    # ── Graph: repeat-offender frequency ─────────────────────────
    for _etype, _eval in [("url", raw), ("domain", host)]:
        _fadj, _fsigs = fraud_graph.get_entity_risk_adjustment(_etype, _eval)
        if _fsigs:
            reasons.extend(_fsigs)
            score = max(0, min(100, score + _fadj))

    # ── Graph: BFS guilt-by-association ──────────────────────────
    gadj, gsigs = fraud_graph.connected_risk("url", raw)
    if gsigs:
        reasons.extend(gsigs)
        score = max(0, min(100, score + gadj))

    # Register domain/URL in graph
    link_url_scan(raw, host, float(score))
    add_entity_link("url", raw, "domain", host, "payment_resolves_to")

    # ── Weighted signal calibration ───────────────────────────────
    score, _ = scoring_engine.calibrate(score, "payment", reasons)

    # ── Context-aware cross-entity boost ─────────────────────────
    ctx_adj, ctx_sigs = scoring_engine.context_adjust("payment", raw, score, reasons)
    if ctx_sigs:
        reasons.extend(ctx_sigs)
        score = max(0, min(100, score + ctx_adj))

    # ── Claude AI semantic analysis (optional) ───────────────────
    ai_summary  = ""
    ai_adj      = 0
    if payload.use_ai:
        content = (
            f"URL: {raw}\n"
            f"Page Title: {payload.page_title or 'N/A'}\n"
            f"Merchant: {payload.merchant_name or 'N/A'}\n"
            f"Has Payment Form: {payload.has_payment_form}\n"
            f"Gateway Signals: {', '.join(gateway_info['payment_signals']) or 'none'}"
        )
        ai_adj, ai_summary, ai_signals = await ai_analyze(
            "Payment Page", content, score, reasons
        )
        if ai_signals:
            reasons.extend([f"[AI] {s}" for s in ai_signals])
        score = max(0, min(100, score + ai_adj))

    level = level_for(score, "payment")
    alert = record_alert("payment", raw, score, level, reasons, ai_summary)

    # ── XAI structured explanation ────────────────────────────────
    xai = xai_engine.explain(score, level, reasons, "url", ml_score, ai_adj)

    return {
        "alert_id":         alert.id,
        "target":           raw,
        "host":             host,
        "risk_score":       score,
        "risk_level":       level,
        "reasons":          reasons,
        "ai_analysis":      ai_summary,
        "ledger_hash":      alert.ledger_hash,
        "recommendation":   recommendation(level, "payment"),
        "ml_score":         ml_score,
        "explanation":      xai,
        "gateway_info":     gateway_info,
        "is_trusted_gateway": gateway_info["is_trusted"],
        "verified_gateway":   gateway_info["verified_gateway"],
        "is_payment_page":    gateway_info["is_payment_page"],
    }


# ═══════════════════════════════════════════════════════════════
# ⑧  Email Analyzer
# ═══════════════════════════════════════════════════════════════

class EmailPayload(BaseModel):
    subject:     Optional[str] = None
    sender:      Optional[str] = None
    body:        Optional[str] = None
    sender_domain: Optional[str] = None
    reply_to:    Optional[str] = None
    has_attachments: Optional[bool] = None
    num_links:   Optional[int] = None


async def analyze_email(p: EmailPayload) -> dict:
    reasons: list[str] = []
    score = 0

    subject_low = (p.subject or "").lower()
    body_low    = (p.body or "").lower()
    sender_low  = (p.sender or "").lower()
    combined    = f"{subject_low} {body_low}"

    # Urgency / pressure language
    urgency_words = ["urgent", "immediately", "action required", "expire", "suspended",
                     "locked", "verify now", "last chance", "24 hours", "limited time",
                     "final notice", "warning", "alert", "act now", "don't delay"]
    urgency_hits = [w for w in urgency_words if w in combined]
    if urgency_hits:
        score += min(25, len(urgency_hits) * 8)
        reasons.append(f"High-urgency language: {', '.join(urgency_hits[:3])}.")

    # Scam phrases
    scam_hits = [phrase for phrase in EMAIL_SCAM_PHRASES if phrase in combined]
    if scam_hits:
        score += min(35, len(scam_hits) * 12)
        reasons.append(f"Known scam phrases detected: {', '.join(scam_hits[:2])}.")

    # Sender domain analysis
    if p.sender_domain:
        domain_result = await analyze_url(f"http://{p.sender_domain}", use_ai=False)
        d_score = domain_result.get("risk_score", 0)
        if d_score >= DANGER_THRESHOLD:
            score += 40
            reasons.append(f"Sender domain scored as dangerous ({d_score}/100).")
        elif d_score >= CAUTION_THRESHOLD:
            score += 20
            reasons.append(f"Sender domain is suspicious ({d_score}/100).")

    # Reply-to mismatch
    if p.reply_to and p.sender:
        sender_domain  = p.sender.split("@")[-1].lower() if "@" in p.sender else ""
        replyto_domain = p.reply_to.split("@")[-1].lower() if "@" in p.reply_to else ""
        if sender_domain and replyto_domain and sender_domain != replyto_domain:
            score += 30
            reasons.append(f"Reply-To domain ({replyto_domain}) differs from sender domain ({sender_domain}) — spoofing indicator.")

    # Suspicious sender patterns
    if re.search(r"\d{5,}", sender_low):
        score += 15
        reasons.append("Sender address contains many consecutive digits — unusual for legitimate senders.")
    if re.search(r"(noreply|no-reply|donotreply).*@.*\.(tk|xyz|top|click|live|icu)", sender_low):
        score += 25
        reasons.append("No-reply sender on a suspicious TLD.")

    # Financial / crypto requests
    financial_patterns = ["wire transfer", "bank account", "bitcoin", "crypto", "gift card",
                          "western union", "money gram", "zelle", "venmo", "paypal request"]
    fin_hits = [f for f in financial_patterns if f in body_low]
    if fin_hits:
        score += min(30, len(fin_hits) * 15)
        reasons.append(f"Financial transaction request: {', '.join(fin_hits[:2])}.")

    # Credential harvesting
    cred_patterns = ["enter your password", "confirm your password", "verify your identity",
                     "click the link below", "reset your password", "your credentials"]
    cred_hits = [c for c in cred_patterns if c in body_low]
    if cred_hits:
        score += min(25, len(cred_hits) * 12)
        reasons.append("Credential harvesting language detected.")

    # Attachments
    if p.has_attachments:
        score += 10
        reasons.append("Email contains attachments — exercise caution before opening.")

    # Excessive links
    if p.num_links and p.num_links > 5:
        score += 10
        reasons.append(f"Email contains {p.num_links} links — unusually high for legitimate emails.")

    # Poor grammar indicators
    grammar_patterns = ["kindly", "do the needful", "revert back", "good day dear",
                        "i need your assistance", "strictly confidential"]
    gram_hits = [g for g in grammar_patterns if g in body_low]
    if gram_hits:
        score += min(15, len(gram_hits) * 8)
        reasons.append("Phrases typical of scam emails detected.")

    # Header injection detection
    full_raw = f"{p.subject or ''}\n{p.sender or ''}\n{p.reply_to or ''}"
    for pattern in EMAIL_HEADER_INJECTION:
        if re.search(pattern, full_raw, re.IGNORECASE):
            score += 35
            reasons.append("Header injection pattern detected — possible email spoofing attempt.")
            break

    # Encoding obfuscation
    for pattern in EMAIL_ENCODING_OBFUSCATION:
        if re.search(pattern, full_raw, re.IGNORECASE):
            score += 20
            reasons.append("Encoding/obfuscation in headers — common phishing evasion technique.")
            break

    if not reasons:
        reasons.append("No strong phishing signals detected in this email.")

    score = max(0, min(score, 100))

    # ── Behavioral analysis ──────────────────────────────────────
    sender_key = p.sender or p.subject or "email"
    beh_adj, beh_sigs = behavior_engine.analyze("email", sender_key, score)
    if beh_sigs:
        reasons.extend(beh_sigs); score = max(0, min(100, score + beh_adj))

    # ── Graph risk propagation ───────────────────────────────────
    if p.sender and "@" in p.sender:
        domain = p.sender.split("@")[-1].lower()
        # Frequency: repeat-offender check on sender address and domain
        for _etype, _eval in [("email", p.sender.lower()), ("domain", domain)]:
            _freq_adj, _freq_sigs = fraud_graph.get_entity_risk_adjustment(_etype, _eval)
            if _freq_sigs:
                reasons.extend(_freq_sigs); score = max(0, min(100, score + _freq_adj))
        # BFS: guilt-by-association
        link_email_scan(p.sender.lower(), domain, float(score))
        add_entity_link("email", p.sender.lower(), "domain", domain, "sent_from_domain")
        g_adj, g_sigs = fraud_graph.connected_risk("email", p.sender.lower())
        if g_sigs:
            reasons.extend(g_sigs); score = max(0, min(100, score + g_adj))

    score, _ = scoring_engine.calibrate(score, "email", reasons)

    ctx_adj, ctx_sigs = scoring_engine.context_adjust("email", p.sender or "", score, reasons)
    if ctx_sigs:
        reasons.extend(ctx_sigs); score = max(0, min(100, score + ctx_adj))

    ai_summary = ""
    content_for_ai = f"Subject: {p.subject or 'N/A'}\nFrom: {p.sender or 'N/A'}\nBody excerpt: {(p.body or '')[:400]}"
    adjustment, ai_summary, ai_signals = await ai_analyze("Email", content_for_ai, score, reasons)
    if ai_signals:
        reasons.extend([f"[AI] {s}" for s in ai_signals])
    score = max(0, min(100, score + adjustment))

    level = level_for(score, "email")
    target = p.subject or p.sender or "Email"
    alert = record_alert("email", target, score, level, reasons, ai_summary)

    return {
        "alert_id": alert.id, "target": target,
        "risk_score": score, "risk_level": level, "reasons": reasons,
        "ai_analysis": ai_summary, "ledger_hash": alert.ledger_hash,
        "recommendation": recommendation(level, "email"),
        "explanation": xai_engine.explain(score, level, reasons, "email", None, adjustment),
    }


# ═══════════════════════════════════════════════════════════════
# ⑧  Phone Number Analyzer
# ═══════════════════════════════════════════════════════════════

class PhonePayload(BaseModel):
    number:       str
    country_code: Optional[str] = None
    call_context: Optional[str] = None
    claimed_org:  Optional[str] = None


async def analyze_phone(p: PhonePayload) -> dict:
    reasons: list[str] = []
    score = 0
    number = re.sub(r"[\s\-\(\)\+\.]", "", p.number)

    if len(number) < 7 or len(number) > 15:
        score += 20
        reasons.append(f"Phone number length ({len(number)} digits) is unusual.")

    if re.match(r"^1(800|888|877|866|855|844|833|822)\d{7}$", number):
        score += 10
        reasons.append("Toll-free number — commonly used in phone scams. Verify independently.")

    if re.match(r"^(\d)\1{6,}$", number):
        score += 35
        reasons.append("Repetitive digit pattern — likely fake/spoofed number.")

    # Premium area code check
    if len(number) >= 3 and number[:3] in PREMIUM_AREA_CODES:
        score += 25
        reasons.append(f"Area code {number[:3]} is associated with premium-rate/scam calls.")

    gov_orgs = ["irs", "social security", "medicare", "fbi", "dea", "customs", "immigration",
                "border patrol", "treasury", "court", "police", "sheriff"]
    if p.claimed_org:
        claimed_low = p.claimed_org.lower()
        gov_hits = [g for g in gov_orgs if g in claimed_low]
        if gov_hits:
            score += 40
            reasons.append(f"Caller claims to be {p.claimed_org} — government agencies do NOT call demanding immediate payment.")

    bank_names = ["bank", "visa", "mastercard", "amex", "paypal", "venmo", "zelle", "crypto"]
    if p.claimed_org:
        bank_hits = [b for b in bank_names if b in p.claimed_org.lower()]
        if bank_hits and p.call_context == "received_call":
            score += 25
            reasons.append(f"Caller claims to represent a financial institution — call back using the official number.")

    if p.call_context == "payment_request":
        score += 30
        reasons.append("Caller is requesting a payment — a major red flag for phone fraud.")
    elif p.call_context == "sms_received":
        score += 10
        reasons.append("SMS from this number — check for embedded links carefully.")

    if p.country_code and p.country_code.upper() in HIGH_RISK_COUNTRIES:
        score += 25
        reasons.append(f"Call originates from high-risk country code ({p.country_code}).")

    if p.call_context == "received_call" and p.country_code and len(number) < 8:
        score += 20
        reasons.append("Short international number with incoming call — possible wangiri/callback scam.")

    if not reasons:
        reasons.append("No strong fraud indicators detected for this phone number.")

    score = max(0, min(score, 100))

    beh_adj, beh_sigs = behavior_engine.analyze("phone", p.number, score)
    if beh_sigs:
        reasons.extend(beh_sigs); score = max(0, min(100, score + beh_adj))

    link_phone_scan(p.number, p.country_code, float(score))
    g_adj, g_sigs = fraud_graph.connected_risk("phone", p.number)
    if g_sigs:
        reasons.extend(g_sigs); score = max(0, min(100, score + g_adj))

    score, _ = scoring_engine.calibrate(score, "phone", reasons)

    ctx_adj, ctx_sigs = scoring_engine.context_adjust("phone", p.number, score, reasons)
    if ctx_sigs:
        reasons.extend(ctx_sigs); score = max(0, min(100, score + ctx_adj))

    content_for_ai = f"Phone: {p.number}, Country: {p.country_code or 'Unknown'}, Context: {p.call_context or 'N/A'}, Claimed org: {p.claimed_org or 'None'}"
    adjustment, ai_summary, ai_signals = await ai_analyze("Phone Fraud", content_for_ai, score, reasons)
    if ai_signals:
        reasons.extend([f"[AI] {s}" for s in ai_signals])
    score = max(0, min(100, score + adjustment))

    level = level_for(score, "phone")
    alert = record_alert("phone", p.number, score, level, reasons, ai_summary)

    return {
        "alert_id": alert.id, "target": p.number,
        "risk_score": score, "risk_level": level, "reasons": reasons,
        "ai_analysis": ai_summary, "ledger_hash": alert.ledger_hash,
        "recommendation": recommendation(level, "phone"),
        "explanation": xai_engine.explain(score, level, reasons, "phone", None, adjustment),
    }


# ═══════════════════════════════════════════════════════════════
# ⑨  SMS Analyzer
# ═══════════════════════════════════════════════════════════════

class SMSPayload(BaseModel):
    message:   str
    sender:    Optional[str] = None
    has_link:  Optional[bool] = None
    link_url:  Optional[str] = None


async def analyze_sms(p: SMSPayload) -> dict:
    reasons: list[str] = []
    score = 0
    msg_low = p.message.lower()

    for pattern in SMS_SCAM_PATTERNS:
        if re.search(pattern, msg_low):
            score += 15
            reasons.append(f"SMS scam pattern: '{pattern[:40]}' detected.")
            if score >= 60:
                break

    if p.has_link or p.link_url:
        score += 15
        reasons.append("SMS contains a link — always verify before clicking.")

    if p.link_url:
        try:
            link_result = await analyze_url(p.link_url, use_ai=False)
            ls = link_result.get("risk_score", 0)
            if ls >= DANGER_THRESHOLD:
                score += 40
                reasons.append(f"Embedded link is dangerous ({ls}/100).")
            elif ls >= CAUTION_THRESHOLD:
                score += 20
                reasons.append(f"Embedded link is suspicious ({ls}/100).")
        except Exception:
            pass

    if p.sender and re.match(r"^\d+$", re.sub(r"[\s\+\-]", "", p.sender)):
        score += 5
        reasons.append("SMS from a numeric ID — can be spoofed.")

    shortener_pattern = r"(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd|rb\.gy)"
    if re.search(shortener_pattern, msg_low):
        score += 20
        reasons.append("SMS contains a URL shortener — real destination is hidden.")

    # Emoji urgency detection
    urgency_emojis = ["🚨", "⚠️", "‼️", "🔴", "❗", "💰", "🤑", "🎁", "💸"]
    emoji_count = sum(p.message.count(e) for e in urgency_emojis)
    if emoji_count >= 2:
        score += 10
        reasons.append(f"Multiple urgency/money emojis ({emoji_count}) — pressure manipulation tactic.")

    # Sender ID impersonation
    if p.sender:
        sender_check = p.sender.lower()
        for org in KNOWN_SENDER_IDS:
            if org in sender_check and re.match(r"^\d+$", re.sub(r"[\s\+\-]", "", p.sender)):
                score += 25
                reasons.append(f"Sender ID spoofs '{org}' with a numeric ID — classic smishing.")
                break

    if not reasons:
        reasons.append("No strong scam indicators detected in this SMS.")

    score = max(0, min(score, 100))

    beh_adj, beh_sigs = behavior_engine.analyze("sms", p.message[:80], score)
    if beh_sigs:
        reasons.extend(beh_sigs); score = max(0, min(100, score + beh_adj))

    # Link SMS entities into graph
    link_domain = None
    if p.link_url:
        from urllib.parse import urlparse as _up
        _h = (_up(p.link_url).hostname or "").lower()
        if _h:
            link_domain = _h
    link_sms_scan(p.sender, link_domain, float(score))
    if link_domain:
        add_entity_link("sms_sender", p.sender or "unknown", "domain", link_domain, "contains_link_to")
        g_adj, g_sigs = fraud_graph.connected_risk("domain", link_domain)
        if g_sigs:
            reasons.extend(g_sigs); score = max(0, min(100, score + g_adj))

    score, _ = scoring_engine.calibrate(score, "sms", reasons)

    ctx_adj, ctx_sigs = scoring_engine.context_adjust("sms", p.message[:80], score, reasons)
    if ctx_sigs:
        reasons.extend(ctx_sigs); score = max(0, min(100, score + ctx_adj))

    content_for_ai = f"SMS: {p.message[:400]}, Sender: {p.sender or 'Unknown'}"
    adjustment, ai_summary, ai_signals = await ai_analyze("SMS Scam", content_for_ai, score, reasons)
    if ai_signals:
        reasons.extend([f"[AI] {s}" for s in ai_signals])
    score = max(0, min(100, score + adjustment))

    level = level_for(score, "sms")
    alert = record_alert("sms", p.message[:60], score, level, reasons, ai_summary)

    return {
        "alert_id": alert.id, "target": p.message[:80],
        "risk_score": score, "risk_level": level, "reasons": reasons,
        "ai_analysis": ai_summary, "ledger_hash": alert.ledger_hash,
        "recommendation": recommendation(level, "sms"),
        "explanation": xai_engine.explain(score, level, reasons, "sms", None, adjustment),
    }


# ═══════════════════════════════════════════════════════════════
# ⑩  Social Media Profile Analyzer
# ═══════════════════════════════════════════════════════════════

class SocialPayload(BaseModel):
    platform:       str
    username:       str
    display_name:   Optional[str] = None
    bio:            Optional[str] = None
    follower_count: Optional[int] = None
    following_count: Optional[int] = None
    post_count:     Optional[int] = None
    account_age_days: Optional[float] = None
    verified:       Optional[bool] = None
    profile_url:    Optional[str] = None
    is_selling:     Optional[bool] = None
    dm_requesting_payment: Optional[bool] = None


async def analyze_social(p: SocialPayload) -> dict:
    reasons: list[str] = []
    score = 0

    username_low = p.username.lower()
    display_low  = (p.display_name or "").lower()
    bio_low      = (p.bio or "").lower()

    for brand in POPULAR_BRANDS:
        if brand in username_low and leet_normalize(username_low) != username_low:
            score += 35
            reasons.append(f"Username contains leet-spoof of brand '{brand}'.")
            break
        if brand in username_low:
            score += 20
            reasons.append(f"Username contains brand name '{brand}' — verify this is an official account.")
            break
        if brand in display_low and p.verified is not True:
            score += 25
            reasons.append(f"Display name contains brand '{brand}' but account is not verified.")
            break

    if (p.follower_count is not None and p.following_count is not None
            and p.following_count > 0):
        ratio = p.follower_count / p.following_count
        if ratio < 0.1 and p.follower_count < 100:
            score += 20
            reasons.append(f"Very low follower/following ratio ({ratio:.2f}) — possible bot or fake account.")

    if p.account_age_days is not None and p.account_age_days < 30:
        score += 20
        reasons.append(f"Account is only {p.account_age_days:.0f} days old.")
        if p.is_selling:
            score += 25
            reasons.append("New account is already selling — high risk of scam.")

    if p.dm_requesting_payment:
        score += 45
        reasons.append("Account is requesting payment via DM — classic social media scam.")

    investment_bio = ["guaranteed returns", "double your money", "investment opportunity",
                      "dm me", "dm for info", "earn from home", "crypto trader",
                      "passive income", "forex", "binary options"]
    bio_hits = [b for b in investment_bio if b in bio_low]
    if bio_hits:
        score += min(30, len(bio_hits) * 12)
        reasons.append(f"Bio contains investment/scam language: {', '.join(bio_hits[:2])}.")

    if p.profile_url:
        try:
            url_result = await analyze_url(p.profile_url, use_ai=False)
            us = url_result.get("risk_score", 0)
            if us >= CAUTION_THRESHOLD:
                score += 20
                reasons.append(f"Profile link URL is suspicious ({us}/100).")
        except Exception:
            pass

    if not reasons:
        reasons.append("No strong social media fraud indicators detected.")

    score = max(0, min(score, 100))

    content_for_ai = f"Platform: {p.platform}, Username: {p.username}, Display: {p.display_name}, Bio: {(p.bio or '')[:200]}"
    adjustment, ai_summary, ai_signals = await ai_analyze("Social Media Profile", content_for_ai, score, reasons)
    if ai_signals:
        reasons.extend([f"[AI] {s}" for s in ai_signals])
    score = max(0, min(100, score + adjustment))

    level = level_for(score, "social")
    alert = record_alert("social", f"@{p.username} ({p.platform})", score, level, reasons, ai_summary)

    return {
        "alert_id": alert.id, "target": f"@{p.username} on {p.platform}",
        "risk_score": score, "risk_level": level, "reasons": reasons,
        "ai_analysis": ai_summary, "ledger_hash": alert.ledger_hash,
        "recommendation": recommendation(level, "social"),
        "explanation": xai_engine.explain(score, level, reasons, "social", None, adjustment),
    }


# ═══════════════════════════════════════════════════════════════
# ⑪  Merchant Analyzer
# ═══════════════════════════════════════════════════════════════

class MerchantPayload(BaseModel):
    name:                str
    account_id:          Optional[str]   = None
    country:             Optional[str]   = None
    account_age_days:    Optional[float] = None
    verified:            Optional[bool]  = None
    complaints:          Optional[int]   = None
    avg_transaction_usd: Optional[float] = None
    website:             Optional[str]   = None


async def analyze_merchant(p: MerchantPayload) -> dict:
    reasons: list[str] = []
    score = 0
    name     = p.name.strip()
    name_low = name.lower()

    for brand in POPULAR_BRANDS:
        norm = leet_normalize(name_low)
        if brand in norm:
            if brand not in name_low:
                score += 40
                reasons.append(f"Name contains leet-spoof of brand '{brand}'.")
            else:
                score += 30
                reasons.append(f"Name contains brand '{brand}' — verify this is the official merchant.")
            break
        for token in re.split(r"[\s\-_.,]+", name_low):
            ntoken = leet_normalize(token)
            if token and levenshtein(ntoken, brand) <= 1 and len(brand) >= 5:
                score += 35
                reasons.append(f"Name token '{token}' is close to brand '{brand}' — possible impersonation.")
                break

    kw_hits = [k for k in PHISH_KEYWORDS if k in name_low]
    if kw_hits:
        score += min(25, len(kw_hits) * 10)
        reasons.append(f"Merchant name contains suspicious keywords: {', '.join(kw_hits[:3])}.")

    if p.account_age_days is not None:
        if p.account_age_days < 7:
            score += 40
            reasons.append(f"Account is only {p.account_age_days:.0f} day(s) old.")
        elif p.account_age_days < 30:
            score += 20
            reasons.append(f"Account is {p.account_age_days:.0f} days old — relatively new.")

    if p.verified is False:
        score += 25
        reasons.append("Merchant account is not verified.")
    elif p.verified is None:
        score += 10
        reasons.append("Verification status unknown.")

    if p.country:
        cc = p.country.strip().upper()
        if cc in HIGH_RISK_COUNTRIES:
            score += 30
            reasons.append(f"Country '{cc}' has an elevated payment-fraud base-rate.")

    if p.complaints and p.complaints > 0:
        score += min(30, p.complaints * 15)
        reasons.append(f"{p.complaints} prior complaint(s) recorded.")

    if p.avg_transaction_usd and p.avg_transaction_usd > 5000:
        score += 10
        reasons.append(f"High average transaction amount (${p.avg_transaction_usd:,.0f}).")

    if p.website:
        try:
            ws = await analyze_url(p.website, use_ai=False)
            if ws["risk_score"] >= DANGER_THRESHOLD:
                score += 35
                reasons.append(f"Merchant website scored as dangerous ({ws['risk_score']}/100).")
            elif ws["risk_score"] >= CAUTION_THRESHOLD:
                score += 15
                reasons.append(f"Merchant website is suspicious ({ws['risk_score']}/100).")
        except Exception:
            pass

    if not reasons:
        reasons.append("No strong risk signals detected.")

    score = max(0, min(score, 100))

    content_for_ai = f"Merchant: {name}, Country: {p.country or 'N/A'}, Age: {p.account_age_days or 'N/A'} days, Verified: {p.verified}"
    adjustment, ai_summary, ai_signals = await ai_analyze("Merchant Fraud", content_for_ai, score, reasons)
    if ai_signals:
        reasons.extend([f"[AI] {s}" for s in ai_signals])
    score = max(0, min(100, score + adjustment))

    level = level_for(score, "merchant")
    alert = record_alert("merchant", name, score, level, reasons, ai_summary)

    return {
        "alert_id": alert.id, "target": name,
        "risk_score": score, "risk_level": level, "reasons": reasons,
        "ai_analysis": ai_summary, "ledger_hash": alert.ledger_hash,
        "recommendation": recommendation(level, "merchant"),
        "explanation": xai_engine.explain(score, level, reasons, "merchant", None, adjustment),
    }


# ═══════════════════════════════════════════════════════════════
# ⑫  File Analyzer
# ═══════════════════════════════════════════════════════════════

async def analyze_file(filename: str, contents: bytes) -> dict:
    sha256      = hashlib.sha256(contents).hexdigest()
    size        = len(contents)
    parts       = filename.lower().rsplit(".", 1)
    ext         = parts[1] if len(parts) == 2 else ""
    reasons: list[str] = []
    score = 0
    actual_type = detect_magic(contents)

    if sha256 in KNOWN_MALWARE_HASHES:
        score += 85
        reasons.append("File hash matches a known malware signature.")

    expected = EXT_TO_TYPE.get(ext)
    if expected and actual_type and expected != actual_type:
        score += 50
        reasons.append(f"Claims '.{ext}' but contents are '{actual_type}' — file-type disguise.")

    if ext in DANGEROUS_EXTENSIONS:
        score += 55
        reasons.append(f"'.{ext}' is an executable/script extension commonly used to deliver malware.")

    if re.search(r"\.[a-z0-9]{2,4}\.(exe|scr|bat|cmd|vbs|js|jar|hta|ps1|msi)$", filename, re.I):
        score += 35
        reasons.append("Double extension detected (e.g. '.pdf.exe') — classic social-engineering trick.")

    if ext in MACRO_ENABLED_EXTENSIONS:
        score += 30
        reasons.append(f"'.{ext}' is a macro-enabled Office format.")
    elif ext in MACRO_CAPABLE_EXTENSIONS:
        score += 10
        reasons.append(f"'.{ext}' can carry embedded macros or exploits.")

    if actual_type == "zip" and b"vbaProject.bin" in contents:
        score += 50
        reasons.append("Archive contains a VBA macro module — macro malware indicator.")

    if actual_type == "pdf" or ext == "pdf":
        hit_names: list[str] = []
        for tok, weight in _PDF_RISKY_TOKENS.items():
            if tok in contents:
                score += weight
                hit_names.append(tok.decode())
        if hit_names:
            reasons.append(f"PDF contains risky objects: {', '.join(hit_names)}.")

    low = contents[:16384].lower()
    script_hits = [s.decode(errors="ignore") for s in _SCRIPT_INDICATORS if s in low]
    if script_hits:
        score += min(35, 12 * len(script_hits))
        reasons.append(f"Contains script-execution strings: {', '.join(script_hits[:3])}.")

    if contents[:2] == b"MZ":
        if ext in {"exe", "dll", "scr", "com", "cpl", "sys"}:
            score += 20
            reasons.append("Confirmed Windows PE binary (MZ header).")
        else:
            score += 25
            reasons.append("File has an MZ/PE header — Windows executable in disguise.")

    if ext in {"doc", "docx", "pdf"} and size < 4096 and actual_type != "pdf":
        score += 10
        reasons.append(f"File is suspiciously small ({size} bytes) for a '.{ext}' — possible dropper.")

    if size > 50 * 1024 * 1024 and ext not in {"iso", "img", "zip", "mp4", "mov", "mkv"}:
        score += 10
        reasons.append(f"File is very large ({size // (1024*1024)} MB) for its declared type.")

    score = max(0, min(score, 100))
    if not reasons:
        reasons.append("No obvious malware indicators detected.")

    level = level_for(score, "file")
    alert = record_alert("file", filename, score, level, reasons)

    return {
        "alert_id": alert.id, "target": filename, "sha256": sha256,
        "size_bytes": size, "extension": ext, "detected_type": actual_type,
        "risk_score": score, "risk_level": level, "reasons": reasons,
        "ledger_hash": alert.ledger_hash,
        "recommendation": recommendation(level, "file"),
        "explanation": xai_engine.explain(score, level, reasons, "file"),
    }


# ═══════════════════════════════════════════════════════════════
# ⑬  QR Code Analyzer
# ═══════════════════════════════════════════════════════════════

class QRPayload(BaseModel):
    decoded_url: str
    context:     Optional[str] = None


async def analyze_qr(p: QRPayload) -> dict:
    reasons: list[str] = []
    score = 0

    url_result = await analyze_url(p.decoded_url, use_ai=False)
    url_score  = url_result.get("risk_score", 0)
    score += url_score
    reasons.extend([f"[URL] {r}" for r in url_result.get("reasons", []) if "whitelist" not in r])

    if p.context == "payment":
        score += 15
        reasons.append("QR code is for a payment — extra caution: verify the payee.")
    elif p.context == "unknown":
        score += 10
        reasons.append("QR code from an unknown/untrusted source.")

    if url_score >= CAUTION_THRESHOLD:
        score += 10
        reasons.append("Suspicious QR codes may be physical stickers placed over legitimate ones.")

    score = max(0, min(score, 100))

    ai_summary = ""
    content_for_ai = f"QR URL: {p.decoded_url}, Context: {p.context or 'unknown'}"
    adjustment, ai_summary, ai_signals = await ai_analyze("QR Code", content_for_ai, score, reasons)
    if ai_signals:
        reasons.extend([f"[AI] {s}" for s in ai_signals])
    score = max(0, min(100, score + adjustment))

    level = level_for(score, "qr")
    alert = record_alert("qr", p.decoded_url, score, level, reasons, ai_summary)

    return {
        "alert_id": alert.id, "target": p.decoded_url,
        "risk_score": score, "risk_level": level, "reasons": reasons,
        "ai_analysis": ai_summary, "ledger_hash": alert.ledger_hash,
        "recommendation": recommendation(level, "qr"),
        "explanation": xai_engine.explain(score, level, reasons, "qr", None, adjustment),
    }


# ═══════════════════════════════════════════════════════════════
# ⑭  IP Address Analyzer  (NEW)
# ═══════════════════════════════════════════════════════════════

class IPPayload(BaseModel):
    ip_address: str
    context:    Optional[str] = None  # "login_attempt"|"transaction"|"api_call"|"email_sender"
    port:       Optional[int] = None


async def analyze_ip(p: IPPayload) -> dict:
    reasons: list[str] = []
    score = 0
    ip = p.ip_address.strip()

    ipv4_re = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    ipv6_re = re.compile(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$")
    is_ipv4 = bool(ipv4_re.match(ip))
    is_ipv6 = bool(ipv6_re.match(ip))

    if not is_ipv4 and not is_ipv6:
        score += 20
        reasons.append("Input does not appear to be a valid IPv4 or IPv6 address.")

    # Private / reserved range
    if any(ip.startswith(prefix) for prefix in PRIVATE_IP_PREFIXES):
        score += 40
        reasons.append(f"IP {ip} is in a private/reserved range — should never appear in external traffic.")

    # Loopback
    if ip.startswith("127.") or ip == "::1":
        score += 25
        reasons.append("Loopback address used in external context is suspicious.")

    # All-same-octet pattern (common in spoofed/test IPs)
    if is_ipv4:
        octets = ip.split(".")
        try:
            vals = [int(o) for o in octets]
            if all(v == vals[0] for v in vals):
                score += 30
                reasons.append("All octets identical — common in spoofed/test addresses.")
            if vals[0] == 0 or vals[-1] == 0 or vals[-1] == 255:
                score += 15
                reasons.append("Network or broadcast address used as source — invalid for real traffic.")
            if octets[0] in DATACENTER_FIRST_OCTETS and p.context in ("login_attempt", "transaction"):
                score += 20
                reasons.append(f"First octet /{octets[0]}.x.x.x is a well-known datacenter range — unusual for end-users.")
        except ValueError:
            score += 20
            reasons.append("IP octets contain non-integer values.")

    # Risky port
    if p.port:
        if p.port in RISKY_PORTS:
            svc = RISKY_PORTS[p.port]
            score += 25
            reasons.append(f"Port {p.port} ({svc}) is a high-risk service port.")
        elif p.port < 1024 and p.port not in (80, 443, 25, 587, 53):
            score += 15
            reasons.append(f"Low-numbered port {p.port} is privileged and unusual for web connections.")
        elif p.port > 49151:
            score += 10
            reasons.append(f"Ephemeral port {p.port} used as a server port is suspicious.")

    # Context risk
    if p.context == "login_attempt":
        score += 5
        reasons.append("IP observed in login context — monitor for brute-force patterns.")
    elif p.context == "transaction":
        score += 10
        reasons.append("IP used for a financial transaction — elevated verification recommended.")
    elif p.context == "email_sender":
        score += 5
        reasons.append("IP reported as email sender — check SPF/DKIM/DMARC records.")

    if not reasons:
        reasons.append("No strong risk indicators for this IP address.")

    score = max(0, min(score, 100))

    beh_adj, beh_sigs = behavior_engine.analyze("ip", ip, score)
    if beh_sigs:
        reasons.extend(beh_sigs); score = max(0, min(100, score + beh_adj))

    link_ip_scan(ip, float(score))
    g_adj, g_sigs = fraud_graph.connected_risk("ip", ip)
    if g_sigs:
        reasons.extend(g_sigs); score = max(0, min(100, score + g_adj))

    score, _ = scoring_engine.calibrate(score, "ip", reasons)

    ctx_adj, ctx_sigs = scoring_engine.context_adjust("ip", ip, score, reasons)
    if ctx_sigs:
        reasons.extend(ctx_sigs); score = max(0, min(100, score + ctx_adj))

    content_for_ai = f"IP: {ip}, Port: {p.port or 'N/A'}, Context: {p.context or 'N/A'}"
    adjustment, ai_summary, ai_signals = await ai_analyze("IP Address", content_for_ai, score, reasons)
    if ai_signals:
        reasons.extend([f"[AI] {s}" for s in ai_signals])
    score = max(0, min(100, score + adjustment))

    level = level_for(score, "ip")
    target_str = f"{ip}:{p.port}" if p.port else ip
    alert = record_alert("ip", target_str, score, level, reasons, ai_summary)

    return {
        "alert_id": alert.id, "target": target_str,
        "ip_version": "IPv6" if is_ipv6 else ("IPv4" if is_ipv4 else "invalid"),
        "risk_score": score, "risk_level": level, "reasons": reasons,
        "ai_analysis": ai_summary, "ledger_hash": alert.ledger_hash,
        "recommendation": recommendation(level, "ip"),
        "explanation": xai_engine.explain(score, level, reasons, "ip", None, adjustment),
    }


# ═══════════════════════════════════════════════════════════════
# ⑮  Cryptocurrency Address Analyzer  (NEW)
# ═══════════════════════════════════════════════════════════════

class CryptoPayload(BaseModel):
    address:   str
    coin:      Optional[str] = None   # "BTC"|"ETH"|"LTC"|"XMR"|"TRX"|"SOL"|"BNB"
    context:   Optional[str] = None   # "payment_request"|"investment"|"donation"
    message:   Optional[str] = None


async def analyze_crypto(p: CryptoPayload) -> dict:
    reasons: list[str] = []
    score = 0
    addr    = p.address.strip()
    msg_low = (p.message or "").lower()

    # Address format validation
    detected_coin = None
    for coin_key, pattern in CRYPTO_ADDRESS_PATTERNS.items():
        if re.match(pattern, addr):
            detected_coin = coin_key
            break

    if not detected_coin:
        score += 30
        reasons.append("Address does not match any known cryptocurrency format (BTC/ETH/LTC/XMR/TRX/SOL/BNB).")
    else:
        if p.coin and p.coin.upper() not in detected_coin.upper():
            score += 20
            reasons.append(f"Address format ({detected_coin}) does not match claimed coin ({p.coin}) — possible address substitution attack.")
        else:
            reasons.append(f"Address validates as {detected_coin.upper()} format.")

    # Mixer / tumbler detection
    if msg_low:
        mixer_hits = [m for m in CRYPTO_MIXER_LABELS if m in msg_low]
        if mixer_hits:
            score += 40
            reasons.append(f"Message references known mixer/tumbler services: {', '.join(mixer_hits)}.")

    # Scam phrase detection
    scam_hits = [s for s in CRYPTO_SCAM_PHRASES if s in msg_low]
    if scam_hits:
        score += min(45, len(scam_hits) * 15)
        reasons.append(f"Scam phrases in context: {', '.join(scam_hits[:3])}.")

    # Context risk
    if p.context == "payment_request":
        score += 15
        reasons.append("Crypto payment requested — verify payee identity through an out-of-band channel.")
    elif p.context == "investment":
        score += 30
        reasons.append("Crypto investment solicitation — extremely high fraud base-rate in unsolicited investment offers.")
    elif p.context == "donation":
        score += 5
        reasons.append("Donation address — always verify via the organization's official website.")

    # Entropy check (random disposable wallets)
    ent = shannon_entropy(addr.lower())
    if ent > 4.2:
        score += 10
        reasons.append(f"Address entropy ({ent:.2f}) is consistent with auto-generated disposable wallets.")

    # Monero elevated risk (privacy coin)
    if detected_coin == "xmr":
        score += 15
        reasons.append("Monero (XMR) is a privacy coin that obscures transaction trails — commonly used in scams.")

    # Very few unique characters (fake/test address)
    unique_chars = len(set(addr.lower().replace("0x", "").replace("1", "")))
    if unique_chars <= 4:
        score += 20
        reasons.append("Address has very few unique characters — possibly a fake or test address.")

    if not reasons or all("validates" in r for r in reasons):
        reasons.append("No strong fraud signals detected for this address in the given context.")

    score = max(0, min(score, 100))

    beh_adj, beh_sigs = behavior_engine.analyze("crypto", addr, score)
    if beh_sigs:
        reasons.extend(beh_sigs); score = max(0, min(100, score + beh_adj))

    # Graph: frequency — same address reused in multiple fraud alerts
    _freq_adj, _freq_sigs = fraud_graph.get_entity_risk_adjustment("crypto", addr)
    if _freq_sigs:
        reasons.extend(_freq_sigs); score = max(0, min(100, score + _freq_adj))

    link_crypto_scan(addr, detected_coin, float(score))
    add_entity_link("crypto", addr, "coin_type", detected_coin or "unknown", "coin_type")
    g_adj, g_sigs = fraud_graph.connected_risk("crypto", addr)
    if g_sigs:
        reasons.extend(g_sigs); score = max(0, min(100, score + g_adj))

    score, _ = scoring_engine.calibrate(score, "crypto", reasons)

    ctx_adj, ctx_sigs = scoring_engine.context_adjust("crypto", addr, score, reasons)
    if ctx_sigs:
        reasons.extend(ctx_sigs); score = max(0, min(100, score + ctx_adj))

    content_for_ai = f"Crypto address: {addr}, Type: {detected_coin or 'unknown'}, Context: {p.context or 'N/A'}, Message: {(p.message or '')[:200]}"
    adjustment, ai_summary, ai_signals = await ai_analyze("Cryptocurrency Address", content_for_ai, score, reasons)
    if ai_signals:
        reasons.extend([f"[AI] {s}" for s in ai_signals])
    score = max(0, min(100, score + adjustment))

    level = level_for(score, "crypto")
    alert = record_alert("crypto", addr[:60], score, level, reasons, ai_summary)

    return {
        "alert_id": alert.id, "target": addr,
        "detected_coin": detected_coin,
        "risk_score": score, "risk_level": level, "reasons": reasons,
        "ai_analysis": ai_summary, "ledger_hash": alert.ledger_hash,
        "recommendation": recommendation(level, "crypto"),
        "explanation": xai_engine.explain(score, level, reasons, "crypto", None, adjustment),
    }


# ═══════════════════════════════════════════════════════════════
# ⑯  Bulk URL Scanner  (NEW)
# ═══════════════════════════════════════════════════════════════

class BulkURLPayload(BaseModel):
    urls:    List[str]
    use_ai:  bool = False


async def analyze_bulk_urls(urls: List[str], use_ai: bool = False) -> dict:
    urls = [u.strip() for u in urls if u.strip()][:20]

    async def safe_scan(raw: str) -> dict:
        try:
            return await analyze_url(raw, use_ai=use_ai)
        except Exception as exc:
            return {
                "target": raw, "risk_score": 0, "risk_level": "safe",
                "reasons": [f"Scan error: {exc}"], "error": True,
            }

    results = list(await asyncio.gather(*[safe_scan(u) for u in urls]))

    danger_count  = sum(1 for r in results if r.get("risk_level") == "danger")
    caution_count = sum(1 for r in results if r.get("risk_level") == "caution")
    safe_count    = sum(1 for r in results if r.get("risk_level") == "safe")
    max_score     = max((r.get("risk_score", 0) for r in results), default=0)

    return {
        "total": len(results),
        "danger": danger_count,
        "caution": caution_count,
        "safe": safe_count,
        "max_score": max_score,
        "results": results,
    }


# ═══════════════════════════════════════════════════════════════
# ⑰  Recommendations
# ═══════════════════════════════════════════════════════════════

def recommendation(level: str, kind: str) -> str:
    _msgs: dict[str, dict[str, str]] = {
        "danger": {
            "payment": "Do NOT enter any payment details on this page. This appears to be a fake payment page designed to steal your card or banking information. Close this tab immediately and contact your bank if you entered any details.",
            "url":      "Do NOT visit this link. Report it to your security team or bank immediately.",
            "email":    "Do NOT click any links or open attachments. Mark as phishing and delete.",
            "phone":    "Do NOT call back or provide any information. Block the number immediately.",
            "merchant": "Do NOT send any payment. Verify the merchant through official channels first.",
            "file":     "Do NOT open this file. Delete it immediately and run a full device scan.",
            "social":   "Do NOT engage or send money. Report the account to the platform.",
            "sms":      "Do NOT click any links. Block the sender and report as spam.",
            "qr":       "Do NOT scan or proceed with this QR code. It may lead to a phishing site.",
            "ip":       "Block this IP immediately. Investigate any sessions or transactions linked to it.",
            "crypto":   "Do NOT send funds to this address. This shows characteristics of a scam wallet.",
        },
        "caution": {
            "payment": "Proceed with extreme caution. Verify the payment page URL, check for HTTPS, and confirm the domain exactly matches the official gateway before entering card details.",
            "url":      "Proceed with caution. Double-check the domain and do not enter credentials.",
            "email":    "Verify the sender's identity through a separate channel before acting.",
            "phone":    "Do not share sensitive info. Call back using the official number from the org's website.",
            "merchant": "Verify the merchant independently before paying.",
            "file":     "Open only if you fully trust the sender. Scan with antivirus first.",
            "social":   "Verify account authenticity through the platform's official verification.",
            "sms":      "Do not click links. Verify the message through the official channel.",
            "qr":       "Preview the URL before proceeding. Verify it matches the expected destination.",
            "ip":       "Flag for review. Check if this IP appears across multiple suspicious events.",
            "crypto":   "Proceed with extreme caution. Verify the address via official channels before sending.",
        },
        "safe": {
            "payment": "Payment page appears legitimate. Always verify the padlock icon (HTTPS) and confirm the domain in your browser's address bar before entering card details.",
            "url":      "No strong phishing signals detected. Normal caution still advised.",
            "email":    "No strong scam signals detected. Normal caution still advised.",
            "phone":    "No strong fraud indicators. Normal caution still advised.",
            "merchant": "No strong risk signals detected. Normal caution still advised.",
            "file":     "No strong malware signals detected. Normal caution still advised.",
            "social":   "No strong fraud indicators detected. Normal caution still advised.",
            "sms":      "No strong scam indicators detected. Normal caution still advised.",
            "qr":       "No strong phishing signals. Normal caution still advised.",
            "ip":       "No strong threat signals for this IP. Monitor for unusual activity.",
            "crypto":   "No strong scam signals detected. Always double-check addresses before sending.",
        },
    }
    return _msgs.get(level, _msgs["safe"]).get(kind, "No recommendation available.")


# ═══════════════════════════════════════════════════════════════
# ⑱  FastAPI Application
# ═══════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Initialise SQLite schemas
    init_db()
    init_auth_db()

    # Restore ledger from DB so blocks survive server restarts
    for row in load_ledger_blocks():
        LEDGER.append(LedgerBlock(
            index=row["idx"], timestamp=row["timestamp"],
            alert_id=row["alert_id"], payload_hash=row["payload_hash"],
            prev_hash=row["prev_hash"], block_hash=row["block_hash"],
        ))

    # Load or auto-train the URL ML model
    if not url_ml_model.load():
        try:
            import logging
            logging.getLogger("fraudx.ml").info(
                "No url_model.pkl found — auto-training on synthetic data…"
            )
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, url_ml_model.auto_train)
        except Exception as exc:
            import logging
            logging.getLogger("fraudx.ml").warning("Auto-train failed: %s", exc)

    def _sha256_str(s: str) -> str:
        return hashlib.sha256(s.encode()).hexdigest()
    KNOWN_MALWARE_HASHES.add(_sha256_str("demo-eicar-like-string"))
    KNOWN_MALWARE_HASHES.add("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
    yield


app = FastAPI(
    title="FRAUD-X Real-Time Detection v2",
    description="AI-powered real-time fraud, phishing, scam and malware detection.",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "chrome-extension://",
    ],
    allow_origin_regex=r"chrome-extension://[a-z]{32}",
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)

INDEX_HTML  = Path(__file__).parent / "index.html"
LOGIN_HTML  = Path(__file__).parent / "login.html"
SIGNUP_HTML = Path(__file__).parent / "signup.html"
AUTH_DB     = Path(__file__).parent / "fraudx.db"

JWT_SECRET      = os.environ.get("FRAUDX_JWT_SECRET", "fraudx-dev-secret-change-in-production")
JWT_ALGO        = "HS256"
JWT_EXPIRE_DAYS = 7


# ─── Auth DB helpers ─────────────────────────────────────────────────────────

def _auth_conn():
    conn = sqlite3.connect(str(AUTH_DB))
    conn.row_factory = sqlite3.Row
    return conn


def init_auth_db():
    with _auth_conn() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS users (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            email       TEXT UNIQUE,
            mobile      TEXT UNIQUE,
            google_id   TEXT UNIQUE,
            password_hash TEXT,
            avatar      TEXT,
            created_at  REAL NOT NULL,
            is_active   INTEGER DEFAULT 1
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS otp_store (
            mobile     TEXT PRIMARY KEY,
            otp        TEXT NOT NULL,
            expires_at REAL NOT NULL
        )""")
        # Seed demo/default accounts on first run
        import bcrypt as _bcrypt, uuid as _uuid
        _DEMO_USERS = [
            ("Super Admin",   "super_admin@fraudx.ai",   "FraudX@Admin2025!"),
            ("Admin",         "admin@fraudx.ai",         "Admin@2025!"),
            ("Analyst",       "analyst@fraudx.ai",       "Analyst@2025!"),
            ("Investigator",  "investigator@fraudx.ai",  "Invest@2025!"),
            ("Admin",         "admin@fraudx.local",      "Admin@1234"),
        ]
        for _name, _email, _pw_plain in _DEMO_USERS:
            exists = c.execute("SELECT id FROM users WHERE email = ?", (_email,)).fetchone()
            if exists is None:
                _pw_hash = _bcrypt.hashpw(_pw_plain.encode(), _bcrypt.gensalt()).decode()
                c.execute(
                    "INSERT INTO users (id,name,email,password_hash,created_at) VALUES (?,?,?,?,?)",
                    (str(_uuid.uuid4()), _name, _email, _pw_hash, time.time()),
                )


def _make_token(user_id: str, name: str, email: str) -> str:
    import jwt as pyjwt
    payload = {
        "sub": user_id, "name": name, "email": email or "",
        "iat": int(time.time()),
        "exp": int(time.time()) + JWT_EXPIRE_DAYS * 86400,
    }
    return pyjwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)


def _verify_token(token: str) -> dict:
    import jwt as pyjwt
    try:
        return pyjwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


_bearer = HTTPBearer(auto_error=False)


def get_current_user(creds: HTTPAuthorizationCredentials = Depends(_bearer)) -> dict:
    if not creds:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return _verify_token(creds.credentials)


# ─── Auth Pydantic models ────────────────────────────────────────────────────

class SignupPayload(BaseModel):
    name: str
    email: Optional[str] = None
    mobile: Optional[str] = None
    password: Optional[str] = None

class LoginPayload(BaseModel):
    email: str
    password: str

class MobileOtpSendPayload(BaseModel):
    mobile: str

class MobileOtpVerifyPayload(BaseModel):
    mobile: str
    otp: str

class GoogleAuthPayload(BaseModel):
    credential: str   # Google ID token from GSI JS library


# ─── Auth endpoints ──────────────────────────────────────────────────────────

@app.get("/login",  include_in_schema=False)
def login_page():
    return FileResponse(str(LOGIN_HTML))

@app.get("/signup", include_in_schema=False)
def signup_page():
    return FileResponse(str(SIGNUP_HTML))


@app.post("/auth/signup", tags=["Auth"])
def auth_signup(p: SignupPayload):
    if not p.email and not p.mobile:
        raise HTTPException(status_code=400, detail="Email or mobile required")
    if p.email and not p.password:
        raise HTTPException(status_code=400, detail="Password required for email signup")
    uid = str(uuid.uuid4())
    pw_hash = bcrypt.hashpw(p.password.encode(), bcrypt.gensalt()).decode() if p.password else None
    try:
        with _auth_conn() as c:
            c.execute(
                "INSERT INTO users (id,name,email,mobile,password_hash,created_at) VALUES (?,?,?,?,?,?)",
                (uid, p.name, p.email, p.mobile, pw_hash, time.time()),
            )
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Email or mobile already registered")
    token = _make_token(uid, p.name, p.email or "")
    return {"token": token, "name": p.name, "email": p.email, "id": uid}


@app.post("/auth/login", tags=["Auth"])
def auth_login(p: LoginPayload):
    with _auth_conn() as c:
        row = c.execute("SELECT * FROM users WHERE email=?", (p.email,)).fetchone()
    if not row or not row["password_hash"]:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not bcrypt.checkpw(p.password.encode(), row["password_hash"].encode()):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = _make_token(row["id"], row["name"], row["email"] or "")
    return {"token": token, "name": row["name"], "email": row["email"], "id": row["id"]}


@app.post("/auth/mobile/send-otp", tags=["Auth"])
def auth_send_otp(p: MobileOtpSendPayload):
    otp = str(secrets.randbelow(900000) + 100000)   # 6-digit OTP
    expires = time.time() + 600                      # 10-minute expiry
    with _auth_conn() as c:
        c.execute("INSERT OR REPLACE INTO otp_store VALUES (?,?,?)", (p.mobile, otp, expires))
    # In production: integrate an SMS gateway here (Twilio/MSG91).
    # For development we return the OTP directly so the UI can fill it.
    return {"message": "OTP sent", "dev_otp": otp}


@app.post("/auth/mobile/verify-otp", tags=["Auth"])
def auth_verify_otp(p: MobileOtpVerifyPayload):
    with _auth_conn() as c:
        row = c.execute("SELECT * FROM otp_store WHERE mobile=?", (p.mobile,)).fetchone()
    if not row or row["otp"] != p.otp:
        raise HTTPException(status_code=401, detail="Invalid OTP")
    if time.time() > row["expires_at"]:
        raise HTTPException(status_code=401, detail="OTP expired")
    # Find or create user
    with _auth_conn() as c:
        user = c.execute("SELECT * FROM users WHERE mobile=?", (p.mobile,)).fetchone()
        if not user:
            uid = str(uuid.uuid4())
            c.execute(
                "INSERT INTO users (id,name,mobile,created_at) VALUES (?,?,?,?)",
                (uid, p.mobile, p.mobile, time.time()),
            )
            name, email = p.mobile, ""
        else:
            uid, name, email = user["id"], user["name"], user["email"] or ""
        c.execute("DELETE FROM otp_store WHERE mobile=?", (p.mobile,))
    token = _make_token(uid, name, email)
    return {"token": token, "name": name, "email": email, "id": uid}


@app.post("/auth/google", tags=["Auth"])
async def auth_google(p: GoogleAuthPayload):
    """Verify a Google ID token from Google Identity Services and sign in / register the user."""
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            r = await client.get(
                "https://oauth2.googleapis.com/tokeninfo",
                params={"id_token": p.credential},
            )
        if r.status_code != 200:
            raise HTTPException(status_code=401, detail="Invalid Google token")
        gdata = r.json()
        google_id = gdata.get("sub")
        email     = gdata.get("email", "")
        name      = gdata.get("name", email.split("@")[0])
        avatar    = gdata.get("picture", "")
        if not google_id:
            raise HTTPException(status_code=401, detail="Google token missing sub")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Google token verification failed")

    with _auth_conn() as c:
        user = c.execute("SELECT * FROM users WHERE google_id=? OR email=?", (google_id, email)).fetchone()
        if user:
            uid  = user["id"]
            name = user["name"]
            c.execute("UPDATE users SET google_id=?,avatar=? WHERE id=?", (google_id, avatar, uid))
        else:
            uid = str(uuid.uuid4())
            c.execute(
                "INSERT INTO users (id,name,email,google_id,avatar,created_at) VALUES (?,?,?,?,?,?)",
                (uid, name, email, google_id, avatar, time.time()),
            )
    token = _make_token(uid, name, email)
    return {"token": token, "name": name, "email": email, "id": uid, "avatar": avatar}


@app.get("/auth/me", tags=["Auth"])
def auth_me(user: dict = Depends(get_current_user)):
    with _auth_conn() as c:
        row = c.execute("SELECT id,name,email,mobile,avatar,created_at FROM users WHERE id=?", (user["sub"],)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    return dict(row)


# ─── Main page / pages ───────────────────────────────────────────────────────

@app.get("/", include_in_schema=False)
def root():
    # Serve Next.js static export if built
    if INDEX_HTML.exists():
        return FileResponse(str(INDEX_HTML))
    return JSONResponse({"status": "ok", "docs": "/docs"})


class UrlPayload(BaseModel):
    url: str
    use_ai: bool = True


class PaymentPayload(BaseModel):
    url: str
    domain:           Optional[str]       = None
    page_title:       Optional[str]       = None
    merchant_name:    Optional[str]       = None
    has_payment_form: bool                = False
    form_action_url:  Optional[str]       = None
    form_field_names: Optional[List[str]] = None
    use_ai:           bool                = False   # default off — stay under 300 ms


class NotesPayload(BaseModel):
    notes: str


# ── Scanners ──────────────────────────────────────────────────

@app.post("/api/scan/url", summary="Scan a URL for phishing", tags=["Scanners"])
async def scan_url(payload: UrlPayload):
    return await analyze_url(payload.url, use_ai=payload.use_ai)


@app.post("/api/scan/payment", summary="Payment gateway verification (URL + page context)", tags=["Scanners"])
async def scan_payment(payload: PaymentPayload):
    """
    Full payment-page analysis combining URL heuristics with payment-specific signals.

    Accepts page context from the Chrome extension (title, merchant name, form signals)
    and runs the complete FRAUD-X engine pipeline, recording a kind='payment' alert.

    - **is_trusted_gateway**: True when the domain is on the verified gateway whitelist
    - **gateway_info**: breakdown of which payment-specific signals fired
    - **recommendation**: user-facing action advice
    """
    return await analyze_payment(payload)


@app.post("/api/scan/email", summary="Analyze an email for scams", tags=["Scanners"])
async def scan_email(payload: EmailPayload):
    return await analyze_email(payload)


@app.post("/api/scan/phone", summary="Score a phone number for fraud", tags=["Scanners"])
async def scan_phone(payload: PhonePayload):
    return await analyze_phone(payload)


@app.post("/api/scan/merchant", summary="Score a merchant", tags=["Scanners"])
async def scan_merchant(payload: MerchantPayload):
    return await analyze_merchant(payload)


@app.post("/api/scan/file", summary="Scan a file for malware", tags=["Scanners"])
async def scan_file(file: UploadFile = File(...)):
    contents = await file.read()
    if len(contents) > 25 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large (25 MB limit).")
    return await analyze_file(file.filename or "unknown", contents)


@app.post("/api/scan/social", summary="Analyze a social media profile", tags=["Scanners"])
async def scan_social(payload: SocialPayload):
    return await analyze_social(payload)


@app.post("/api/scan/sms", summary="Analyze an SMS message for scams", tags=["Scanners"])
async def scan_sms(payload: SMSPayload):
    return await analyze_sms(payload)


@app.post("/api/scan/qr", summary="Analyze a QR code URL", tags=["Scanners"])
async def scan_qr(payload: QRPayload):
    return await analyze_qr(payload)


@app.post("/api/scan/ip", summary="Check an IP address reputation", tags=["Scanners"])
async def scan_ip(payload: IPPayload):
    return await analyze_ip(payload)


@app.post("/api/scan/crypto", summary="Analyze a cryptocurrency address", tags=["Scanners"])
async def scan_crypto(payload: CryptoPayload):
    return await analyze_crypto(payload)


@app.post("/api/scan/bulk", summary="Bulk URL scan (up to 20)", tags=["Scanners"])
async def scan_bulk(payload: BulkURLPayload):
    if not payload.urls:
        raise HTTPException(status_code=400, detail="At least one URL required.")
    return await analyze_bulk_urls(payload.urls, use_ai=payload.use_ai)


# ═══════════════════════════════════════════════════════════════
# §§1-20  Enterprise Engine Endpoints
# ═══════════════════════════════════════════════════════════════

# ── §1 Event Correlation ──────────────────────────────────────

class CorrelationPayload(BaseModel):
    url_score:       float = 0.0
    biometrics_risk: float = 0.0
    device_trust:    float = 100.0
    threat_intel:    float = 0.0
    velocity:        float = 0.0
    session_anomaly: float = 0.0
    graph_risk:      float = 0.0
    dom_mutation:    float = 0.0
    browser_env:     float = 0.0
    ato_risk:        float = 0.0
    url:             str   = ""
    ip:              str   = ""
    session_id:      str   = ""
    user_id:         str   = ""

@app.post("/api/engine/correlate", summary="§1 Event correlation engine", tags=["Enterprise"])
def engine_correlate(p: CorrelationPayload):
    inp = CorrelationInput(
        url_score=p.url_score, biometrics_risk=p.biometrics_risk,
        device_trust=p.device_trust, threat_intel=p.threat_intel,
        velocity=p.velocity, session_anomaly=p.session_anomaly,
        graph_risk=p.graph_risk, dom_mutation=p.dom_mutation,
        browser_env=p.browser_env, ato_risk=p.ato_risk,
        url=p.url, ip=p.ip, session_id=p.session_id, user_id=p.user_id,
    )
    result = event_correlation_engine.correlate(inp)
    return result.to_dict()

@app.get("/api/engine/correlate/stats", tags=["Enterprise"])
def engine_correlate_stats():
    return event_correlation_engine.stats()


# ── §2 Window Analytics ───────────────────────────────────────

class WindowEventPayload(BaseModel):
    score:      float
    severity:   str = "safe"
    url:        str = ""
    ip:         str = ""
    session_id: str = ""
    kind:       str = "url"

@app.post("/api/engine/windows/record", summary="§2 Record event into sliding windows", tags=["Enterprise"])
def windows_record(p: WindowEventPayload):
    evt = WindowFraudEvent(
        score=p.score, severity=p.severity, url=p.url,
        ip=p.ip, session_id=p.session_id, kind=p.kind,
    )
    window_analytics.record(evt)
    return {"ok": True}

@app.get("/api/engine/windows/report", summary="§2 Sliding window analytics report", tags=["Enterprise"])
def windows_report():
    return window_analytics.report()

@app.get("/api/engine/windows/burst", tags=["Enterprise"])
def windows_burst():
    return window_analytics.detect_burst()


# ── §3 ATO Engine ─────────────────────────────────────────────

class ATOPayload(BaseModel):
    user_id:       str
    ip:            str   = ""
    lat:           Optional[float] = None
    lon:           Optional[float] = None
    device_fp:     str   = ""
    browser_fp:    str   = ""
    login_hour:    Optional[int]   = None
    typing_speed:  Optional[float] = None
    session_duration: Optional[float] = None
    otp_attempts:  int   = 0

@app.post("/api/engine/ato/assess", summary="§3 Account takeover assessment", tags=["Enterprise"])
def ato_assess(p: ATOPayload):
    inp = ATOInput(
        user_id=p.user_id, ip=p.ip, lat=p.lat, lon=p.lon,
        device_fp=p.device_fp, browser_fp=p.browser_fp,
        login_hour=p.login_hour, typing_speed=p.typing_speed,
        session_duration=p.session_duration, otp_attempts=p.otp_attempts,
    )
    result = ato_engine.assess(inp)
    return result.to_dict()

@app.get("/api/engine/ato/stats", tags=["Enterprise"])
def ato_stats():
    return ato_engine.stats()


# ── §4 Session Intelligence ───────────────────────────────────

class SessionEventPayload(BaseModel):
    session_id: str
    kind:       str   # EventKind value
    value:      Optional[float] = None
    meta:       Optional[dict]  = None

@app.post("/api/engine/session/event", summary="§4 Record session event", tags=["Enterprise"])
def session_event(p: SessionEventPayload):
    from session_intelligence import EventKind
    try:
        kind = EventKind(p.kind)
    except ValueError:
        kind = EventKind.PAGE_VIEW
    session_intelligence.record_event(p.session_id, kind, value=p.value, meta=p.meta)
    return {"ok": True}

@app.get("/api/engine/session/{session_id}/score", summary="§4 Session fraud score", tags=["Enterprise"])
def session_score(session_id: str):
    score = session_intelligence.score_session(session_id)
    return score.to_dict() if score else {"error": "session not found"}

@app.get("/api/engine/session/stats", tags=["Enterprise"])
def session_stats():
    return session_intelligence.stats()


# ── §5 Memory Engine ──────────────────────────────────────────

@app.get("/api/engine/memory/stats", summary="§5 Memory engine store sizes", tags=["Enterprise"])
def memory_stats():
    return memory_engine.stats()

@app.get("/api/engine/memory/events", summary="§5 Recent memory events", tags=["Enterprise"])
def memory_events(n: int = 50):
    return {"events": memory_engine.recent_events(n)}

class FlagDevicePayload(BaseModel):
    device_fp: str
    reason:    str
    score:     float = 80.0

@app.post("/api/engine/memory/flag-device", summary="§5/§18 Flag suspicious device", tags=["Enterprise"])
def memory_flag_device(p: FlagDevicePayload):
    memory_engine.flag_device(p.device_fp, p.reason, p.score)
    return {"ok": True, "device_fp": p.device_fp[:16] + "…"}

class AddDomainPayload(BaseModel):
    domain: str
    source: str = "analyst"

@app.post("/api/engine/memory/phishing-domain", summary="§18 Add phishing domain globally", tags=["Enterprise"])
def memory_add_phishing_domain(p: AddDomainPayload):
    memory_engine.add_phishing_domain(p.domain, p.source)
    return {"ok": True, "domain": p.domain}

@app.get("/api/engine/memory/phishing-domains", tags=["Enterprise"])
def memory_list_phishing_domains(limit: int = 200):
    return {"domains": memory_engine.list_phishing_domains(limit)}

@app.post("/api/engine/memory/prune", summary="§5 Prune expired memory entries", tags=["Enterprise"])
def memory_prune():
    return memory_engine.prune_all()


# ── §6 Campaign Detector ──────────────────────────────────────

class CampaignObservePayload(BaseModel):
    entity:    str
    score:     float
    domain:    str = ""
    ip:        str = ""
    device_fp: str = ""
    kind:      str = "url"

@app.post("/api/engine/campaigns/observe", summary="§6 Record entity for campaign detection", tags=["Enterprise"])
def campaigns_observe(p: CampaignObservePayload):
    alert = campaign_detector.observe(
        entity=p.entity, score=p.score, domain=p.domain,
        ip=p.ip, device_fp=p.device_fp, kind=p.kind,
    )
    return {"alert": alert, "ok": True}

@app.get("/api/engine/campaigns/active", summary="§6 Active campaigns", tags=["Enterprise"])
def campaigns_active():
    return {"campaigns": campaign_detector.active_campaigns()}

@app.get("/api/engine/campaigns/confirmed", summary="§6 Confirmed fraud campaigns", tags=["Enterprise"])
def campaigns_confirmed():
    return {"campaigns": campaign_detector.confirmed_campaigns()}

@app.get("/api/engine/campaigns/alerts", tags=["Enterprise"])
def campaigns_alerts(n: int = 20):
    return {"alerts": campaign_detector.recent_alerts(n)}

@app.get("/api/engine/campaigns/stats", tags=["Enterprise"])
def campaigns_stats():
    return campaign_detector.stats()


# ── §12 Drift Monitor ─────────────────────────────────────────

class DriftScorePayload(BaseModel):
    score: float

class DriftFeedbackPayload(BaseModel):
    predicted_score: float
    true_label:      int    # 1=fraud, 0=legit
    threshold:       float  = 50.0

class DriftBaselinePayload(BaseModel):
    tp: int; fp: int; tn: int; fn: int

@app.post("/api/engine/drift/record-score", summary="§12 Record score for drift monitoring", tags=["Enterprise"])
def drift_record_score(p: DriftScorePayload):
    drift_monitor.record_score(p.score)
    return {"ok": True}

@app.post("/api/engine/drift/feedback", summary="§12 Record analyst feedback label", tags=["Enterprise"])
def drift_feedback(p: DriftFeedbackPayload):
    drift_monitor.record_feedback(p.predicted_score, p.true_label, p.threshold)
    return {"ok": True}

@app.get("/api/engine/drift/analyze", summary="§12 Run drift analysis", tags=["Enterprise"])
def drift_analyze():
    return drift_monitor.analyze()

@app.post("/api/engine/drift/baseline", summary="§12 Set performance baseline after training", tags=["Enterprise"])
def drift_set_baseline(p: DriftBaselinePayload):
    drift_monitor.set_baseline_metrics(p.tp, p.fp, p.tn, p.fn)
    return {"ok": True}

@app.get("/api/engine/drift/events", tags=["Enterprise"])
def drift_events(n: int = 20):
    return {"events": drift_monitor.recent_drift_events(n)}

@app.get("/api/engine/drift/stats", tags=["Enterprise"])
def drift_stats():
    return drift_monitor.stats()


# ── §17 Confidence Fusion ─────────────────────────────────────

class FusionPayload(BaseModel):
    sources: list[dict]   # [{name, score, confidence, weight?}]

@app.post("/api/engine/fusion/fuse", summary="§17 Confidence fusion from multiple sources", tags=["Enterprise"])
def fusion_fuse(p: FusionPayload):
    sources = [
        SourceSignal(
            name       = s.get("name", f"src_{i}"),
            score      = float(s.get("score", 0)),
            confidence = float(s.get("confidence", 0.5)),
            weight     = float(s.get("weight", 1.0)),
        )
        for i, s in enumerate(p.sources)
    ]
    result = confidence_fusion.fuse(sources)
    return result.to_dict()


# ── §19 Signature Engine ──────────────────────────────────────

class SignatureIngestPayload(BaseModel):
    score:     float
    url:       str = ""
    domain:    str = ""
    ip:        str = ""
    device_fp: str = ""
    campaign:  str = ""

class ManualSigPayload(BaseModel):
    pattern:     str
    sig_type:    str
    description: str
    confidence:  float = 0.90
    source:      str   = "analyst"

@app.post("/api/engine/signatures/ingest", summary="§19 Ingest fraud event → auto-generate signatures", tags=["Enterprise"])
def signatures_ingest(p: SignatureIngestPayload):
    signature_engine.ingest_fraud_event(
        score=p.score, url=p.url, domain=p.domain,
        ip=p.ip, device_fp=p.device_fp, campaign=p.campaign,
    )
    return {"ok": True}

@app.post("/api/engine/signatures/manual", summary="§19 Add manual analyst signature", tags=["Enterprise"])
def signatures_manual(p: ManualSigPayload):
    sig_id = signature_engine.add_manual_signature(
        pattern=p.pattern, sig_type=p.sig_type,
        description=p.description, confidence=p.confidence, source=p.source,
    )
    return {"ok": True, "sig_id": sig_id}

class SigMatchPayload(BaseModel):
    url:       str = ""
    domain:    str = ""
    ip:        str = ""
    device_fp: str = ""

@app.post("/api/engine/signatures/match", summary="§19 Match artifacts against active signatures", tags=["Enterprise"])
def signatures_match(p: SigMatchPayload):
    matches = signature_engine.match(url=p.url, domain=p.domain, ip=p.ip, device_fp=p.device_fp)
    return {"matches": matches, "count": len(matches)}

@app.get("/api/engine/signatures/active", tags=["Enterprise"])
def signatures_active():
    return {"signatures": signature_engine.active_signatures()}

@app.get("/api/engine/signatures/all", tags=["Enterprise"])
def signatures_all():
    return {"signatures": signature_engine.all_signatures()}

@app.post("/api/engine/signatures/{sig_id}/false-positive", summary="§19 Report false positive", tags=["Enterprise"])
def signatures_fp(sig_id: str):
    signature_engine.report_false_positive(sig_id)
    return {"ok": True}

@app.get("/api/engine/signatures/stats", tags=["Enterprise"])
def signatures_stats():
    return signature_engine.stats()


# ── §20 Multi-Agent Orchestrator ─────────────────────────────

class OrchestratorPayload(BaseModel):
    url:          str  = ""
    domain:       str  = ""
    ip:           str  = ""
    device_fp:    str  = ""
    session_id:   str  = ""
    biometrics:   Optional[dict] = None
    session_score:Optional[dict] = None
    velocity:     Optional[dict] = None
    browser_env:  Optional[dict] = None
    page_signals: Optional[dict] = None

@app.post("/api/engine/orchestrate", summary="§20 Run all agents in parallel, return unified result", tags=["Enterprise"])
def engine_orchestrate(p: OrchestratorPayload):
    result = multi_agent_orchestrator.analyze(
        url=p.url, domain=p.domain, ip=p.ip, device_fp=p.device_fp,
        session_id=p.session_id, biometrics=p.biometrics,
        session_score=p.session_score, velocity=p.velocity,
        browser_env=p.browser_env, page_signals=p.page_signals,
    )
    return result.to_dict()

@app.get("/api/engine/orchestrate/stats", tags=["Enterprise"])
def orchestrate_stats():
    return multi_agent_orchestrator.stats()


# ── §15 Simulation Engine ─────────────────────────────────────

class SimulationPayload(BaseModel):
    scenario:        str
    seed:            int  = 42
    n_users:         Optional[int] = None
    n_requests:      Optional[int] = None
    n_attempts:      Optional[int] = None
    n_transactions:  Optional[int] = None
    n_victims:       Optional[int] = None
    n_cards:         Optional[int] = None

@app.post("/api/engine/simulate", summary="§15 Run a fraud simulation scenario", tags=["Enterprise"])
def engine_simulate(p: SimulationPayload):
    try:
        sc = ScenarioType(p.scenario)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Unknown scenario. Choose from: {[s.value for s in ScenarioType]}")

    kwargs = {}
    if p.n_users        is not None: kwargs["n_users"]        = p.n_users
    if p.n_requests     is not None: kwargs["n_requests"]     = p.n_requests
    if p.n_attempts     is not None: kwargs["n_attempts"]     = p.n_attempts
    if p.n_transactions is not None: kwargs["n_transactions"] = p.n_transactions
    if p.n_victims      is not None: kwargs["n_victims"]      = p.n_victims
    if p.n_cards        is not None: kwargs["n_cards"]        = p.n_cards

    run = simulation_engine.run(sc, seed=p.seed, **kwargs)
    return run.to_dict()

@app.post("/api/engine/simulate/all", summary="§15 Run all simulation scenarios", tags=["Enterprise"])
def engine_simulate_all(seed: int = 42):
    return simulation_engine.run_all(seed=seed)

@app.get("/api/engine/simulate/stats", tags=["Enterprise"])
def simulation_stats():
    return simulation_engine.stats()


# ── §18 Distributed Intelligence (combined view) ─────────────

@app.get("/api/engine/intelligence/summary", summary="§18 Cross-engine intelligence summary", tags=["Enterprise"])
def intelligence_summary():
    return {
        "memory":     memory_engine.stats(),
        "campaigns":  campaign_detector.stats(),
        "signatures": signature_engine.stats(),
        "drift":      drift_monitor.stats(),
        "windows":    window_analytics.report(),
        "agents":     multi_agent_orchestrator.stats(),
    }


# ── ML Model ─────────────────────────────────────────────────

@app.get("/api/ml/status", summary="ML model status and feature importance", tags=["Intelligence"])
def ml_status():
    return url_ml_model.status()


@app.post("/api/ml/retrain", summary="Retrain ML model on synthetic data", tags=["Intelligence"])
async def ml_retrain():
    """Retrain the URL Random Forest on a fresh synthetic dataset (runs in background thread)."""
    if not url_ml_model.is_ready and not _sklearn_available():
        raise HTTPException(status_code=503, detail="scikit-learn not installed.")
    loop = asyncio.get_event_loop()
    try:
        metrics = await loop.run_in_executor(None, url_ml_model.auto_train)
        return {"ok": True, "metrics": metrics}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/api/ml/predict", summary="Raw ML probability for a URL (no heuristics)", tags=["Intelligence"])
async def ml_predict(payload: UrlPayload):
    """Return the raw Random Forest probability score for a URL, bypassing all heuristics."""
    if not url_ml_model.is_ready:
        raise HTTPException(status_code=503, detail="ML model not loaded.")
    from ml_url_model import extract_features, FEATURE_NAMES
    prob, conf = url_ml_model.predict(payload.url)
    feats = extract_features(payload.url)
    return {
        "url": payload.url,
        "ml_probability": prob,
        "confidence": conf,
        "risk_level": "danger" if prob >= 65 else "caution" if prob >= 35 else "safe",
        "features": dict(zip(FEATURE_NAMES, feats)),
    }


def _sklearn_available() -> bool:
    import importlib.util
    return importlib.util.find_spec("sklearn") is not None


# ── Monitor ───────────────────────────────────────────────────

@app.get("/api/alerts", summary="List alerts with pagination and filtering", tags=["Monitor"])
def list_alerts(
    page:      int = 1,
    per_page:  int = 50,
    kind:      Optional[str] = None,
    level:     Optional[str] = None,
    min_score: Optional[int] = None,
    max_score: Optional[int] = None,
    search:    Optional[str] = None,
    start_ts:  Optional[float] = None,
    end_ts:    Optional[float] = None,
):
    """
    Paginated alert list from SQLite.

    - **page** / **per_page**: pagination (per_page max 200)
    - **kind**: filter by scan type (url, email, crypto, …)
    - **level**: filter by risk level (safe, caution, danger)
    - **min_score** / **max_score**: score range filter
    - **search**: substring match on target
    - **start_ts** / **end_ts**: Unix timestamp range
    """
    return get_alerts_paginated(
        page=page, per_page=per_page, kind=kind, level=level,
        min_score=min_score, max_score=max_score,
        search=search, start_ts=start_ts, end_ts=end_ts,
    )


@app.get("/api/alerts/{alert_id}", summary="Get a single alert by ID", tags=["Monitor"])
def get_alert(alert_id: str):
    alert = get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found.")
    return alert


@app.delete("/api/alerts/{alert_id}", summary="Delete a single alert", tags=["Monitor"])
def remove_alert(alert_id: str):
    if not delete_alert(alert_id):
        raise HTTPException(status_code=404, detail="Alert not found.")
    return {"ok": True, "deleted": alert_id}


@app.patch("/api/alerts/{alert_id}/notes", summary="Add or update analyst notes on an alert", tags=["Monitor"])
def set_alert_notes(alert_id: str, payload: NotesPayload):
    if not update_alert_notes(alert_id, payload.notes):
        raise HTTPException(status_code=404, detail="Alert not found.")
    return {"ok": True, "alert_id": alert_id, "notes": payload.notes}


@app.get("/api/stats", summary="Aggregate scan statistics", tags=["Monitor"])
def get_stats():
    return get_db_stats()


@app.get("/api/stats/trend", summary="6-hour scan trend", tags=["Monitor"])
def get_trend():
    return {"buckets": get_trend_from_db(6)}


@app.get("/api/analytics/distribution", summary="Risk-score distribution histogram", tags=["Monitor"])
def analytics_distribution(kind: Optional[str] = None):
    """
    Returns alert counts in 10-point risk-score buckets (0-9, 10-19, … 90-100).
    Optionally filtered by scan kind.

    Example response:
      [{"range": "80-89", "min": 80, "max": 89, "count": 42}, ...]
    """
    return {"distribution": get_score_distribution(kind=kind)}


@app.get("/api/analytics/top-targets", summary="Most-flagged targets", tags=["Monitor"])
def analytics_top_targets(
    kind:  Optional[str] = None,
    level: Optional[str] = None,
    limit: int = 10,
    hours: int = 24,
):
    """
    Top targets ranked by scan count in the last `hours` hours.
    Optionally filtered by kind (url, email, …) and risk level.

    Example response:
      {"hours": 24, "count": 5, "targets": [
        {"target": "http://paypa1-login.tk/...", "kind": "url",
         "scan_count": 14, "avg_score": 85.3, "max_score": 92,
         "danger_count": 12, "caution_count": 2, "last_seen": 1714700000}
      ]}
    """
    limit   = max(1, min(limit, 100))
    hours   = max(1, min(hours, 720))
    targets = get_top_targets(kind=kind, level=level, limit=limit, hours=hours)
    return {"hours": hours, "count": len(targets), "targets": targets}


@app.get("/api/analytics/timeline", summary="Per-kind scan counts over time", tags=["Monitor"])
def analytics_timeline(hours: int = 24, interval_min: int = 60):
    """
    Scan activity broken into equal time intervals, split by scan kind.
    Useful for a stacked-area or grouped-bar chart.

    - **hours**: lookback window (1–168)
    - **interval_min**: bucket size in minutes (5–1440)

    Example response:
      {"interval_minutes": 60, "hours": 24, "buckets": [
        {"label": "23h ago", "start_ts": 1714676400, "total": 3,
         "by_kind": {"url": 2, "email": 1}}, ...
      ]}
    """
    hours        = max(1, min(hours, 168))
    interval_min = max(5, min(interval_min, 1440))
    return get_kind_timeline(hours=hours, interval_min=interval_min)


@app.get("/api/ledger", summary="Return the chained audit ledger", tags=["Monitor"])
def list_ledger():
    return {"blocks": [asdict(b) for b in LEDGER], "length": len(LEDGER), "valid": verify_ledger()}


@app.get("/api/export", summary="Export alerts as CSV", tags=["Monitor"])
def export_alerts(kind: Optional[str] = None, level: Optional[str] = None, limit: int = 5000):
    """Export up to `limit` alerts as CSV (newest first). Optionally filter by kind/level."""
    result = get_alerts_paginated(page=1, per_page=min(limit, 5000), kind=kind, level=level)
    buf    = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["id", "kind", "target", "risk_score", "risk_level",
                     "timestamp", "ledger_hash", "notes", "reasons"])
    for a in result["alerts"]:
        reasons = a.get("reasons", [])
        if isinstance(reasons, list):
            reasons = " | ".join(reasons)
        writer.writerow([
            a.get("id"), a.get("kind"), a.get("target"),
            a.get("risk_score"), a.get("risk_level"),
            time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(a.get("timestamp", 0))),
            a.get("ledger_hash", ""),
            a.get("notes", ""),
            reasons,
        ])
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=fraud-x-alerts.csv"},
    )


# ── Admin ─────────────────────────────────────────────────────

@app.get("/api/graph", summary="Entity relationship subgraph", tags=["Intelligence"])
def get_graph(entity_type: str, entity_value: str, depth: int = 2):
    """Return the fraud entity graph for a given node (from SQLite)."""
    depth = max(1, min(depth, 3))
    return get_entity_graph(entity_type, entity_value, depth)


@app.get("/api/graph/memory", summary="In-memory entity graph", tags=["Intelligence"])
def get_graph_memory(entity_type: str, entity_value: str, depth: int = 2):
    """Return the in-memory fraud graph subgraph for a node."""
    depth = max(1, min(depth, 3))
    return fraud_graph.subgraph(entity_type, entity_value, depth)


@app.get("/api/graph/stats", summary="Graph statistics", tags=["Intelligence"])
def get_graph_stats():
    return fraud_graph.stats()


@app.get("/api/graph/clusters", summary="Fraud cluster / campaign detection", tags=["Intelligence"])
def get_graph_clusters(min_size: int = 2, min_fraud_nodes: int = 2):
    """
    Detect connected clusters of high-risk entities.
    Returns groups sorted by fraud_node_count descending.

    Example output:
      { "cluster_count": 2, "clusters": [
          { "size": 4, "fraud_node_count": 3, "avg_risk_score": 81.2,
            "total_fraud_hits": 9,
            "nodes": [
              { "id": "domain:malicious-site.xyz", "fraud_count": 4,
                "total_scans": 5, "fraud_rate": 0.8, "avg_score": 84.0 },
              ...
            ]
          }, ...
        ]
      }
    """
    min_size        = max(2, min(min_size, 20))
    min_fraud_nodes = max(1, min(min_fraud_nodes, 10))
    clusters = fraud_graph.detect_fraud_clusters(
        min_size=min_size, min_fraud_nodes=min_fraud_nodes
    )
    return {"cluster_count": len(clusters), "clusters": clusters}


@app.get("/api/graph/nodes/top", summary="Top high-risk nodes by influence", tags=["Intelligence"])
def get_top_nodes(top_n: int = 10):
    """
    Return nodes ranked by influence = PageRank * fraud_count * avg_score.
    Useful for identifying the most dangerous repeated-offender entities.

    Example output:
      { "count": 3, "nodes": [
          { "id": "domain:paypa1-login.tk", "fraud_count": 7, "total_scans": 8,
            "fraud_rate": 0.875, "avg_risk_score": 88.3,
            "pagerank": 0.000412, "influence_score": 7.294 },
          ...
        ]
      }
    """
    top_n = max(1, min(top_n, 50))
    nodes = fraud_graph.top_risk_nodes(top_n=top_n)
    return {"count": len(nodes), "nodes": nodes}


@app.get("/api/behavior", summary="Behavioral analysis statistics", tags=["Intelligence"])
def get_behavior():
    """Return velocity stats and per-kind risk baselines."""
    velocity = behavior_engine.velocity_stats()
    baselines = {
        kind: behavior_engine.kind_baseline(kind)
        for kind in ["url", "email", "phone", "sms", "file", "merchant", "social", "qr", "ip", "crypto"]
    }
    return {"velocity": velocity, "baselines": baselines}


@app.get("/api/behavior/campaigns", summary="Active fraud campaigns", tags=["Intelligence"])
def get_campaigns(active_only: bool = True):
    """
    Return entities that have been promoted to active fraud campaigns.

    A campaign is declared when:
      - Same target scanned ≥10 times total (repeat_scan_N trigger), OR
      - Same target scored ≥65 on ≥5 separate scans (high_risk_hits_N trigger), OR
      - Same domain reached via ≥3 distinct scan types (domain_sweep trigger)

    Example response:
      { "count": 2, "campaigns": [
          { "kind": "url", "target": "http://paypa1-login.tk/...",
            "trigger": "repeat_scan_12", "scan_count": 12,
            "fraud_count": 10, "avg_score": 84.5, "is_active": true,
            "alert_ids": ["abc123", ...] },
          { "kind": "domain_sweep", "target": "paypa1-login.tk",
            "trigger": "domain_sweep_3_kinds",
            "kinds": ["url", "email", "sms"], ... }
        ]
      }
    """
    campaigns = behavior_engine.get_campaigns(active_only=active_only)
    return {"count": len(campaigns), "campaigns": campaigns}


@app.post("/api/behavior/campaigns/{campaign_id}/resolve",
          summary="Mark a campaign as resolved", tags=["Intelligence"])
def resolve_campaign(campaign_id: str):
    """Mark a detected fraud campaign as resolved/handled."""
    ok = behavior_engine.mark_campaign_resolved(campaign_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Campaign not found.")
    return {"ok": True, "campaign_id": campaign_id}


@app.get("/api/behavior/hot", summary="Most-scanned targets", tags=["Intelligence"])
def get_hot_targets(kind: Optional[str] = None, top_n: int = 10, window_min: int = 60):
    """
    Return the most frequently scanned targets in the last `window_min` minutes.

    Example response:
      { "window_minutes": 60, "count": 3, "targets": [
          { "kind": "url", "target": "http://paypa1-login.tk/verify",
            "scans_in_window": 14, "total_scans": 22,
            "fraud_hits": 12, "avg_score": 85.1, "is_campaign": true },
          ...
        ]
      }
    """
    top_n      = max(1, min(top_n, 50))
    window_min = max(1, min(window_min, 1440))
    targets    = behavior_engine.get_hot_targets(
        kind=kind, top_n=top_n, window_sec=window_min * 60
    )
    return {"window_minutes": window_min, "count": len(targets), "targets": targets}


@app.get("/api/behavior/domains", summary="Domain sweep / cross-type activity", tags=["Intelligence"])
def get_domain_sweeps():
    """
    Return domains that have appeared in multiple scan types (URL + email + SMS etc.).
    Domains reaching ≥3 kinds are flagged as 'is_sweep': true.
    """
    sweeps = behavior_engine.get_domain_sweep_summary()
    return {"count": len(sweeps), "domains": sweeps}


@app.get("/api/scoring/thresholds", summary="Dynamic threshold state", tags=["Intelligence"])
def get_scoring_thresholds():
    """
    Returns current danger/caution thresholds for every scan type,
    including how much each has drifted from the static base and why.

    Thresholds adapt after ≥20 scans per kind. Before that they stay at base.

    Example response:
      { "url":   { "danger_threshold": 62, "caution_threshold": 29,
                   "base_danger": 65, "drift": -3,
                   "observed_fraud_rate_pct": 24.1,
                   "expected_fraud_rate_pct": 18.0,
                   "scan_count": 47, "adapted": true },
        "crypto": { "danger_threshold": 55, ... "adapted": false } }
    """
    return scoring_engine.thresholds_summary()


@app.get("/api/scoring/session", summary="Active cross-entity session context", tags=["Intelligence"])
def get_scoring_session():
    """
    Returns what's in the current 10-minute scan session window.
    When multiple scan kinds are all high-risk, every subsequent scan
    receives a context-aware corroboration bonus.

    Example response:
      { "window_seconds": 600, "total_in_window": 8,
        "scans_by_kind": {"url": 5, "crypto": 2, "sms": 1},
        "high_risk_by_kind": {"url": 4, "crypto": 2, "sms": 1},
        "multi_vector_active": true,
        "active_kinds": ["crypto", "sms", "url"] }
    """
    return scoring_engine.session_summary()


@app.get("/api/history", summary="Scan history for a target", tags=["Intelligence"])
def get_history(target: str, kind: Optional[str] = None):
    """Return past scan results for a specific target from SQLite."""
    rows = get_target_history(target, kind)
    for r in rows:
        try:
            r["reasons"] = json.loads(r["reasons"])
        except Exception:
            pass
    return {"target": target, "count": len(rows), "history": rows}


class ClearPayload(BaseModel):
    secret: str = ""

_CLEAR_KEY: str = os.environ.get("FRAUD_X_CLEAR_KEY", "")

@app.post("/api/alerts/clear", summary="Reset demo state", tags=["Admin"])
def clear_alerts(body: ClearPayload = ClearPayload()):
    if _CLEAR_KEY and body.secret != _CLEAR_KEY:
        raise HTTPException(status_code=403, detail="Invalid or missing clear secret.")
    ALERTS.clear()
    LEDGER.clear()
    deleted = clear_all_alerts()
    return {"ok": True, "message": f"Cleared {deleted} alerts from DB and reset in-memory state."}


@app.websocket("/ws/alerts")
async def websocket_alerts(ws: WebSocket):
    """Real-time alert stream. Sends every new alert as JSON the moment it is recorded."""
    await ws_manager.connect(ws)
    try:
        while True:
            await ws.receive_text()   # keepalive ping from client
    except WebSocketDisconnect:
        ws_manager.disconnect(ws)


@app.get("/api/health", summary="Service health probe", tags=["Admin"])
def health():
    graph_stats = fraud_graph.stats()
    velocity    = behavior_engine.velocity_stats()
    return {
        "status": "ok", "version": "3.0.0",
        "alerts": len(ALERTS), "ledger_len": len(LEDGER),
        "ledger_valid": verify_ledger(), "ai_model": GEMINI_MODEL,
        "scanners": ["url", "email", "phone", "sms", "file", "merchant", "social", "qr", "ip", "crypto", "bulk"],
        "engines": {
            "ml":       "active",
            "graph":    graph_stats,
            "behavior": {"last_hour": velocity["last_hour"], "last_5min": velocity["last_5min"]},
            "database": "sqlite",
        },
    }


# ═══════════════════════════════════════════════════════════════
# Authentication endpoints
# ═══════════════════════════════════════════════════════════════

def _get_token(request) -> Optional[str]:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return request.cookies.get("fraudx_token")


def _require_auth(request):
    from fastapi import Request
    token = _get_token(request)
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required")
    payload = decode_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    if is_session_revoked(payload.get("jti", "")):
        raise HTTPException(status_code=401, detail="Session revoked")
    user = get_user_by_id(payload["sub"])
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


class LoginPayload(BaseModel):
    email:    str
    password: str

class MFAVerifyPayload(BaseModel):
    challenge_id: str
    code:         int

class RegisterPayload(BaseModel):
    email:    str
    name:     str
    password: str
    role:     str = "analyst"

class UpdateRolePayload(BaseModel):
    role: str

class MFASetupPayload(BaseModel):
    code: int


@app.post("/api/auth/login", summary="Login — returns JWT or MFA challenge", tags=["Auth"])
async def auth_login(p: LoginPayload, request: "Request"):
    from fastapi import Request
    user_row = verify_password(p.email.lower().strip(), p.password)
    if not user_row:
        audit(None, "login_failed", f"email={p.email}", request.client.host if request.client else "")
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user_row["is_active"]:
        raise HTTPException(status_code=403, detail="Account deactivated")

    # MFA required?
    if user_row["mfa_enabled"]:
        challenge_id = create_mfa_challenge(user_row["id"], user_row)
        return {"mfa_required": True, "challenge_id": challenge_id}

    update_last_login(user_row["id"])
    access  = create_access_token(user_row)
    refresh, _ = create_refresh_token(user_row["id"])
    audit(user_row["id"], "login_success", f"email={p.email}", request.client.host if request.client else "")
    return {
        "access_token":  access,
        "refresh_token": refresh,
        "token_type":    "bearer",
        "user": {
            "id": user_row["id"], "email": user_row["email"],
            "name": user_row["name"], "role": user_row["role"],
            "avatar_color": user_row["avatar_color"],
        },
    }


@app.post("/api/auth/register", summary="Self-service account registration", tags=["Auth"])
def auth_register(p: RegisterPayload):
    try:
        user = create_user(p.email.lower().strip(), p.name.strip(), p.password, role="analyst")
        return {"message": "Account created successfully", "user_id": user.user_id}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="An account with this email already exists")
    except (ValueError, Exception) as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/auth/mfa/verify", summary="Verify MFA TOTP code", tags=["Auth"])
async def auth_mfa_verify(p: MFAVerifyPayload, request: "Request"):
    from fastapi import Request
    user_row = resolve_mfa_challenge(p.challenge_id, p.code)
    if not user_row:
        raise HTTPException(status_code=401, detail="Invalid MFA code or challenge expired")
    update_last_login(user_row["id"])
    access  = create_access_token(user_row)
    refresh, _ = create_refresh_token(user_row["id"])
    audit(user_row["id"], "mfa_verify_success", "", request.client.host if request.client else "")
    return {
        "access_token":  access,
        "refresh_token": refresh,
        "token_type":    "bearer",
        "user": {
            "id": user_row["id"], "email": user_row["email"],
            "name": user_row["name"], "role": user_row["role"],
            "avatar_color": user_row["avatar_color"],
        },
    }


@app.post("/api/auth/logout", summary="Revoke current session", tags=["Auth"])
async def auth_logout(request: "Request"):
    from fastapi import Request
    token = _get_token(request)
    if token:
        payload = decode_token(token)
        if payload:
            revoke_session(payload.get("jti", ""))
            audit(payload.get("sub"), "logout", "")
    return {"ok": True}


@app.get("/api/auth/me", summary="Get current user profile", tags=["Auth"])
async def auth_me(request: "Request"):
    from fastapi import Request
    user = _require_auth(request)
    return user.to_dict()


@app.post("/api/auth/mfa/setup", summary="Enable MFA — returns TOTP secret", tags=["Auth"])
async def auth_mfa_setup(request: "Request"):
    from fastapi import Request
    user = _require_auth(request)
    secret = generate_mfa_secret()
    return {
        "secret":    secret,
        "issuer":    "FRAUD-X",
        "account":   user.email,
        "qr_label":  f"FRAUD-X:{user.email}",
    }


@app.post("/api/auth/mfa/confirm", summary="Confirm MFA setup with first code", tags=["Auth"])
async def auth_mfa_confirm(p: MFASetupPayload, request: "Request"):
    from fastapi import Request
    user   = _require_auth(request)
    secret = request.headers.get("X-MFA-Secret", "")
    if not secret or not verify_totp(secret, p.code):
        raise HTTPException(status_code=400, detail="Invalid code — TOTP not confirmed")
    enable_mfa(user.id, secret)
    audit(user.id, "mfa_enabled", "")
    return {"ok": True, "mfa_enabled": True}


# ── User management (admin only) ──────────────────────────────

@app.get("/api/admin/users", summary="List all users", tags=["Admin"])
async def admin_list_users(request: "Request"):
    from fastapi import Request
    user = _require_auth(request)
    if not user.has_permission("users:manage"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    return {"users": list_users()}


@app.post("/api/admin/users", summary="Create new user", tags=["Admin"])
async def admin_create_user(p: RegisterPayload, request: "Request"):
    from fastapi import Request
    user = _require_auth(request)
    if not user.has_permission("users:manage"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    try:
        new_user = create_user(p.email.lower().strip(), p.name, p.password, p.role)
        audit(user.id, "user_created", f"email={p.email},role={p.role}")
        return new_user.to_dict()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.patch("/api/admin/users/{uid}/role", summary="Update user role", tags=["Admin"])
async def admin_update_role(uid: str, p: UpdateRolePayload, request: "Request"):
    from fastapi import Request
    actor = _require_auth(request)
    if not actor.has_permission("users:manage"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    try:
        update_user_role(uid, p.role)
        audit(actor.id, "role_updated", f"uid={uid},role={p.role}")
        return {"ok": True}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.delete("/api/admin/users/{uid}", summary="Deactivate user", tags=["Admin"])
async def admin_deactivate_user(uid: str, request: "Request"):
    from fastapi import Request
    actor = _require_auth(request)
    if not actor.has_permission("users:manage"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    deactivate_user(uid)
    audit(actor.id, "user_deactivated", f"uid={uid}")
    return {"ok": True}


@app.get("/api/admin/audit", summary="Audit log", tags=["Admin"])
async def admin_audit(request: "Request", limit: int = 100):
    from fastapi import Request
    actor = _require_auth(request)
    if not actor.has_permission("users:manage"):
        raise HTTPException(status_code=403, detail="Insufficient permissions")
    return {"log": get_audit_log(limit)}


# ═══════════════════════════════════════════════════════════════
# FRAUD-X Cyber Intelligence Engine — AI Assistant
# (all provider branding hidden; appears as native FRAUD-X AI)
# ═══════════════════════════════════════════════════════════════

_FRAUDX_AI_SYSTEM = """You are the FRAUD-X Cyber Intelligence Engine — an enterprise-grade AI \
security analyst embedded in the FRAUD-X fraud detection platform.

Your role:
- Analyze fraud signals, risk scores, and behavioral anomalies with expert precision
- Explain phishing indicators, suspicious payment pages, and account takeover patterns
- Help security analysts investigate fraud cases and interpret AI model outputs
- Provide actionable recommendations to protect users from financial fraud
- Generate clear fraud investigation summaries and threat assessments
- Explain SHAP feature importance, model confidence, and detection signals

Persona rules:
- You are FRAUD-X AI — never reference or hint at any external AI provider or model name
- Speak as a native FRAUD-X security expert
- Keep responses concise and security-focused (3-5 sentences for explanations)
- Use professional cybersecurity terminology
- Format structured outputs (risk summaries, investigation notes) clearly
- If asked who you are: "I am the FRAUD-X Cyber Intelligence Engine, your integrated AI security analyst"

Capabilities you have:
- Real-time fraud score interpretation
- Phishing URL pattern explanation
- Behavioral biometric anomaly analysis
- Account takeover risk assessment
- Payment gateway legitimacy analysis
- Fraud ring relationship explanation
- Threat intelligence interpretation
- Investigation workflow guidance
- Security awareness education"""


class ChatPayload(BaseModel):
    message:  str
    context:  Optional[dict] = None
    history:  Optional[list] = None   # [{role, content}] for multi-turn


@app.post("/api/chat", summary="FRAUD-X AI security assistant", tags=["AI"])
async def api_chat(p: ChatPayload):
    api_key = os.environ.get("GEMINI_API_KEY", "")
    if not api_key:
        return {"reply": "FRAUD-X AI is initializing. Please ensure the system is fully configured.", "source": "fraudx-ai"}

    ctx      = p.context or {}
    ctx_info = ""

    if ctx.get("url"):
        ctx_info += f"\n[Current URL under analysis: {ctx['url']}]"
    if ctx.get("risk"):
        r = ctx["risk"]
        ctx_info += (f"\n[FRAUD-X Risk Assessment: Level={r.get('risk_level','unknown')}, "
                     f"Score={r.get('risk_score','?')}/100, "
                     f"Primary Threat={r.get('primary_threat','none')}]")
    if ctx.get("payment"):
        pay = ctx["payment"]
        ctx_info += (f"\n[Payment Page Analysis: Level={pay.get('risk_level','unknown')}, "
                     f"Score={pay.get('risk_score','?')}/100, "
                     f"Trusted={pay.get('is_trusted_gateway',False)}]")
    if ctx.get("case"):
        case = ctx["case"]
        ctx_info += f"\n[Active Case: {case.get('id','?')} — {case.get('title','?')} — Status: {case.get('status','?')}]"
    if ctx.get("transaction"):
        t = ctx["transaction"]
        ctx_info += f"\n[Transaction: Score={t.get('score','?')}, URL={t.get('url','?')}, IP={t.get('ip','?')}]"

    system = _FRAUDX_AI_SYSTEM + (f"\n\nCurrent analysis context:{ctx_info}" if ctx_info else "")

    # Build conversation history for multi-turn
    contents = []
    for msg in (p.history or [])[-6:]:
        role = "user" if msg.get("role") == "user" else "model"
        contents.append({"role": role, "parts": [{"text": msg.get("content", "")}]})
    contents.append({"role": "user", "parts": [{"text": p.message}]})

    try:
        async with httpx.AsyncClient(timeout=25.0) as client:
            resp = await client.post(
                f"{GEMINI_API_URL}?key={api_key}",
                headers={"Content-Type": "application/json"},
                json={
                    "systemInstruction": {"parts": [{"text": system}]},
                    "contents":          contents,
                    "generationConfig":  {"maxOutputTokens": 512, "temperature": 0.25},
                },
            )
        if resp.status_code != 200:
            return {"reply": "FRAUD-X AI is temporarily offline. Our team is investigating.", "source": "fraudx-ai"}

        data  = resp.json()
        reply = data["candidates"][0]["content"]["parts"][0]["text"].strip()
        return {"reply": reply, "source": "fraudx-ai"}

    except Exception:
        return {"reply": "FRAUD-X AI encountered an analysis error. Please retry.", "source": "fraudx-ai"}


# ═══════════════════════════════════════════════════════════════
# §13/§18 Offline phishing cache for browser extension
# ═══════════════════════════════════════════════════════════════

# Known phishing/fraud domains compiled from multiple threat intel sources.
# Extension fetches this hourly for offline detection.
_PHISHING_DOMAINS: list[str] = [
    # Common typosquatting targets (examples — expand with live feeds)
    "paypa1.com", "paypol.com", "paypa-l.com",
    "amazon-security.com", "amaz0n.com", "amazonn.com",
    "netflix-billing.com", "netfliix.com",
    "apple-id-verify.com", "appleid-support.com",
    "google-security-alert.com",
    "bank0famerica.com", "bankofamerica-secure.com",
    "citibank-verify.com", "wellsfarg0.com",
    "steamcommunity-trade.com", "steam-login.net",
    "coinbase-support.net", "binance-verify.com",
    "upi-payment-verify.in", "paytm-kyc-update.com",
    "phonepe-offer.in", "gpay-cashback.com",
    "razorpay-verify.in", "payu-secure.com",
    "hdfc-netbanking-update.com", "sbi-account-verify.in",
    "icici-secure-login.com", "axis-bank-verify.in",
]


@app.get("/api/phishing/cache", summary="Offline phishing domain cache for extension", tags=["Extension"])
def phishing_cache():
    """Returns known phishing domains for extension offline detection.
    The extension fetches this list hourly and caches it locally."""
    # Also include any domains from recent danger alerts
    dynamic = []
    try:
        for alert in list(ALERTS)[-200:]:
            if alert.get("risk_level") == "danger" and alert.get("url"):
                try:
                    h = urlparse(alert["url"]).hostname
                    if h and h not in _PHISHING_DOMAINS:
                        dynamic.append(h)
                except Exception:
                    pass
    except Exception:
        pass

    all_domains = list(set(_PHISHING_DOMAINS + dynamic))
    return {
        "domains": all_domains,
        "count":   len(all_domains),
        "source":  "fraudx-threat-intel",
        "updated": time.time(),
    }



# ═══════════════════════════════════════════════════════════════
# ENTERPRISE UPGRADE — Real-Time Streaming & Multi-Channel WS
# ═══════════════════════════════════════════════════════════════

import random
import string
import platform
import psutil  # optional — gracefully degraded

# ── Per-channel WebSocket managers ────────────────────────────

class _ChannelWSManager:
    """Lightweight broadcast manager for a named channel."""

    def __init__(self, channel: str) -> None:
        self.channel = channel
        self._sockets: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._sockets.append(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self._sockets = [s for s in self._sockets if s is not ws]

    async def broadcast(self, data: dict) -> None:
        dead: list[WebSocket] = []
        payload = {**data, "_channel": self.channel}
        for ws in self._sockets:
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)

    @property
    def count(self) -> int:
        return len(self._sockets)


ws_transactions = _ChannelWSManager("transactions")
ws_system       = _ChannelWSManager("system")
ws_risk         = _ChannelWSManager("risk")
ws_activity     = _ChannelWSManager("activity")


# ── Live transaction stream generator ─────────────────────────

_MERCHANTS = [
    "Amazon Pay", "Razorpay", "Stripe", "PayU India", "HDFC NetBanking",
    "SBI Online", "Paytm Gateway", "Axis Pay", "ICICI iPay", "PhonePe",
    "GPay Merchant", "Mobikwik", "BharatPe", "Cashfree", "Instamojo",
    "Unknown Merchant", "Foreign Gateway Ltd", "CryptoMerchant Pro",
    "QuickPay India", "SecurePay Solutions",
]

_COUNTRIES = [
    ("IN", "India", "safe"), ("US", "United States", "safe"),
    ("GB", "United Kingdom", "safe"), ("SG", "Singapore", "safe"),
    ("RU", "Russia", "danger"), ("NG", "Nigeria", "danger"),
    ("CN", "China", "caution"), ("PK", "Pakistan", "caution"),
    ("UA", "Ukraine", "caution"), ("KP", "North Korea", "danger"),
    ("DE", "Germany", "safe"), ("AU", "Australia", "safe"),
    ("BR", "Brazil", "caution"), ("IR", "Iran", "danger"),
]

_DEVICES = [
    "Chrome/Windows", "Safari/iOS", "Chrome/Android", "Firefox/Linux",
    "Unknown Device", "HeadlessChrome", "curl/7.x", "Python-requests",
    "Samsung Browser", "Edge/Windows",
]

_PAYMENT_METHODS = [
    "UPI", "Net Banking", "Debit Card", "Credit Card",
    "Wallet", "NEFT", "RTGS", "Crypto", "QR Code",
]

_BLOCKED_REASONS = [
    "Foreign IP + unknown device",
    "Velocity burst: 12 tx in 60s",
    "High-risk country + VPN detected",
    "Impossible travel: 3800km in 4min",
    "Bot pattern: keystroke velocity 0",
    "Known phishing domain in referrer",
    "Card BIN mismatch with billing country",
    "Multiple failed OTPs before payment",
]

_txn_counter = [10000]


def _generate_live_transaction() -> dict:
    """Generate a realistic synthetic transaction for the live stream."""
    _txn_counter[0] += 1
    txn_id = _txn_counter[0]

    country_code, country_name, country_risk = random.choice(_COUNTRIES)
    merchant = random.choice(_MERCHANTS)
    device = random.choice(_DEVICES)
    payment = random.choice(_PAYMENT_METHODS)

    # Weight risk by merchant and country
    suspicious_merchant = any(w in merchant for w in ["Unknown", "Foreign", "Crypto"])
    suspicious_device   = any(w in device   for w in ["HeadlessChrome", "curl", "Python"])

    amount = round(random.uniform(10, 150000), 2)
    login_attempts = random.choices([1, 1, 1, 2, 3, 5, 8], weights=[50,20,10,8,6,4,2])[0]

    # Derive a realistic score
    base_score = 10
    if country_risk == "danger":   base_score += 45
    elif country_risk == "caution": base_score += 20
    if suspicious_merchant:         base_score += 25
    if suspicious_device:           base_score += 30
    if login_attempts >= 3:         base_score += 15
    if amount > 50000:              base_score += 10
    base_score = min(98, base_score + random.randint(-10, 15))
    base_score = max(2, base_score)

    if base_score >= 75:
        status = "BLOCKED"
        reason = random.choice(_BLOCKED_REASONS)
    elif base_score >= 50:
        status = "DANGER"
        reason = f"Risk score {base_score} — flagged for review"
    elif base_score >= 25:
        status = "CAUTION"
        reason = f"Moderate signals — monitoring"
    else:
        status = "SAFE"
        reason = "All checks passed"

    # Fake IP
    ip = ".".join(str(random.randint(1, 254)) for _ in range(4))

    behavioral_score = round(random.uniform(5, 95), 1)

    return {
        "txn_id":         f"TXN#{txn_id:05d}",
        "amount":         amount,
        "currency":       "INR" if country_code == "IN" else "USD",
        "merchant":       merchant,
        "country":        country_name,
        "country_code":   country_code,
        "device":         device,
        "ip":             ip,
        "payment_method": payment,
        "timestamp":      time.time(),
        "login_attempts": login_attempts,
        "behavioral_score": behavioral_score,
        "risk_score":     base_score,
        "status":         status,
        "reason":         reason,
        "blocked":        status == "BLOCKED",
    }


async def _live_transaction_loop() -> None:
    """Background task: emit a new transaction every 1-3 seconds."""
    while True:
        try:
            txn = _generate_live_transaction()
            # Broadcast to /ws/transactions
            await ws_transactions.broadcast(txn)

            # Also broadcast high-risk ones as alerts to /ws/alerts
            if txn["status"] in ("DANGER", "BLOCKED"):
                alert_payload = {
                    "type":      "live_txn_alert",
                    "severity":  "critical" if txn["status"] == "BLOCKED" else "danger",
                    "txn_id":    txn["txn_id"],
                    "amount":    txn["amount"],
                    "merchant":  txn["merchant"],
                    "country":   txn["country"],
                    "reason":    txn["reason"],
                    "timestamp": txn["timestamp"],
                }
                await ws_manager.broadcast(alert_payload)

        except Exception:
            pass

        await asyncio.sleep(random.uniform(1.0, 3.0))


async def _system_metrics_loop() -> None:
    """Background task: emit system metrics every 5 seconds."""
    while True:
        try:
            metrics = _get_system_metrics()
            await ws_system.broadcast(metrics)
        except Exception:
            pass
        await asyncio.sleep(5.0)


async def _heartbeat_loop() -> None:
    """Background task: send heartbeat pings every 10 seconds."""
    while True:
        await asyncio.sleep(10.0)
        ts = time.time()
        ping = {"type": "heartbeat", "ts": ts}
        for mgr in [ws_transactions, ws_system, ws_risk, ws_activity, ws_manager]:
            try:
                await mgr.broadcast(ping)
            except Exception:
                pass


# ── System metrics helper ──────────────────────────────────────

def _get_system_metrics() -> dict:
    metrics: dict = {
        "timestamp":      time.time(),
        "alerts_total":   len(ALERTS),
        "ledger_len":     len(LEDGER),
        "ledger_valid":   verify_ledger(),
        "ws_clients": {
            "alerts":       ws_manager.count if hasattr(ws_manager, "count") else len(ws_manager._sockets),
            "transactions": ws_transactions.count,
            "system":       ws_system.count,
            "risk":         ws_risk.count,
            "activity":     ws_activity.count,
        },
        "stream_txn_counter": _txn_counter[0],
    }
    try:
        metrics["cpu_pct"]    = psutil.cpu_percent(interval=None)
        metrics["mem_pct"]    = psutil.virtual_memory().percent
        metrics["disk_pct"]   = psutil.disk_usage("/").percent
    except Exception:
        metrics["cpu_pct"]    = 0
        metrics["mem_pct"]    = 0
        metrics["disk_pct"]   = 0

    return metrics


# ── Start background tasks on app startup ─────────────────────

_bg_tasks: list = []


@app.on_event("startup")
async def _start_enterprise_background_tasks():
    _bg_tasks.append(asyncio.create_task(_live_transaction_loop()))
    _bg_tasks.append(asyncio.create_task(_system_metrics_loop()))
    _bg_tasks.append(asyncio.create_task(_heartbeat_loop()))


@app.on_event("shutdown")
async def _stop_enterprise_background_tasks():
    for t in _bg_tasks:
        t.cancel()
    await asyncio.gather(*_bg_tasks, return_exceptions=True)


# ── New WebSocket endpoints ────────────────────────────────────

@app.websocket("/ws/transactions")
async def websocket_transactions(ws: WebSocket):
    """Real-time live transaction stream — emits every 1-3 seconds."""
    await ws_transactions.connect(ws)
    try:
        while True:
            data = await ws.receive_text()
            if data == "ping":
                await ws.send_json({"type": "pong", "ts": time.time()})
    except WebSocketDisconnect:
        ws_transactions.disconnect(ws)


@app.websocket("/ws/system")
async def websocket_system(ws: WebSocket):
    """Real-time system health metrics — emits every 5 seconds."""
    await ws_system.connect(ws)
    try:
        # Send current metrics immediately on connect
        await ws.send_json(_get_system_metrics())
        while True:
            data = await ws.receive_text()
            if data == "ping":
                await ws.send_json({"type": "pong", "ts": time.time()})
    except WebSocketDisconnect:
        ws_system.disconnect(ws)


@app.websocket("/ws/risk")
async def websocket_risk(ws: WebSocket):
    """Real-time risk score feed — receives scored events via POST /api/ws/risk/publish."""
    await ws_risk.connect(ws)
    try:
        while True:
            data = await ws.receive_text()
            if data == "ping":
                await ws.send_json({"type": "pong", "ts": time.time()})
    except WebSocketDisconnect:
        ws_risk.disconnect(ws)


@app.websocket("/ws/activity")
async def websocket_activity(ws: WebSocket):
    """Real-time analyst activity feed — IDS events, logins, system actions."""
    await ws_activity.connect(ws)
    try:
        while True:
            data = await ws.receive_text()
            if data == "ping":
                await ws.send_json({"type": "pong", "ts": time.time()})
    except WebSocketDisconnect:
        ws_activity.disconnect(ws)


# ── New REST endpoints ─────────────────────────────────────────

@app.get("/api/stream/transactions/latest", summary="Latest live transactions", tags=["Stream"])
def stream_latest(n: int = 20):
    """Return the last N synthetic live transactions (no WebSocket needed)."""
    n = max(1, min(n, 100))
    txns = [_generate_live_transaction() for _ in range(n)]
    return {"count": len(txns), "transactions": txns}


@app.get("/api/system/metrics", summary="Current system health metrics", tags=["System"])
def system_metrics():
    """Return live system metrics: CPU, memory, disk, WS client counts, ledger state."""
    return _get_system_metrics()


class SimTriggerPayload(BaseModel):
    scenario:   str
    seed:       int  = 0
    broadcast:  bool = True   # if True, push events to /ws/transactions


@app.post("/api/simulate/trigger", summary="Trigger fraud simulation + broadcast to WS", tags=["Stream"])
async def simulate_trigger(p: SimTriggerPayload):
    """
    Run a simulation scenario and:
    - return the summary
    - broadcast each event as a live transaction to /ws/transactions
    - push high-severity events as alerts to /ws/alerts
    """
    try:
        sc = ScenarioType(p.scenario)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown scenario. Valid: {[s.value for s in ScenarioType]}"
        )

    seed = p.seed or int(time.time()) % 100000
    run  = simulation_engine.run(sc, seed=seed)
    summary = run.to_dict()

    if p.broadcast:
        # Push each simulated event as a live transaction over WS
        async def _push():
            for evt in run.events[:50]:   # cap at 50 to avoid flooding
                txn = {
                    "txn_id":         f"SIM#{evt.get('session_id','')[:8]}",
                    "amount":         round(random.uniform(500, 95000), 2),
                    "currency":       "INR",
                    "merchant":       evt.get("url", "Simulated Merchant")[:40],
                    "country":        "Unknown",
                    "device":         "Simulated Device",
                    "ip":             evt.get("ip", "0.0.0.0"),
                    "payment_method": "Simulation",
                    "timestamp":      evt.get("ts", time.time()),
                    "login_attempts": random.randint(1, 6),
                    "behavioral_score": round(evt.get("score", 50), 1),
                    "risk_score":     int(evt.get("score", 50)),
                    "status":         evt.get("severity", "safe").upper(),
                    "reason":         f"[SIM:{sc.value}] {evt.get('url','')[:60]}",
                    "blocked":        evt.get("severity", "") in ("critical", "high"),
                    "_sim":           True,
                    "_scenario":      sc.value,
                }
                await ws_transactions.broadcast(txn)
                if txn["risk_score"] >= 65:
                    await ws_manager.broadcast({
                        "type":     "sim_alert",
                        "scenario": sc.value,
                        "severity": "critical" if txn["risk_score"] >= 80 else "danger",
                        **txn,
                    })
                await asyncio.sleep(0.05)

        asyncio.create_task(_push())

    return {"ok": True, "scenario": sc.value, "seed": seed, "summary": summary}


@app.get("/api/geolocation/hotspots", summary="Fraud geolocation hotspot data", tags=["Intel"])
def geolocation_hotspots():
    """
    Returns country-level fraud risk data for the live map.
    Combines static risk ratings with dynamic alert counts from the last 24h.
    """
    country_risk = {
        "IN": {"name": "India",         "lat": 20.5937, "lng": 78.9629, "base_risk": "low",     "risk_score": 15},
        "US": {"name": "United States", "lat": 37.0902, "lng":-95.7129, "base_risk": "low",     "risk_score": 10},
        "GB": {"name": "United Kingdom","lat": 55.3781, "lng": -3.4360, "base_risk": "low",     "risk_score": 12},
        "SG": {"name": "Singapore",     "lat":  1.3521, "lng":103.8198, "base_risk": "low",     "risk_score": 8},
        "RU": {"name": "Russia",        "lat": 61.5240, "lng": 105.3188,"base_risk": "high",    "risk_score": 82},
        "NG": {"name": "Nigeria",       "lat":  9.0820, "lng":  8.6753, "base_risk": "high",    "risk_score": 88},
        "CN": {"name": "China",         "lat": 35.8617, "lng":104.1954, "base_risk": "medium",  "risk_score": 55},
        "PK": {"name": "Pakistan",      "lat": 30.3753, "lng": 69.3451, "base_risk": "medium",  "risk_score": 62},
        "UA": {"name": "Ukraine",       "lat": 48.3794, "lng": 31.1656, "base_risk": "medium",  "risk_score": 48},
        "KP": {"name": "North Korea",   "lat": 40.3399, "lng":127.5101, "base_risk": "critical","risk_score": 97},
        "IR": {"name": "Iran",          "lat": 32.4279, "lng": 53.6880, "base_risk": "high",    "risk_score": 85},
        "DE": {"name": "Germany",       "lat": 51.1657, "lng": 10.4515, "base_risk": "low",     "risk_score": 14},
        "AU": {"name": "Australia",     "lat":-25.2744, "lng":133.7751, "base_risk": "low",     "risk_score": 11},
        "BR": {"name": "Brazil",        "lat":-14.2350, "lng":-51.9253, "base_risk": "medium",  "risk_score": 42},
        "BY": {"name": "Belarus",       "lat": 53.7098, "lng": 27.9534, "base_risk": "high",    "risk_score": 76},
        "VE": {"name": "Venezuela",     "lat":  6.4238, "lng":-66.5897, "base_risk": "high",    "risk_score": 71},
    }

    # Enrich with recent alert activity (last 24h)
    cutoff = time.time() - 86400
    recent = [a for a in ALERTS if a.timestamp >= cutoff]
    return {
        "countries":   list(country_risk.values()),
        "total_recent_alerts": len(recent),
        "hotspot_count": sum(1 for c in country_risk.values() if c["risk_score"] >= 60),
        "timestamp":   time.time(),
    }


@app.get("/api/attack/timeline", summary="Recent attack event timeline", tags=["Intel"])
def attack_timeline(limit: int = 50):
    """
    Returns a chronological attack event timeline built from recent alerts.
    Each alert becomes one or more timeline steps based on its risk level.
    """
    limit = max(1, min(limit, 200))
    recent = sorted(list(ALERTS)[:limit], key=lambda a: a.timestamp)

    timeline = []
    for alert in recent:
        a = alert if isinstance(alert, dict) else asdict(alert)
        level    = a.get("risk_level", "safe")
        ts       = a.get("timestamp", time.time())
        kind     = a.get("kind", "scan")
        target   = a.get("target", "")[:60]
        score    = a.get("risk_score", 0)

        severity_map = {
            "danger":  "DANGER",
            "caution": "WARNING",
            "safe":    "INFO",
        }
        sev = severity_map.get(level, "INFO")

        # Primary event
        timeline.append({
            "ts":       ts,
            "label":    f"{kind.upper()} scan — {target}",
            "severity": sev,
            "score":    score,
            "alert_id": a.get("id", ""),
        })

        # Secondary steps for high-risk events
        if score >= 65:
            timeline.append({
                "ts":       ts + 1,
                "label":    f"AI risk score: {score}/100 — {level.upper()}",
                "severity": sev,
                "score":    score,
                "alert_id": a.get("id", ""),
            })
            timeline.append({
                "ts":       ts + 2,
                "label":    f"Blockchain ledger updated: {a.get('ledger_hash','')[:16]}…",
                "severity": "INFO",
                "score":    score,
                "alert_id": a.get("id", ""),
            })
        if score >= 80:
            timeline.append({
                "ts":       ts + 3,
                "label":    "Transaction frozen — analyst review required",
                "severity": "DANGER",
                "score":    score,
                "alert_id": a.get("id", ""),
            })

    # Sort descending (newest first)
    timeline.sort(key=lambda e: e["ts"], reverse=True)
    return {"count": len(timeline), "events": timeline[:200]}


class ActivityEventPayload(BaseModel):
    level:   str   # INFO | WARNING | DANGER | CRITICAL
    message: str
    source:  str  = "system"
    meta:    dict = {}


@app.post("/api/activity/publish", summary="Publish an activity event to /ws/activity", tags=["Stream"])
async def publish_activity(p: ActivityEventPayload):
    """Broadcast a custom activity feed event to all /ws/activity subscribers."""
    event = {
        "level":     p.level.upper(),
        "message":   p.message,
        "source":    p.source,
        "meta":      p.meta,
        "timestamp": time.time(),
    }
    await ws_activity.broadcast(event)
    return {"ok": True, "event": event}


class RiskPublishPayload(BaseModel):
    risk_score:      float
    risk_level:      str
    fraud_probability: float = 0.0
    ai_confidence:   float  = 0.0
    primary_threat:  str    = ""
    target:          str    = ""
    explanation:     dict   = {}


@app.post("/api/ws/risk/publish", summary="Push a risk result to /ws/risk channel", tags=["Stream"])
async def publish_risk(p: RiskPublishPayload):
    """Broadcast a risk assessment result to all /ws/risk subscribers."""
    payload = {
        "risk_score":       p.risk_score,
        "risk_level":       p.risk_level,
        "fraud_probability": p.fraud_probability,
        "ai_confidence":    p.ai_confidence,
        "primary_threat":   p.primary_threat,
        "target":           p.target,
        "explanation":      p.explanation,
        "timestamp":        time.time(),
    }
    await ws_risk.broadcast(payload)
    return {"ok": True}


@app.get("/api/ws/status", summary="WebSocket connection counts across all channels", tags=["System"])
def ws_status():
    """Returns how many clients are connected to each WebSocket channel."""
    return {
        "channels": {
            "alerts":       len(ws_manager._sockets),
            "transactions": ws_transactions.count,
            "system":       ws_system.count,
            "risk":         ws_risk.count,
            "activity":     ws_activity.count,
        },
        "total": (
            len(ws_manager._sockets) +
            ws_transactions.count +
            ws_system.count +
            ws_risk.count +
            ws_activity.count
        ),
        "timestamp": time.time(),
    }


@app.get("/api/soc/summary", summary="SOC analyst dashboard summary", tags=["SOC"])
def soc_summary():
    """
    Single endpoint returning everything an analyst SOC dashboard needs:
    stats, recent alerts, system health, active campaigns, top targets.
    """
    cutoff_1h  = time.time() - 3600
    cutoff_24h = time.time() - 86400

    recent_1h  = [a for a in ALERTS if (a.timestamp if hasattr(a,"timestamp") else a.get("timestamp",0)) >= cutoff_1h]
    recent_24h = [a for a in ALERTS if (a.timestamp if hasattr(a,"timestamp") else a.get("timestamp",0)) >= cutoff_24h]

    def _lvl(a):
        return a.risk_level if hasattr(a,"risk_level") else a.get("risk_level","safe")

    danger_1h  = sum(1 for a in recent_1h  if _lvl(a) == "danger")
    danger_24h = sum(1 for a in recent_24h if _lvl(a) == "danger")

    return {
        "stats": {
            "total_alerts":    len(ALERTS),
            "danger_1h":       danger_1h,
            "danger_24h":      danger_24h,
            "alerts_1h":       len(recent_1h),
            "alerts_24h":      len(recent_24h),
            "ledger_blocks":   len(LEDGER),
            "ledger_valid":    verify_ledger(),
            "live_txn_count":  _txn_counter[0] - 10000,
        },
        "system":    _get_system_metrics(),
        "campaigns": campaign_detector.active_campaigns()[:5],
        "ws_clients": ws_status()["channels"],
        "timestamp": time.time(),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000)