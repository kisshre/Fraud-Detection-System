"""
FRAUD-X — Live Fraud Signature Generator  v1.0
===============================================
§19 Dynamic fraud rule generation from observed attack patterns

The engine learns new fraud detection rules automatically from:
  - Confirmed fraud events (high score + analyst confirmation)
  - Attack pattern clustering (repeated signals across events)
  - Threat intelligence matches (new malicious artifacts)
  - DOM mutation patterns (from browser-side detection)
  - AI-detected anomalies (from the correlation engine)

Signature types
---------------
  DOMAIN_PATTERN   — regex or exact domain match
  IP_RANGE         — CIDR block of malicious IPs
  BEHAVIOR_PATTERN — biometric/session pattern rule
  URL_PATTERN      — regex match on URL structure
  PAYMENT_TEMPLATE — fake payment page fingerprint
  DEVICE_CLASS     — suspicious device fingerprint cluster
  CAMPAIGN_RULE    — campaign-specific detection rule

Lifecycle
---------
  CANDIDATE  → detected ≥2 times, not yet confirmed
  ACTIVE     → confirmed ≥ACTIVATION_THRESHOLD times, now enforced
  DEPRECATED → superseded by a more specific rule or expired
"""

from __future__ import annotations

import hashlib
import re
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

# ── Config ────────────────────────────────────────────────────
ACTIVATION_THRESHOLD = 3     # observations to activate a signature
MAX_SIGNATURES       = 2000
SIGNATURE_TTL        = 86400 * 7   # 7 days before review


class SigType(str, Enum):
    DOMAIN_PATTERN   = "domain_pattern"
    IP_RANGE         = "ip_range"
    BEHAVIOR_PATTERN = "behavior_pattern"
    URL_PATTERN      = "url_pattern"
    PAYMENT_TEMPLATE = "payment_template"
    DEVICE_CLASS     = "device_class"
    CAMPAIGN_RULE    = "campaign_rule"


class SigStatus(str, Enum):
    CANDIDATE  = "candidate"
    ACTIVE     = "active"
    DEPRECATED = "deprecated"


@dataclass
class Signature:
    """A single fraud detection rule."""
    sig_id:     str
    sig_type:   SigType
    pattern:    str                    # the actual rule/pattern
    description:str
    confidence: float = 0.5            # 0-1
    hits:       int   = 0              # times this rule triggered
    false_positives: int = 0
    status:     SigStatus = SigStatus.CANDIDATE
    created_at: float = field(default_factory=time.time)
    last_hit:   float = field(default_factory=time.time)
    source:     str = "auto"          # auto|analyst|threat_feed

    @property
    def precision(self) -> float:
        return max(0.0, 1.0 - (self.false_positives / max(1, self.hits)))

    @property
    def is_expired(self) -> bool:
        return (time.time() - self.last_hit) > SIGNATURE_TTL

    def to_dict(self) -> dict:
        return {
            "sig_id":      self.sig_id,
            "type":        self.sig_type.value,
            "pattern":     self.pattern,
            "description": self.description,
            "confidence":  round(self.confidence, 3),
            "hits":        self.hits,
            "false_positives": self.false_positives,
            "precision":   round(self.precision, 3),
            "status":      self.status.value,
            "source":      self.source,
            "created_at":  self.created_at,
            "last_hit":    self.last_hit,
        }


# ═════════════════════════════════════════════════════════════
# §19 Signature Engine
# ═════════════════════════════════════════════════════════════

class SignatureEngine:
    """
    Automatically generates, activates, and manages fraud detection
    signatures from observed attack patterns.
    """

    def __init__(self):
        self._sigs:      dict[str, Signature] = {}
        self._lock       = threading.Lock()
        # Pattern occurrence counters (for auto-activation)
        self._pattern_hits: dict[str, int] = defaultdict(int)
        self._recent_generated: deque = deque(maxlen=200)
        self._total_generated = 0

    # ── Signature generation from events ─────────────────────

    def ingest_fraud_event(
        self,
        score:     float,
        url:       str    = "",
        domain:    str    = "",
        ip:        str    = "",
        device_fp: str    = "",
        signals:   list   = None,
        campaign:  str    = "",
    ):
        """
        Auto-generate signatures from a high-confidence fraud event.
        Only generates for events with score ≥ 70.
        """
        if score < 70:
            return

        generated = []

        # Domain signature
        if domain:
            sig = self._generate_domain_sig(domain, score)
            if sig:
                generated.append(sig)

        # URL pattern signature
        if url:
            sig = self._generate_url_sig(url, score)
            if sig:
                generated.append(sig)

        # IP range signature
        if ip:
            sig = self._generate_ip_sig(ip, score)
            if sig:
                generated.append(sig)

        # Device class signature
        if device_fp and len(device_fp) >= 8:
            sig = self._generate_device_sig(device_fp[:16], score)
            if sig:
                generated.append(sig)

        # Campaign rule
        if campaign:
            sig = self._generate_campaign_sig(campaign, score)
            if sig:
                generated.append(sig)

        with self._lock:
            for sig in generated:
                self._upsert(sig)
                self._recent_generated.append(sig.sig_id)
                self._total_generated += 1

    # ── Manual signature creation (analyst + threat feed) ────

    def add_manual_signature(
        self,
        pattern:     str,
        sig_type:    str,
        description: str,
        confidence:  float = 0.90,
        source:      str   = "analyst",
    ) -> str:
        sig_id = self._make_id(pattern)
        sig    = Signature(
            sig_id      = sig_id,
            sig_type    = SigType(sig_type) if sig_type in SigType._value2member_map_ else SigType.URL_PATTERN,
            pattern     = pattern,
            description = description,
            confidence  = confidence,
            status      = SigStatus.ACTIVE,   # manual sigs immediately active
            source      = source,
        )
        with self._lock:
            self._upsert(sig)
        return sig_id

    # ── Matching API ──────────────────────────────────────────

    def match(
        self,
        url:       str = "",
        domain:    str = "",
        ip:        str = "",
        device_fp: str = "",
    ) -> list[dict]:
        """
        Return all ACTIVE signatures matching the given artifacts.
        Updates hit counters for matched signatures.
        """
        with self._lock:
            active = [s for s in self._sigs.values() if s.status == SigStatus.ACTIVE]

        matches: list[Signature] = []
        for sig in active:
            if self._matches(sig, url=url, domain=domain, ip=ip, device_fp=device_fp):
                matches.append(sig)

        with self._lock:
            for sig in matches:
                sig.hits    += 1
                sig.last_hit = time.time()

        return [s.to_dict() for s in matches]

    def report_false_positive(self, sig_id: str):
        with self._lock:
            sig = self._sigs.get(sig_id)
            if sig:
                sig.false_positives += 1
                if sig.precision < 0.30:
                    sig.status = SigStatus.DEPRECATED

    # ── Query ─────────────────────────────────────────────────

    def active_signatures(self) -> list[dict]:
        with self._lock:
            return [s.to_dict() for s in self._sigs.values() if s.status == SigStatus.ACTIVE]

    def all_signatures(self) -> list[dict]:
        with self._lock:
            return [s.to_dict() for s in self._sigs.values()]

    def stats(self) -> dict:
        with self._lock:
            sigs = list(self._sigs.values())
        from collections import Counter
        status_counts = Counter(s.status.value for s in sigs)
        return {
            "total":           len(sigs),
            "active":          status_counts.get("active", 0),
            "candidate":       status_counts.get("candidate", 0),
            "deprecated":      status_counts.get("deprecated", 0),
            "total_generated": self._total_generated,
            "total_hits":      sum(s.hits for s in sigs),
        }

    def cleanup(self):
        """Deprecate expired or low-precision signatures."""
        with self._lock:
            for sig in self._sigs.values():
                if sig.is_expired and sig.status == SigStatus.ACTIVE:
                    sig.status = SigStatus.DEPRECATED
                if sig.precision < 0.20 and sig.hits >= 10:
                    sig.status = SigStatus.DEPRECATED

    # ── Internal helpers ──────────────────────────────────────

    def _upsert(self, new_sig: Signature):
        """Add new signature or update hit count if duplicate pattern."""
        existing = self._sigs.get(new_sig.sig_id)
        if existing:
            self._pattern_hits[new_sig.sig_id] += 1
            count = self._pattern_hits[new_sig.sig_id]
            if existing.status == SigStatus.CANDIDATE and count >= ACTIVATION_THRESHOLD:
                existing.status = SigStatus.ACTIVE
            existing.confidence = min(1.0, existing.confidence + 0.05)
            existing.last_hit   = time.time()
        else:
            self._pattern_hits[new_sig.sig_id] = 1
            if len(self._sigs) >= MAX_SIGNATURES:
                self.cleanup()
            self._sigs[new_sig.sig_id] = new_sig

    def _matches(
        self, sig: Signature,
        url: str = "", domain: str = "", ip: str = "", device_fp: str = ""
    ) -> bool:
        try:
            if sig.sig_type == SigType.DOMAIN_PATTERN and domain:
                return bool(re.search(sig.pattern, domain, re.I))
            if sig.sig_type == SigType.URL_PATTERN and url:
                return bool(re.search(sig.pattern, url, re.I))
            if sig.sig_type == SigType.IP_RANGE and ip:
                prefix = ".".join(ip.split(".")[:3])
                return sig.pattern == prefix or ip.startswith(sig.pattern)
            if sig.sig_type == SigType.DEVICE_CLASS and device_fp:
                return device_fp.startswith(sig.pattern)
        except re.error:
            return sig.pattern in (url + domain + ip + device_fp)
        return False

    def _generate_domain_sig(self, domain: str, score: float) -> Optional[Signature]:
        # Generate a regex that matches the domain and common variants
        escaped = re.escape(domain)
        pattern = f"^{escaped}$|{escaped}"
        sig_id  = self._make_id("domain:" + domain)
        return Signature(
            sig_id      = sig_id,
            sig_type    = SigType.DOMAIN_PATTERN,
            pattern     = pattern,
            description = f"Auto-detected phishing domain: {domain} (score {score:.0f})",
            confidence  = min(0.95, score / 100),
        )

    def _generate_url_sig(self, url: str, score: float) -> Optional[Signature]:
        try:
            from urllib.parse import urlparse
            parsed  = urlparse(url)
            # Use the path pattern as the signature
            path    = parsed.path.rstrip("/") or "/"
            pattern = re.escape(path) + r".*"
            sig_id  = self._make_id("url:" + path)
            return Signature(
                sig_id      = sig_id,
                sig_type    = SigType.URL_PATTERN,
                pattern     = pattern,
                description = f"Auto-detected phishing URL path: {path}",
                confidence  = min(0.90, score / 100),
            )
        except Exception:
            return None

    def _generate_ip_sig(self, ip: str, score: float) -> Optional[Signature]:
        prefix  = ".".join(ip.split(".")[:3])
        sig_id  = self._make_id("ip:" + prefix)
        return Signature(
            sig_id      = sig_id,
            sig_type    = SigType.IP_RANGE,
            pattern     = prefix,
            description = f"Malicious /24 subnet: {prefix}.0/24",
            confidence  = min(0.85, score / 100),
        )

    def _generate_device_sig(self, fp_prefix: str, score: float) -> Optional[Signature]:
        sig_id = self._make_id("dev:" + fp_prefix)
        return Signature(
            sig_id      = sig_id,
            sig_type    = SigType.DEVICE_CLASS,
            pattern     = fp_prefix,
            description = f"Suspicious device class: {fp_prefix}…",
            confidence  = min(0.75, score / 100),
        )

    def _generate_campaign_sig(self, campaign_id: str, score: float) -> Optional[Signature]:
        sig_id = self._make_id("camp:" + campaign_id)
        return Signature(
            sig_id      = sig_id,
            sig_type    = SigType.CAMPAIGN_RULE,
            pattern     = campaign_id,
            description = f"Campaign detection rule: {campaign_id}",
            confidence  = min(0.92, score / 100),
        )

    @staticmethod
    def _make_id(raw: str) -> str:
        return "SIG-" + hashlib.sha1(raw.encode()).hexdigest()[:10].upper()


# ── Singleton ─────────────────────────────────────────────────
signature_engine = SignatureEngine()
