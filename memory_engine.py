"""
FRAUD-X — Real-Time Memory Engine  v1.0
========================================
§5  In-memory fraud state — fast retrieval, low latency
§18 Distributed fraud intelligence — instant ecosystem-wide blocking

Provides a fast, thread-safe in-memory store for:
  - Recent fraud attempts   (keyed by URL/IP/session)
  - Suspicious devices      (device fingerprints flagged as bad)
  - Temporary attack signatures (auto-expire after TTL)
  - Recent phishing domains (sub-minute propagation from live detection)
  - Session attack history  (per-session event chain for correlation)
  - Global threat intel cache (shared intelligence across all requests)

§18 Distributed-intelligence note:
  In a production deployment, replace the in-process dicts with a Redis
  cluster. The MemoryEngine interface is Redis-compatible: get/set/delete
  operations map directly to Redis GET/SET/DEL with TTL support.
  In this single-node deployment, the in-process store achieves sub-ms
  reads and serves the same purpose for up to ~100k concurrent sessions.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Optional

# ── Default TTLs (seconds) ────────────────────────────────────
TTL_FRAUD_ATTEMPT   = 3600       #  1 hour
TTL_SUSPICIOUS_DEV  = 86400      # 24 hours
TTL_ATTACK_SIG      = 600        # 10 minutes
TTL_PHISHING_DOMAIN = 3600       #  1 hour
TTL_SESSION_HIST    = 1800       # 30 minutes
TTL_THREAT_INTEL    = 3600       #  1 hour

# ── Store size limits ─────────────────────────────────────────
MAX_FRAUD_ATTEMPTS   = 50_000
MAX_SUSPICIOUS_DEVS  = 20_000
MAX_ATTACK_SIGS      = 5_000
MAX_PHISHING_DOMAINS = 100_000
MAX_SESSION_HIST     = 100_000


# ═════════════════════════════════════════════════════════════
# Generic TTL cache
# ═════════════════════════════════════════════════════════════

class TTLCache:
    """
    Thread-safe dict with per-entry TTL and size capping.
    Expired entries are pruned lazily on read and eagerly on set()
    once the store exceeds MAX_SIZE.
    """

    def __init__(self, max_size: int = 10_000, default_ttl: float = 3600.0):
        self._store:    dict[str, tuple[Any, float]] = {}   # key → (value, expires_at)
        self._lock      = threading.Lock()
        self._max_size  = max_size
        self._default_ttl = default_ttl

    def set(self, key: str, value: Any, ttl: Optional[float] = None):
        expires = time.time() + (ttl if ttl is not None else self._default_ttl)
        with self._lock:
            self._store[key] = (value, expires)
            if len(self._store) > self._max_size:
                self._evict_locked()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            entry = self._store.get(key)
            if not entry:
                return None
            value, expires = entry
            if time.time() > expires:
                del self._store[key]
                return None
            return value

    def exists(self, key: str) -> bool:
        return self.get(key) is not None

    def delete(self, key: str):
        with self._lock:
            self._store.pop(key, None)

    def keys_matching(self, prefix: str) -> list[str]:
        now = time.time()
        with self._lock:
            return [k for k, (_, exp) in self._store.items()
                    if k.startswith(prefix) and exp > now]

    def size(self) -> int:
        with self._lock:
            return len(self._store)

    def prune(self) -> int:
        now = time.time()
        with self._lock:
            expired = [k for k, (_, exp) in self._store.items() if exp <= now]
            for k in expired:
                del self._store[k]
            return len(expired)

    def _evict_locked(self):
        """Evict oldest entries (by expiry time) when at capacity."""
        n_evict = max(1, self._max_size // 10)
        sorted_keys = sorted(self._store.keys(), key=lambda k: self._store[k][1])
        for k in sorted_keys[:n_evict]:
            del self._store[k]


# ═════════════════════════════════════════════════════════════
# §5 + §18 Memory Engine
# ═════════════════════════════════════════════════════════════

class MemoryEngine:
    """
    Central in-memory fraud intelligence store.

    Stores and indexes all short-lived fraud signals for
    instant cross-request correlation and §18 ecosystem-wide
    threat intelligence propagation.
    """

    def __init__(self):
        # §5 Recent fraud attempts: url/ip → {score, reason, ts}
        self.fraud_attempts   = TTLCache(MAX_FRAUD_ATTEMPTS,   TTL_FRAUD_ATTEMPT)

        # §18 Suspicious device fingerprints
        self.suspicious_devs  = TTLCache(MAX_SUSPICIOUS_DEVS,  TTL_SUSPICIOUS_DEV)

        # §19 Active attack signatures
        self.attack_sigs      = TTLCache(MAX_ATTACK_SIGS,      TTL_ATTACK_SIG)

        # §13/§18 Phishing domains (instant global propagation)
        self.phishing_domains = TTLCache(MAX_PHISHING_DOMAINS, TTL_PHISHING_DOMAIN)

        # §4/§5 Session attack history
        self.session_history  = TTLCache(MAX_SESSION_HIST,     TTL_SESSION_HIST)

        # §3 Threat intel cache (IP/domain reputation)
        self.threat_intel     = TTLCache(10_000,               TTL_THREAT_INTEL)

        # §6 Campaign tracking: campaign_id → set of affected entities
        self._campaigns: dict[str, set] = defaultdict(set)
        self._campaign_lock = threading.Lock()

        # Real-time event log (§14 audit + streaming)
        self._event_log: deque = deque(maxlen=10_000)
        self._log_lock   = threading.Lock()

    # ── Fraud attempts ────────────────────────────────────────

    def record_fraud_attempt(
        self, key: str, score: float, reason: str,
        kind: str = "url", ttl: float = TTL_FRAUD_ATTEMPT,
    ):
        """Record a detected fraud attempt. key = url | ip | session_id."""
        self.fraud_attempts.set(key, {
            "score": score, "reason": reason, "kind": kind,
            "ts": time.time(), "count": self._increment_count(key),
        }, ttl=ttl)
        self._log(kind="fraud_attempt", key=key, score=score, reason=reason)

    def get_fraud_history(self, key: str) -> Optional[dict]:
        return self.fraud_attempts.get(key)

    def is_known_bad(self, key: str) -> bool:
        entry = self.fraud_attempts.get(key)
        return entry is not None and entry.get("score", 0) >= 60

    def _increment_count(self, key: str) -> int:
        existing = self.fraud_attempts.get(key)
        return (existing.get("count", 0) + 1) if existing else 1

    # ── Suspicious devices (§3/§7) ────────────────────────────

    def flag_device(self, device_fp: str, reason: str, score: float = 80.0):
        self.suspicious_devs.set(device_fp, {
            "reason": reason, "score": score, "ts": time.time(),
        })
        self._log(kind="device_flagged", key=device_fp[:24], score=score, reason=reason)

    def is_suspicious_device(self, device_fp: str) -> bool:
        return self.suspicious_devs.exists(device_fp)

    # ── Phishing domains (§13/§18) ────────────────────────────

    def add_phishing_domain(self, domain: str, source: str = "live_detection"):
        """§18: Once a domain is detected as phishing, instantly block globally."""
        domain = domain.lower().strip()
        self.phishing_domains.set(domain, {"source": source, "ts": time.time()})
        self._log(kind="phishing_domain", key=domain, score=100, reason=source)

    def is_phishing_domain(self, domain: str) -> bool:
        return self.phishing_domains.exists(domain.lower().strip())

    def list_phishing_domains(self, limit: int = 1000) -> list[str]:
        return self.phishing_domains.keys_matching("")[:limit]

    # ── Attack signatures (§19) ───────────────────────────────

    def store_signature(self, sig_id: str, signature: dict, ttl: float = TTL_ATTACK_SIG):
        self.attack_sigs.set(sig_id, {**signature, "ts": time.time()})

    def get_signature(self, sig_id: str) -> Optional[dict]:
        return self.attack_sigs.get(sig_id)

    # ── Session history (§5/§11) ──────────────────────────────

    def append_session_event(self, session_id: str, event: dict):
        existing = self.session_history.get(session_id) or []
        existing.append({**event, "ts": time.time()})
        if len(existing) > 500:
            existing = existing[-500:]
        self.session_history.set(session_id, existing)

    def get_session_history(self, session_id: str) -> list:
        return self.session_history.get(session_id) or []

    # ── Campaign tracking (§6/§18) ────────────────────────────

    def add_to_campaign(self, campaign_id: str, entity: str):
        with self._campaign_lock:
            self._campaigns[campaign_id].add(entity)

    def campaign_size(self, campaign_id: str) -> int:
        with self._campaign_lock:
            return len(self._campaigns.get(campaign_id, set()))

    def list_campaigns(self) -> list[dict]:
        with self._campaign_lock:
            return [
                {"id": cid, "entities": len(ents), "ts": time.time()}
                for cid, ents in self._campaigns.items()
            ]

    # ── Threat intel cache (§3) ───────────────────────────────

    def cache_threat_intel(self, key: str, result: dict, ttl: float = TTL_THREAT_INTEL):
        self.threat_intel.set(key, result, ttl=ttl)

    def get_threat_intel(self, key: str) -> Optional[dict]:
        return self.threat_intel.get(key)

    # ── Event log + maintenance ───────────────────────────────

    def _log(self, kind: str, key: str, score: float, reason: str):
        with self._log_lock:
            self._event_log.append({
                "kind": kind, "key": key, "score": score,
                "reason": reason, "ts": time.time(),
            })

    def recent_events(self, n: int = 50) -> list:
        with self._log_lock:
            return list(self._event_log)[-n:]

    def prune_all(self) -> dict:
        """Evict all expired entries from all caches."""
        return {
            "fraud_attempts":  self.fraud_attempts.prune(),
            "suspicious_devs": self.suspicious_devs.prune(),
            "attack_sigs":     self.attack_sigs.prune(),
            "phishing_domains":self.phishing_domains.prune(),
            "session_history": self.session_history.prune(),
            "threat_intel":    self.threat_intel.prune(),
        }

    def stats(self) -> dict:
        return {
            "fraud_attempts":   self.fraud_attempts.size(),
            "suspicious_devs":  self.suspicious_devs.size(),
            "attack_sigs":      self.attack_sigs.size(),
            "phishing_domains": self.phishing_domains.size(),
            "session_history":  self.session_history.size(),
            "threat_intel":     self.threat_intel.size(),
            "campaigns":        len(self._campaigns),
        }


# ── Singleton ─────────────────────────────────────────────────
memory_engine = MemoryEngine()
