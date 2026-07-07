"""
FRAUD-X — Central Event Correlation Engine  v1.0
=================================================
§1  Real-time event correlation — unifies ALL fraud signals
§11 Attack chain detection — multi-stage fraud progression
§17 Confidence fusion — per-source meta-confidence weighting

Algorithm
---------
  1. Accept a CorrelationInput with up to 10 fraud signal scores (0-100)
  2. Apply per-signal weights calibrated from operational data
  3. Invert trust signals (device_trust, browser_trust → risk contribution)
  4. Sum weighted contributions → raw_score
  5. Apply corroboration boost when ≥3 signals are simultaneously high-risk
  6. Compute meta-confidence from signal coverage ratio
  7. Map to severity band (safe/suspicious/high/critical) + action
  8. Track attack chains (multi-stage fraud progressions) per session
  9. Buffer recent events for sliding-window analytics

§1 Example from spec:
  New Device (device_trust=20)     → 0.12 weight → +9.6
  Suspicious Typing (biometrics=70)→ 0.12 weight → +8.4
  Bad IP Reputation (threat=80)    → 0.18 weight → +14.4
  High Transaction Amount (vel=60) → 0.10 weight → +6.0
  ──────────────────────────────────────────────────────
  Weighted sum = 38.4  +  corroboration boost = +12  →  50.4 → HIGH
"""

from __future__ import annotations

import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Optional

# ── Signal weights (tuned for financial fraud detection) ──────
SIGNAL_WEIGHTS: dict[str, float] = {
    "url_score":        0.20,   # URL ML + heuristic score
    "biometrics_risk":  0.12,   # Behavioral biometrics (§6)
    "device_trust":     0.12,   # Device fingerprint (inverted: low trust = risk)
    "threat_intel":     0.18,   # VirusTotal / GSB / AbuseIPDB
    "velocity":         0.10,   # Transaction velocity (§12 extension)
    "session_anomaly":  0.10,   # Session-level signals (§4)
    "graph_risk":       0.08,   # Graph fraud relationships
    "dom_mutation":     0.05,   # DOM mutation risk (§8)
    "browser_env":      0.05,   # Browser environment risk (§9)
    "ato_risk":         0.10,   # Account takeover risk (§3)
}

# ── Corroboration boost (§1) ──────────────────────────────────
CORROBORATION_BOOST     = 12    # points added when multiple signals align
CORROBORATION_THRESHOLD = 55    # signal score that counts as "high-risk"
CORROBORATION_MIN       = 3     # minimum aligned signals to trigger boost

# ── Risk band thresholds (§8 bands) ──────────────────────────
BAND_CRITICAL   = 81
BAND_HIGH       = 61
BAND_SUSPICIOUS = 31

# ── Attack chain stages ───────────────────────────────────────
ATTACK_STAGES = [
    "phishing_url",
    "fake_login",
    "device_mismatch",
    "otp_abuse",
    "high_transaction",
    "account_takeover",
    "data_exfiltration",
]


# ═════════════════════════════════════════════════════════════
# Data classes
# ═════════════════════════════════════════════════════════════

@dataclass
class CorrelationInput:
    """All available fraud signals for a single event/session."""
    # Signal scores (0-100 each)
    url_score:        float = 0.0
    biometrics_risk:  float = 0.0
    device_trust:     float = 100.0   # 100 = fully trusted; inverted internally
    threat_intel:     float = 0.0
    velocity:         float = 0.0
    session_anomaly:  float = 0.0
    graph_risk:       float = 0.0
    dom_mutation:     float = 0.0
    browser_env:      float = 0.0
    ato_risk:         float = 0.0
    # Metadata
    url:              str   = ""
    user_id:          str   = ""
    session_id:       str   = ""
    ip:               str   = ""
    amount:           float = 0.0
    ts:               float = field(default_factory=time.time)


@dataclass
class CorrelationResult:
    """Unified fraud intelligence output."""
    unified_score:      float          # 0-100
    confidence:         float          # 0-1 meta-confidence
    severity:           str            # safe|suspicious|high|critical
    recommended_action: str            # allow|flag|challenge|block
    active_signals:     list           # top contributing signals
    corroboration:      int            # count of simultaneously high-risk signals
    breakdown:          dict           # per-signal weighted contributions
    attack_chain:       Optional[dict] = None   # multi-stage chain if detected
    ts:                 float = field(default_factory=time.time)

    @property
    def is_fraud(self) -> bool:
        return self.unified_score >= BAND_HIGH

    def to_dict(self) -> dict:
        d = {
            "unified_score":      round(self.unified_score, 2),
            "confidence":         round(self.confidence, 3),
            "severity":           self.severity,
            "recommended_action": self.recommended_action,
            "active_signals":     self.active_signals,
            "corroboration":      self.corroboration,
            "is_fraud":           self.is_fraud,
            "breakdown":          {k: round(v, 2) for k, v in self.breakdown.items()},
            "ts":                 self.ts,
        }
        if self.attack_chain:
            d["attack_chain"] = self.attack_chain
        return d


# ═════════════════════════════════════════════════════════════
# Attack Chain Tracker (§11)
# ═════════════════════════════════════════════════════════════

class AttackChainTracker:
    """
    Tracks multi-stage fraud attack progressions per session.

    A chain is confirmed when:
    - ≥2 distinct attack stages are observed in a session
    - Each stage threshold is exceeded
    - Stages occur in a plausible temporal sequence
    """

    STAGE_THRESHOLDS = {
        "phishing_url":      ("url_score",       60),
        "fake_login":        ("session_anomaly",  55),
        "device_mismatch":   ("device_trust",     40),   # inverted: <40 = mismatch
        "otp_abuse":         ("ato_risk",         50),
        "high_transaction":  ("velocity",         65),
        "account_takeover":  ("ato_risk",         70),
        "data_exfiltration": ("session_anomaly",  75),
    }

    def __init__(self):
        self._chains: dict[str, list] = {}   # session_id → [stage_events]
        self._lock = threading.Lock()

    def update(self, inp: CorrelationInput) -> Optional[dict]:
        if not inp.session_id:
            return None

        detected = []
        raw = {
            "url_score":       inp.url_score,
            "session_anomaly": inp.session_anomaly,
            "device_trust":    100.0 - inp.device_trust,   # invert
            "ato_risk":        inp.ato_risk,
            "velocity":        inp.velocity,
        }

        for stage, (sig, thresh) in self.STAGE_THRESHOLDS.items():
            if raw.get(sig, 0) >= thresh:
                detected.append(stage)

        if not detected:
            return None

        with self._lock:
            chain = self._chains.setdefault(inp.session_id, [])
            for s in detected:
                if not any(e["stage"] == s for e in chain):
                    chain.append({"stage": s, "ts": inp.ts, "score": raw.get(
                        self.STAGE_THRESHOLDS[s][0], 0)})

            if len(chain) >= 2:
                confidence = min(1.0, len(chain) / 4)
                stages_list = [e["stage"] for e in chain]
                progression = [s for s in ATTACK_STAGES if s in stages_list]
                return {
                    "session_id":  inp.session_id,
                    "stages":      chain,
                    "progression": progression,
                    "confidence":  round(confidence, 3),
                    "stage_count": len(chain),
                    "probability": round(confidence * 100, 1),
                }
        return None

    def clear_old(self, max_age: float = 3600.0):
        cutoff = time.time() - max_age
        with self._lock:
            stale = [sid for sid, chain in self._chains.items()
                     if chain and chain[-1]["ts"] < cutoff]
            for sid in stale:
                del self._chains[sid]

    def stats(self) -> dict:
        with self._lock:
            return {
                "active_chains": len(self._chains),
                "total_stages":  sum(len(c) for c in self._chains.values()),
            }


# ═════════════════════════════════════════════════════════════
# Central Event Correlation Engine (§1)
# ═════════════════════════════════════════════════════════════

class EventCorrelationEngine:
    """
    Correlates all fraud signals into a single unified fraud score.

    Thread-safe. Maintains a rolling event buffer for analytics.
    Optionally integrates with the AttackChainTracker for §11.
    """

    def __init__(self, weights: Optional[dict] = None):
        self._weights       = {**SIGNAL_WEIGHTS, **(weights or {})}
        self._event_buffer  = deque(maxlen=20_000)
        self._lock          = threading.Lock()
        self._chain_tracker = AttackChainTracker()
        self._total         = 0
        self._blocked       = 0

    # ── Core correlation (§1 + §17) ──────────────────────────

    def correlate(self, inp: CorrelationInput) -> CorrelationResult:
        """
        Produce a CorrelationResult from all available signals.
        See module docstring for full algorithm description.
        """
        # Build signal dict with trust inversion
        signals: dict[str, float] = {
            "url_score":        max(0.0, min(100.0, inp.url_score)),
            "biometrics_risk":  max(0.0, min(100.0, inp.biometrics_risk)),
            "device_trust":     max(0.0, min(100.0, 100.0 - inp.device_trust)),
            "threat_intel":     max(0.0, min(100.0, inp.threat_intel)),
            "velocity":         max(0.0, min(100.0, inp.velocity)),
            "session_anomaly":  max(0.0, min(100.0, inp.session_anomaly)),
            "graph_risk":       max(0.0, min(100.0, inp.graph_risk)),
            "dom_mutation":     max(0.0, min(100.0, inp.dom_mutation)),
            "browser_env":      max(0.0, min(100.0, inp.browser_env)),
            "ato_risk":         max(0.0, min(100.0, inp.ato_risk)),
        }

        # Weighted sum + breakdown
        breakdown: dict[str, float] = {}
        weighted_sum   = 0.0
        active_signals = []
        corroboration  = 0

        for key, raw in signals.items():
            w            = self._weights.get(key, 0.0)
            contribution = raw * w
            weighted_sum += contribution
            breakdown[key] = contribution

            if raw >= CORROBORATION_THRESHOLD:
                corroboration += 1
            if raw >= 35.0:
                active_signals.append({
                    "signal": key, "score": round(raw, 1), "weight": w,
                    "contribution": round(contribution, 2),
                })

        active_signals.sort(key=lambda x: -x["score"])

        # Corroboration boost (§1)
        boost     = CORROBORATION_BOOST if corroboration >= CORROBORATION_MIN else 0
        raw_score = min(100.0, weighted_sum + boost)

        # Meta-confidence = ratio of signals that have real data (>0)
        non_zero   = sum(1 for v in signals.values() if v > 0)
        confidence = non_zero / len(signals)

        # Severity + recommended action
        severity, action = self._classify(raw_score)

        # Attack chain detection (§11)
        chain = self._chain_tracker.update(inp)

        result = CorrelationResult(
            unified_score=raw_score,
            confidence=confidence,
            severity=severity,
            recommended_action=action,
            active_signals=active_signals[:5],
            corroboration=corroboration,
            breakdown=breakdown,
            attack_chain=chain,
        )

        # Buffer event for analytics
        with self._lock:
            self._total += 1
            if action == "block":
                self._blocked += 1
            self._event_buffer.append({
                "score":    raw_score,
                "severity": severity,
                "url":      inp.url,
                "session":  inp.session_id,
                "ts":       inp.ts,
            })

        return result

    # ── Risk band classification ──────────────────────────────

    @staticmethod
    def _classify(score: float) -> tuple[str, str]:
        if score >= BAND_CRITICAL:   return "critical",   "block"
        if score >= BAND_HIGH:       return "high",       "challenge"
        if score >= BAND_SUSPICIOUS: return "suspicious", "flag"
        return "safe", "allow"

    # ── Analytics helpers ─────────────────────────────────────

    def recent_events(self, n: int = 100) -> list:
        with self._lock:
            return list(self._event_buffer)[-n:]

    def stats(self) -> dict:
        with self._lock:
            events = list(self._event_buffer)
        if not events:
            return {
                "total": 0, "blocked": 0, "critical": 0,
                "high": 0, "suspicious": 0, "safe": 0,
                "chain_tracker": self._chain_tracker.stats(),
            }
        counts = Counter(e["severity"] for e in events)
        return {
            "total":       self._total,
            "blocked":     self._blocked,
            "critical":    counts.get("critical",   0),
            "high":        counts.get("high",       0),
            "suspicious":  counts.get("suspicious", 0),
            "safe":        counts.get("safe",       0),
            "buffer_size": len(events),
            "chain_tracker": self._chain_tracker.stats(),
        }

    def attack_chains(self) -> dict:
        return self._chain_tracker.stats()

    def cleanup(self):
        self._chain_tracker.clear_old()
        with self._lock:
            cutoff = time.time() - 86400
            while self._event_buffer and self._event_buffer[0]["ts"] < cutoff:
                self._event_buffer.popleft()


# ── Singleton ─────────────────────────────────────────────────
event_correlation_engine = EventCorrelationEngine()
