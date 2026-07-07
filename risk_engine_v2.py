"""
FRAUD-X  ·  Dynamic Risk Scoring Engine v2
==========================================
Combines signals from ALL fraud detection engines into a single
calibrated risk score with action recommendations.

Ensemble weights
----------------
  XGBoost/ensemble   30 %  (from advanced_ml_engine)
  Autoencoder        15 %  (reconstruction anomaly)
  LSTM sequence      10 %  (behavioral drift)
  Behavioral biometrics 10 %
  Transaction velocity  10 %
  Threat intelligence   10 %
  Graph fraud prob       8 %
  Device fingerprint     7 %

Score bands → Actions
---------------------
  0–30   SAFE      → Allow
  31–60  MEDIUM    → OTP / Step-up verification
  61–80  HIGH      → Block + analyst review
  81–100 CRITICAL  → Freeze account + immediate alert
"""

from __future__ import annotations

import logging
import math
import statistics
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("fraudx.risk_v2")

# ── Risk bands ────────────────────────────────────────────────────────────────
BAND_SAFE     = (0,  30)
BAND_MEDIUM   = (31, 60)
BAND_HIGH     = (61, 80)
BAND_CRITICAL = (81, 100)


def _band(score: int) -> str:
    if score <= 30:  return "safe"
    if score <= 60:  return "medium"
    if score <= 80:  return "high"
    return "critical"


def _action(band: str) -> str:
    return {
        "safe":     "ALLOW",
        "medium":   "OTP_VERIFICATION",
        "high":     "BLOCK",
        "critical": "FREEZE_AND_ALERT",
    }.get(band, "ALLOW")


# ═════════════════════════════════════════════════════════════════════════════
# Signal weights (must sum to 1.0)
# ═════════════════════════════════════════════════════════════════════════════

DEFAULT_WEIGHTS: Dict[str, float] = {
    "ensemble_ml":   0.30,
    "autoencoder":   0.15,
    "sequence_lstm": 0.10,
    "biometrics":    0.10,
    "velocity":      0.10,
    "threat_intel":  0.10,
    "graph":         0.08,
    "device_fp":     0.07,
}

assert abs(sum(DEFAULT_WEIGHTS.values()) - 1.0) < 1e-6, "Weights must sum to 1.0"


# ═════════════════════════════════════════════════════════════════════════════
# Data structures
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class RiskSignals:
    """Raw signal scores (each 0–100) from each engine."""
    ensemble_ml:   float = 0.0   # fraud_probability * 100
    autoencoder:   float = 0.0   # anomaly_probability * 100
    sequence_lstm: float = 0.0   # drift_score * 100
    biometrics:    float = 0.0   # bot_risk_score
    velocity:      float = 0.0   # velocity risk score
    threat_intel:  float = 0.0   # total_delta (0–50) → scaled to 100
    graph:         float = 0.0   # graph fraud cluster probability * 100
    device_fp:     float = 0.0   # device risk score


@dataclass
class RiskDecision:
    final_score:    int
    band:           str               # safe / medium / high / critical
    action:         str               # ALLOW / OTP / BLOCK / FREEZE
    confidence:     str               # high / medium / low
    signals:        Dict[str, float]  # per-engine scores used
    reasons:        List[str]
    shap_features:  Dict[str, float]  # top ML feature impacts
    autoencoder:    Dict              # reconstruction details
    sequence:       Dict              # sequence details
    timestamp:      float = field(default_factory=time.time)


# ═════════════════════════════════════════════════════════════════════════════
# Adaptive weight tracker
# ═════════════════════════════════════════════════════════════════════════════

class _AdaptiveWeights:
    """
    Adjust signal weights based on historical prediction accuracy.
    Engines with higher confirmed-fraud hit rate get gradually more weight.
    Uses exponential moving average over a window of confirmed outcomes.
    """

    def __init__(self, base: Dict[str, float], alpha: float = 0.05) -> None:
        self._w     = dict(base)
        self._alpha = alpha              # learning rate
        self._hits  = defaultdict(int)  # engine → correct fraud calls
        self._total = defaultdict(int)  # engine → total confirmed cases

    def update(self, signals: Dict[str, float], confirmed_fraud: bool) -> None:
        threshold = 50.0
        for engine, score in signals.items():
            self._total[engine] += 1
            predicted_fraud = score >= threshold
            if predicted_fraud == confirmed_fraud:
                self._hits[engine] += 1

        # Re-balance weights toward accurate engines every 20 confirmations
        if sum(self._total.values()) % 20 == 0:
            self._rebalance()

    def _rebalance(self) -> None:
        acc = {}
        for eng in self._w:
            t = self._total[eng]
            acc[eng] = self._hits[eng] / t if t > 0 else 0.5

        total_acc = sum(acc.values()) or 1.0
        raw = {eng: acc[eng] / total_acc for eng in self._w}

        # EMA blend with base weights
        base = DEFAULT_WEIGHTS
        for eng in self._w:
            self._w[eng] = (1 - self._alpha) * self._w[eng] + self._alpha * raw.get(eng, base[eng])

        # Normalize to sum to 1.0
        s = sum(self._w.values())
        for eng in self._w:
            self._w[eng] /= s

        logger.debug("[RiskV2] Weights rebalanced: %s", {k: round(v, 3) for k, v in self._w.items()})

    def get(self) -> Dict[str, float]:
        return dict(self._w)


# ═════════════════════════════════════════════════════════════════════════════
# Risk Engine v2
# ═════════════════════════════════════════════════════════════════════════════

class RiskEngineV2:

    def __init__(self) -> None:
        self._weights  = _AdaptiveWeights(DEFAULT_WEIGHTS)
        self._history: deque = deque(maxlen=1000)   # recent decisions
        self._fp_count = 0   # false positives reported
        self._fn_count = 0   # false negatives reported

    # ── Main scoring method ───────────────────────────────────────────────────

    def score(
        self,
        signals: RiskSignals,
        reasons: Optional[List[str]] = None,
        shap_features: Optional[Dict] = None,
        autoencoder_detail: Optional[Dict] = None,
        sequence_detail: Optional[Dict] = None,
    ) -> RiskDecision:
        """
        Combine all engine signals into a final risk score.
        """
        reasons       = reasons       or []
        shap_features = shap_features or {}
        w             = self._weights.get()

        # Build signal dict (clamp each to 0–100)
        raw = {
            "ensemble_ml":   min(100, max(0, signals.ensemble_ml)),
            "autoencoder":   min(100, max(0, signals.autoencoder)),
            "sequence_lstm": min(100, max(0, signals.sequence_lstm)),
            "biometrics":    min(100, max(0, signals.biometrics)),
            "velocity":      min(100, max(0, signals.velocity)),
            "threat_intel":  min(100, max(0, signals.threat_intel * 2)),  # 0–50 → 0–100
            "graph":         min(100, max(0, signals.graph)),
            "device_fp":     min(100, max(0, signals.device_fp)),
        }

        # Weighted sum
        weighted = sum(w.get(k, 0) * v for k, v in raw.items())
        final    = int(round(min(100, max(0, weighted))))

        # Boost for multiple high signals (corroborating evidence)
        high_signals = sum(1 for v in raw.values() if v >= 60)
        if high_signals >= 3:
            final = min(100, final + 8)
            reasons.append(f"[Risk] {high_signals} engines independently flagged high risk")

        band       = _band(final)
        action     = _action(band)
        confidence = self._confidence(raw, final)

        # Generate reason summaries
        for eng, score_val in sorted(raw.items(), key=lambda x: -x[1]):
            if score_val >= 50:
                reasons.append(f"[{eng.replace('_',' ').title()}] score {score_val:.0f}/100")

        decision = RiskDecision(
            final_score   = final,
            band          = band,
            action        = action,
            confidence    = confidence,
            signals       = {k: round(v, 1) for k, v in raw.items()},
            reasons       = list(dict.fromkeys(reasons)),   # deduplicate
            shap_features = shap_features,
            autoencoder   = autoencoder_detail or {},
            sequence      = sequence_detail     or {},
        )
        self._history.append({
            "score": final, "band": band, "ts": decision.timestamp,
            "signals": raw,
        })
        return decision

    # ── Confidence ─────────────────────────────────────────────────────────────

    def _confidence(self, raw: Dict[str, float], final: int) -> str:
        """High confidence when multiple signals agree."""
        values      = list(raw.values())
        agreement   = statistics.stdev(values) if len(values) > 1 else 50
        # Low std-dev = signals agree = high confidence
        if agreement < 15:  return "high"
        if agreement < 30:  return "medium"
        return "low"

    # ── Adaptive feedback ─────────────────────────────────────────────────────

    def report_outcome(self, signals: Dict[str, float], was_fraud: bool) -> None:
        """Called by the feedback engine after analyst confirmation."""
        self._weights.update(signals, was_fraud)
        if not was_fraud:
            self._fp_count += 1
        else:
            self._fn_count += 1

    # ── Summaries ─────────────────────────────────────────────────────────────

    def stats(self) -> Dict:
        if not self._history:
            return {"total_scored": 0}
        scores = [h["score"] for h in self._history]
        bands  = defaultdict(int)
        for h in self._history:
            bands[h["band"]] += 1
        return {
            "total_scored":        len(self._history),
            "avg_score":           round(statistics.mean(scores), 1),
            "max_score":           max(scores),
            "band_distribution":   dict(bands),
            "false_positives_reported": self._fp_count,
            "false_negatives_reported": self._fn_count,
            "current_weights":     {k: round(v, 3) for k, v in self._weights.get().items()},
        }

    def weight_summary(self) -> Dict:
        return {k: round(v, 3) for k, v in self._weights.get().items()}


# ── Singleton ──────────────────────────────────────────────────────────────────
risk_engine_v2 = RiskEngineV2()
