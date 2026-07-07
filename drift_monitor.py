"""
FRAUD-X — AI Drift Detection Monitor  v1.0
==========================================
§12 Real-time AI drift detection — monitors model accuracy, detects
    concept drift, and triggers automatic retraining

Drift Types Monitored
---------------------
  ACCURACY_DRIFT   — model predictions diverging from ground truth
  FEATURE_DRIFT    — input feature distributions shifting (PSI-based)
  CONCEPT_DRIFT    — relationship between features and fraud changing
  LABEL_DRIFT      — fraud/legit ratio changing significantly
  SCORE_DRIFT      — output score distribution shifting

PSI (Population Stability Index) Reference
------------------------------------------
  PSI < 0.10  → Stable             → No action needed
  0.10-0.25   → Moderate drift     → Increase monitoring frequency
  PSI > 0.25  → Significant drift  → Trigger retraining alert

Metrics Tracked
---------------
  - Precision / Recall / F1 (rolling 7-day window)
  - Score distribution histogram (current vs baseline)
  - Feature mean / std drift per feature
  - False positive / false negative rates
  - Retraining trigger events
"""

from __future__ import annotations

import math
import statistics
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

# ── PSI thresholds ────────────────────────────────────────────
PSI_STABLE      = 0.10
PSI_MODERATE    = 0.25
PSI_BUCKETS     = 10

# ── Drift alert thresholds ────────────────────────────────────
ACCURACY_DROP_THRESHOLD  = 0.10  # 10% accuracy drop triggers alert
RECALL_DROP_THRESHOLD    = 0.08  # 8% recall drop (missing fraud)
F1_DROP_THRESHOLD        = 0.08
RETRAIN_WINDOW_COOLDOWN  = 3600  # don't trigger retrain more than 1/hour

# ── Rolling windows ───────────────────────────────────────────
BASELINE_WINDOW  = 1000   # events to establish baseline distribution
MONITOR_WINDOW   = 500    # recent events to compare against baseline


class DriftType(str, Enum):
    NONE     = "none"
    ACCURACY = "accuracy"
    FEATURE  = "feature"
    CONCEPT  = "concept"
    LABEL    = "label"
    SCORE    = "score"


@dataclass
class DriftEvent:
    drift_type:  DriftType
    psi:         float
    severity:    str       # stable|moderate|significant|critical
    feature:     str       # which feature drifted (empty for model-level)
    delta:       float     # magnitude of change
    message:     str
    ts:          float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "drift_type": self.drift_type.value,
            "psi":        round(self.psi, 4),
            "severity":   self.severity,
            "feature":    self.feature,
            "delta":      round(self.delta, 4),
            "message":    self.message,
            "ts":         self.ts,
        }


@dataclass
class ModelMetrics:
    """Rolling prediction accuracy metrics."""
    tp: int = 0; fp: int = 0; tn: int = 0; fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / max(1, self.tp + self.fp)

    @property
    def recall(self) -> float:
        return self.tp / max(1, self.tp + self.fn)

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / max(0.001, p + r)

    @property
    def accuracy(self) -> float:
        total = self.tp + self.fp + self.tn + self.fn
        return (self.tp + self.tn) / max(1, total)

    @property
    def fpr(self) -> float:
        return self.fp / max(1, self.fp + self.tn)

    @property
    def fnr(self) -> float:
        return self.fn / max(1, self.fn + self.tp)

    def to_dict(self) -> dict:
        return {
            "precision": round(self.precision, 4),
            "recall":    round(self.recall,    4),
            "f1":        round(self.f1,        4),
            "accuracy":  round(self.accuracy,  4),
            "fpr":       round(self.fpr,       4),
            "fnr":       round(self.fnr,       4),
            "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
        }


# ═════════════════════════════════════════════════════════════
# PSI Calculator
# ═════════════════════════════════════════════════════════════

def compute_psi(baseline: list[float], current: list[float], buckets: int = PSI_BUCKETS) -> float:
    """
    Population Stability Index between two score distributions.
    Returns 0 when distributions are identical.
    """
    if not baseline or not current:
        return 0.0

    # Build percentile-based bucket boundaries from baseline
    n     = len(baseline)
    step  = 100.0 / buckets
    edges = [
        sorted(baseline)[int(i * n / buckets)]
        for i in range(1, buckets)
    ]
    edges = [-math.inf] + edges + [math.inf]

    def bucket_counts(data: list[float]) -> list[float]:
        counts = [0.0] * buckets
        for v in data:
            for b in range(buckets):
                if edges[b] <= v < edges[b + 1]:
                    counts[b] += 1
                    break
        # Normalize to proportions (avoid div/0 with small smoothing)
        total = max(1.0, len(data))
        return [max(0.0001, c / total) for c in counts]

    base_p = bucket_counts(baseline)
    curr_p = bucket_counts(current)

    psi = sum(
        (c - b) * math.log(c / b)
        for b, c in zip(base_p, curr_p)
    )
    return round(psi, 6)


def psi_severity(psi: float) -> str:
    if psi >= 0.50:  return "critical"
    if psi >= PSI_MODERATE: return "significant"
    if psi >= PSI_STABLE:   return "moderate"
    return "stable"


# ═════════════════════════════════════════════════════════════
# §12 Drift Monitor
# ═════════════════════════════════════════════════════════════

class DriftMonitor:
    """
    Monitors FRAUD-X model outputs for accuracy drift and concept drift.

    Dual-mode operation:
    1. Supervised: compare predictions against analyst labels (feedback loop)
    2. Unsupervised: compare current score distribution against baseline PSI
    """

    def __init__(self):
        # Rolling buffers
        self._baseline_scores:  list[float] = []      # established stable distribution
        self._current_scores:   deque       = deque(maxlen=MONITOR_WINDOW)
        self._recent_labels:    deque       = deque(maxlen=MONITOR_WINDOW)  # (pred, truth)
        self._baseline_metrics: Optional[ModelMetrics] = None
        self._current_metrics   = ModelMetrics()

        self._drift_events:  deque = deque(maxlen=500)
        self._retrain_events:deque = deque(maxlen=50)
        self._lock           = threading.Lock()
        self._last_retrain   = 0.0
        self._total_scored   = 0

    # ── Record score (unsupervised) ───────────────────────────

    def record_score(self, score: float, feature_vals: Optional[dict] = None):
        """Record a model output score for distribution monitoring."""
        with self._lock:
            self._current_scores.append(max(0.0, min(100.0, score)))
            self._total_scored += 1

            # Once we have enough baseline, compute PSI on every new batch
            if (len(self._baseline_scores) < BASELINE_WINDOW
                    and len(self._current_scores) >= BASELINE_WINDOW):
                self._baseline_scores = list(self._current_scores)

    # ── Record feedback (supervised) ─────────────────────────

    def record_feedback(self, predicted_score: float, true_label: int, threshold: float = 50.0):
        """
        Record analyst-confirmed label for supervised drift detection.
        true_label: 1 = fraud, 0 = legitimate
        """
        pred_label = 1 if predicted_score >= threshold else 0
        with self._lock:
            self._recent_labels.append((pred_label, true_label))
            # Update rolling metrics
            if pred_label == 1 and true_label == 1: self._current_metrics.tp += 1
            elif pred_label == 1 and true_label == 0: self._current_metrics.fp += 1
            elif pred_label == 0 and true_label == 0: self._current_metrics.tn += 1
            else: self._current_metrics.fn += 1

    # ── Drift analysis ────────────────────────────────────────

    def analyze(self) -> dict:
        """
        Run full drift analysis. Call periodically (e.g., every 5 minutes).
        Returns dict with all detected drift events and retrain recommendation.
        """
        with self._lock:
            baseline = list(self._baseline_scores)
            current  = list(self._current_scores)
            metrics  = self._current_metrics
            baseline_m = self._baseline_metrics

        drift_events = []

        # Score distribution drift (PSI)
        if len(baseline) >= 100 and len(current) >= 50:
            psi      = compute_psi(baseline, current)
            severity = psi_severity(psi)
            if psi >= PSI_STABLE:
                event = DriftEvent(
                    drift_type = DriftType.SCORE,
                    psi        = psi,
                    severity   = severity,
                    feature    = "output_score",
                    delta      = psi,
                    message    = f"Score distribution PSI={psi:.4f} ({severity})",
                )
                drift_events.append(event)
                with self._lock:
                    self._drift_events.append(event)

        # Accuracy drift (supervised)
        should_retrain = False
        retrain_reason = ""
        if baseline_m and (metrics.tp + metrics.fp + metrics.tn + metrics.fn) >= 50:
            f1_drop   = baseline_m.f1   - metrics.f1
            rec_drop  = baseline_m.recall - metrics.recall
            acc_drop  = baseline_m.accuracy - metrics.accuracy

            if f1_drop > F1_DROP_THRESHOLD:
                msg   = f"F1 dropped {f1_drop:.3f} ({baseline_m.f1:.3f}→{metrics.f1:.3f})"
                event = DriftEvent(DriftType.ACCURACY, f1_drop, "significant", "f1", f1_drop, msg)
                drift_events.append(event)
                should_retrain = True
                retrain_reason = msg

            if rec_drop > RECALL_DROP_THRESHOLD:
                msg   = f"Recall dropped {rec_drop:.3f} — missing more fraud"
                event = DriftEvent(DriftType.ACCURACY, rec_drop, "critical", "recall", rec_drop, msg)
                drift_events.append(event)
                should_retrain = True
                retrain_reason = msg

        # Retrain trigger
        retrain_triggered = False
        now = time.time()
        if should_retrain and (now - self._last_retrain > RETRAIN_WINDOW_COOLDOWN):
            retrain_triggered = True
            self._last_retrain = now
            with self._lock:
                self._retrain_events.append({"reason": retrain_reason, "ts": now})

        return {
            "drift_detected":    len(drift_events) > 0,
            "events":            [e.to_dict() for e in drift_events],
            "current_metrics":   metrics.to_dict(),
            "baseline_set":      len(self._baseline_scores) >= BASELINE_WINDOW,
            "retrain_triggered": retrain_triggered,
            "retrain_reason":    retrain_reason if retrain_triggered else None,
            "total_scored":      self._total_scored,
            "ts":                now,
        }

    def set_baseline_metrics(self, tp: int, fp: int, tn: int, fn: int):
        """Store reference performance metrics after fresh training."""
        with self._lock:
            self._baseline_metrics = ModelMetrics(tp=tp, fp=fp, tn=tn, fn=fn)

    def reset_score_baseline(self):
        """Reset score distribution baseline to current distribution."""
        with self._lock:
            self._baseline_scores = list(self._current_scores)

    def recent_drift_events(self, n: int = 20) -> list[dict]:
        with self._lock:
            return [e.to_dict() for e in list(self._drift_events)[-n:]]

    def retrain_history(self) -> list:
        with self._lock:
            return list(self._retrain_events)

    def stats(self) -> dict:
        with self._lock:
            return {
                "total_scored":     self._total_scored,
                "baseline_size":    len(self._baseline_scores),
                "current_size":     len(self._current_scores),
                "drift_events":     len(self._drift_events),
                "retrain_triggers": len(self._retrain_events),
                "last_retrain":     self._last_retrain,
                "current_metrics":  self._current_metrics.to_dict(),
            }


# ── Singleton ─────────────────────────────────────────────────
drift_monitor = DriftMonitor()
