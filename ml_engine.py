"""
FRAUD-X  ·  ML Engine
Pure-Python statistical fraud scoring — no heavy ML dependencies.

Techniques:
  • Bayesian prior updates per scan type
  • Multi-signal confidence calibration
  • Feature-weighted score adjustment
  • Structured XAI (Explainable AI) output
"""
from __future__ import annotations

import math
from typing import Dict, List, Optional, Tuple


class FraudMLEngine:
    """Lightweight statistical scoring engine."""

    # Base fraud-rate priors (probability that a scan of this type is fraud)
    _PRIORS: Dict[str, float] = {
        "url":      0.18,
        "email":    0.22,
        "phone":    0.18,
        "sms":      0.24,
        "file":     0.12,
        "merchant": 0.16,
        "social":   0.26,
        "qr":       0.20,
        "ip":       0.10,
        "crypto":   0.32,
    }

    # Per-signal category severity weights (used in XAI tagging)
    _CRITICAL_KEYWORDS = frozenset([
        "homograph", "malware", "hash matches", "dangerous destination",
        "dga characteristics", "double extension", "vba macro",
        "header injection", "seed phrase", "private key",
    ])
    _HIGH_KEYWORDS = frozenset([
        "impersonat", "phishing", "scam", "spoofing", "danger",
        "brand", "typosquat", "leet", "mixer", "tumbler",
    ])
    _MEDIUM_KEYWORDS = frozenset([
        "suspicious", "unusual", "risk", "unverified", "caution",
        "shortener", "redirect", "entropy", "repetitive",
    ])

    def __init__(self) -> None:
        # Mutable per-instance priors (updated via feedback)
        self._priors = dict(self._PRIORS)

    # ── Score calibration ────────────────────────────────────────

    def calibrate(
        self,
        raw_score: int,
        scan_type: str,
        reasons: List[str],
    ) -> Tuple[int, str]:
        """
        Apply statistical calibration to a raw heuristic score.
        Returns (calibrated_score, calibration_note).
        """
        positive = [r for r in reasons if not r.startswith("No ") and "whitelist" not in r.lower()]
        n = len(positive)

        # Multi-signal convergence boost
        if n >= 5:
            adj, note = +10, f"Strong convergence: {n} independent fraud signals — high confidence."
        elif n >= 3:
            adj, note = +5, f"Moderate convergence: {n} corroborating signals."
        elif n == 2:
            adj, note = +2, "Two signals detected — moderate confidence."
        elif n == 1:
            adj, note = 0, "Single signal — low confidence. Treat as indicative only."
        else:
            adj, note = -5, "No strong signals detected — score reduced to minimise false positives."

        # Trust-domain false-positive suppression
        if any("whitelist" in r.lower() for r in reasons) and raw_score < 35:
            adj -= 10
            note = "Trusted domain on whitelist — score reduced to limit false positives."

        # Prior-based modifier: rare fraud types penalised less
        prior = self._priors.get(scan_type, 0.15)
        if prior < 0.12 and raw_score < 40:
            adj -= 3

        calibrated = max(0, min(100, raw_score + adj))
        return calibrated, note

    # ── Confidence ───────────────────────────────────────────────

    def confidence(self, score: int, reasons: List[str]) -> str:
        positive = sum(1 for r in reasons if not r.startswith("No "))
        if positive >= 4 and score >= 65:
            return "high"
        if positive >= 2 and score >= 30:
            return "medium"
        return "low"

    # ── XAI structured explanation ────────────────────────────────

    def explain(
        self,
        score: int,
        level: str,
        reasons: List[str],
        scan_type: str,
    ) -> Dict:
        """
        Build a structured Explainable-AI output object.
        Groups signals by severity and identifies the primary threat.
        """
        buckets: Dict[str, List[str]] = {
            "critical": [], "high": [], "medium": [], "low": [], "informational": [],
        }

        for r in reasons:
            r_low = r.lower()
            if r.startswith("No ") or "whitelist" in r_low:
                buckets["informational"].append(r)
            elif any(kw in r_low for kw in self._CRITICAL_KEYWORDS):
                buckets["critical"].append(r)
            elif any(kw in r_low for kw in self._HIGH_KEYWORDS):
                buckets["high"].append(r)
            elif any(kw in r_low for kw in self._MEDIUM_KEYWORDS):
                buckets["medium"].append(r)
            else:
                buckets["low"].append(r)

        primary = (
            buckets["critical"][0] if buckets["critical"] else
            buckets["high"][0] if buckets["high"] else
            None
        )
        signal_count = sum(1 for r in reasons if not r.startswith("No "))

        return {
            "score": score,
            "level": level,
            "confidence": self.confidence(score, reasons),
            "signal_count": signal_count,
            "primary_threat": primary,
            "categories": {k: v for k, v in buckets.items() if v},
            "fraud_type_prior": round(self._priors.get(scan_type, 0.15) * 100, 1),
        }

    # ── Adaptive prior update ─────────────────────────────────────

    def update_prior(self, scan_type: str, confirmed_fraud: bool) -> None:
        """Exponential-moving-average update when outcome is known."""
        cur = self._priors.get(scan_type, 0.15)
        self._priors[scan_type] = 0.92 * cur + 0.08 * (1.0 if confirmed_fraud else 0.0)

    # ── Feature vector (for future model export) ──────────────────

    def feature_vector(
        self,
        scan_type: str,
        target: str,
        reasons: List[str],
        score: int,
    ) -> Dict[str, float]:
        pos = [r for r in reasons if not r.startswith("No ")]
        return {
            "score_norm":     score / 100.0,
            "reason_count":   min(len(reasons) / 10.0, 1.0),
            "positive_sigs":  min(len(pos) / 10.0, 1.0),
            "has_ai_signal":  float(any("[AI]" in r for r in reasons)),
            "has_behavioral": float(any("[Behavioral]" in r for r in reasons)),
            "has_graph":      float(any("[Graph]" in r for r in reasons)),
            "target_len":     min(len(target) / 200.0, 1.0),
            "prior":          self._priors.get(scan_type, 0.15),
        }


# Singleton
ml_engine = FraudMLEngine()
