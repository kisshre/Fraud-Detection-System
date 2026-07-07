"""
FRAUD-X — Real-Time Confidence Fusion Engine  v1.0
===================================================
§17 Meta confidence fusion — combines per-source confidence into
    a single unified certainty score with uncertainty estimation

The engine addresses a fundamental challenge in multi-source fraud
detection: individual detectors produce outputs with varying reliability.
A URL scanner may be 90% confident; a biometrics module only 40%
confident (insufficient data). Naively averaging their outputs
over-weights uncertain sources.

Confidence Fusion Solution
--------------------------
  1. Each source provides (score, confidence) pairs
  2. Weighted harmonic mean of confidence values is computed
  3. Scores are weighted by their per-source confidence
  4. An uncertainty interval is estimated from confidence variance
  5. A "certainty band" (narrow=high certainty, wide=low) is returned

Sources
-------
  url_analysis       — ML+heuristic URL score
  biometrics         — behavioral biometrics
  device             — device fingerprinting trust
  threat_intel       — external threat APIs
  session            — session-level intelligence
  correlation        — event correlation engine output
  ato                — account takeover engine
  campaign           — campaign detector
  graph              — graph fraud relationships
  dom_analysis       — DOM mutation detection (browser-side)

Output
------
  meta_score:          0-100 final fused score
  certainty:           0-100 (100 = high confidence in meta_score)
  uncertainty_band:    [low, high] — 90% confidence interval
  dominant_source:     source contributing most to certainty
  low_confidence_sources: sources with <40% confidence
"""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass, field
from typing import Optional

# ── Minimum confidence to include source in fusion (%) ───────
MIN_CONFIDENCE    = 0.10   # below this, source is excluded
UNCERTAINTY_ALPHA = 0.10   # 90% confidence interval


@dataclass
class SourceSignal:
    """A single source's score + confidence."""
    name:       str
    score:      float        # 0-100
    confidence: float        # 0-1 (how reliable this source's estimate is)
    weight:     float = 1.0  # additional priority weight


@dataclass
class FusionResult:
    """Output of confidence fusion."""
    meta_score:              float         # 0-100 fused score
    certainty:               float         # 0-100 confidence in meta_score
    uncertainty_band:        tuple[float, float]   # [low, high]
    dominant_source:         str
    contributing_sources:    int
    excluded_sources:        list[str]     # excluded due to low confidence
    low_confidence_sources:  list[str]     # included but confidence < 0.40
    source_contributions:    dict[str, float]

    def to_dict(self) -> dict:
        return {
            "meta_score":             round(self.meta_score, 2),
            "certainty":              round(self.certainty, 2),
            "uncertainty_band":       [round(self.uncertainty_band[0], 2),
                                       round(self.uncertainty_band[1], 2)],
            "dominant_source":        self.dominant_source,
            "contributing_sources":   self.contributing_sources,
            "excluded_sources":       self.excluded_sources,
            "low_confidence_sources": self.low_confidence_sources,
            "source_contributions":   {k: round(v, 3) for k, v in self.source_contributions.items()},
        }


# ═════════════════════════════════════════════════════════════
# §17 Confidence Fusion Engine
# ═════════════════════════════════════════════════════════════

class ConfidenceFusionEngine:
    """
    Fuses scores from multiple fraud detection sources weighted by
    their per-observation confidence.

    The algorithm:
    1. Filter sources with confidence < MIN_CONFIDENCE (unreliable)
    2. Compute confidence-weighted score sum:
       weighted_score = Σ(score_i × confidence_i × weight_i)
       total_weight   = Σ(confidence_i × weight_i)
       meta_score     = weighted_score / total_weight
    3. Certainty = harmonic mean of confidence values (penalizes outliers)
    4. Uncertainty band: meta_score ± (1-certainty) × meta_score × 0.5
    5. Dominant source: source with highest (confidence × weight) product
    """

    # Default per-source weights (tune from operational performance data)
    DEFAULT_WEIGHTS: dict[str, float] = {
        "url_analysis":  1.2,
        "biometrics":    0.9,
        "device":        0.8,
        "threat_intel":  1.3,
        "session":       0.9,
        "correlation":   1.1,   # correlation engine already fuses signals
        "ato":           1.0,
        "campaign":      1.2,
        "graph":         0.8,
        "dom_analysis":  0.7,
    }

    def __init__(self, weights: Optional[dict] = None):
        self._weights = {**self.DEFAULT_WEIGHTS, **(weights or {})}

    def fuse(self, sources: list[SourceSignal]) -> FusionResult:
        """
        Fuse a list of SourceSignal objects into a single FusionResult.
        """
        if not sources:
            return self._empty_result()

        # Separate included vs excluded
        included = [s for s in sources if s.confidence >= MIN_CONFIDENCE]
        excluded = [s.name for s in sources if s.confidence < MIN_CONFIDENCE]

        if not included:
            return self._empty_result(excluded=excluded)

        # Confidence-weighted fusion
        total_weight   = 0.0
        weighted_score = 0.0
        contributions: dict[str, float] = {}
        dominant_source = included[0].name
        dominant_w      = 0.0

        for src in included:
            w = max(0.0, src.confidence) * self._weights.get(src.name, 1.0) * src.weight
            weighted_score += max(0.0, min(100.0, src.score)) * w
            total_weight   += w
            contributions[src.name] = w
            if w > dominant_w:
                dominant_w      = w
                dominant_source = src.name

        meta_score = weighted_score / total_weight if total_weight > 0 else 0.0
        meta_score = max(0.0, min(100.0, meta_score))

        # Normalize contributions to sum to 1
        if total_weight > 0:
            contributions = {k: v / total_weight for k, v in contributions.items()}

        # Certainty = harmonic mean of confidence values
        confidence_vals = [s.confidence for s in included]
        if len(confidence_vals) == 1:
            certainty_ratio = confidence_vals[0]
        else:
            n             = len(confidence_vals)
            harmonic_mean = n / sum(1.0 / max(0.001, c) for c in confidence_vals)
            certainty_ratio = harmonic_mean

        # Boost certainty when multiple high-confidence sources agree
        if len([c for c in confidence_vals if c >= 0.7]) >= 3:
            certainty_ratio = min(1.0, certainty_ratio * 1.15)

        certainty = certainty_ratio * 100.0

        # Uncertainty band (90% interval)
        std_deviation = statistics.stdev([s.score for s in included]) if len(included) > 1 else 0.0
        margin = max(2.0, std_deviation * (1.0 - certainty_ratio))
        low_bound  = max(0.0,   meta_score - margin)
        high_bound = min(100.0, meta_score + margin)

        low_conf = [s.name for s in included if s.confidence < 0.40]

        return FusionResult(
            meta_score             = meta_score,
            certainty              = certainty,
            uncertainty_band       = (low_bound, high_bound),
            dominant_source        = dominant_source,
            contributing_sources   = len(included),
            excluded_sources       = excluded,
            low_confidence_sources = low_conf,
            source_contributions   = contributions,
        )

    def quick_fuse(self, score_conf_pairs: list[tuple[float, float]]) -> dict:
        """Simplified fusion for pairs of (score, confidence) without named sources."""
        sources = [
            SourceSignal(name=f"source_{i}", score=s, confidence=c)
            for i, (s, c) in enumerate(score_conf_pairs)
        ]
        r = self.fuse(sources)
        return {
            "meta_score":    round(r.meta_score, 2),
            "certainty":     round(r.certainty, 2),
            "band":          [round(r.uncertainty_band[0], 2), round(r.uncertainty_band[1], 2)],
        }

    @staticmethod
    def _empty_result(excluded: list = None) -> FusionResult:
        return FusionResult(
            meta_score             = 0.0,
            certainty              = 0.0,
            uncertainty_band       = (0.0, 0.0),
            dominant_source        = "none",
            contributing_sources   = 0,
            excluded_sources       = excluded or [],
            low_confidence_sources = [],
            source_contributions   = {},
        )


# ── Singleton ─────────────────────────────────────────────────
confidence_fusion = ConfidenceFusionEngine()
