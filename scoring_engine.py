"""
FRAUD-X  ·  Adaptive Scoring Engine
=====================================
Three interlocking layers:

  1. DynamicThresholds   — danger/caution thresholds that drift per scan type
                           based on observed fraud rates (EMA updates each scan)

  2. WeightedCalibrator  — signal-type-aware convergence adjustment
                           [ML] / [AI] / [Graph] / [Behavioral] signals carry
                           higher weight than plain heuristic signals

  3. ContextAwareScorer  — cross-entity session correlation
                           URL + crypto + SMS all suspicious in same 10-min
                           window → each gets a "multi-vector campaign" boost

Public API (via scoring_engine singleton)
-----------------------------------------
  scoring_engine.calibrate(score, kind, reasons)  → (int, str)
  scoring_engine.context_adjust(kind, target, score, reasons) → (int, List[str])
  scoring_engine.level_for(score, kind)  → "danger" | "caution" | "safe"
  scoring_engine.record(kind, target, score)       [call inside record_alert()]
  scoring_engine.thresholds_summary()    → Dict
"""
from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse


# ── Constants ────────────────────────────────────────────────────
_SESSION_WINDOW_SEC  = 600   # 10-minute cross-entity window
_SESSION_HIGH_FLOOR  = 50    # score ≥ this counts as "high-risk" for context
_THRESHOLD_MAX_DRIFT = 10    # how many points the threshold can drift from base
_EMA_ALPHA           = 0.06  # how quickly thresholds adapt (higher = faster)
_MIN_SCANS_TO_ADAPT  = 20    # don't adapt until we have enough observations


def _domain_from(kind: str, target: str) -> Optional[str]:
    """Best-effort domain extraction from any scan target."""
    try:
        if kind in ("url", "qr"):
            return (urlparse(target).hostname or "").lower() or None
        if kind == "email" and "@" in target:
            return target.split("@")[-1].lower()
        if kind == "sms":
            for token in target.split():
                h = urlparse(token).hostname
                if h:
                    return h.lower()
        if kind == "domain":
            return target.lower()
    except Exception:
        pass
    return None


# ══════════════════════════════════════════════════════════════════
# ①  Dynamic per-kind thresholds
# ══════════════════════════════════════════════════════════════════

class DynamicThresholds:
    """
    Per-kind danger/caution thresholds that drift based on observed fraud rates.

    Logic
    -----
    - We keep an EMA of "is_fraud" (1.0 if score ≥ base_danger, else 0.0) per kind.
    - If the observed fraud rate is HIGHER than the type's baseline prior
      → threshold drifts DOWN (more sensitive; less likely to miss real fraud).
    - If the observed fraud rate is LOWER than expected
      → threshold drifts UP slightly (fewer false positives).
    - Drift is capped at ±_THRESHOLD_MAX_DRIFT points from the base.
    - No adaptation until ≥ _MIN_SCANS_TO_ADAPT observations.

    Type-specific bases reflect intrinsic risk differences:
      crypto/social score naturally higher → lower base thresholds
      file/ip rarely score high → higher caution threshold
    """

    _BASE: Dict[str, Tuple[int, int]] = {
        #  kind         (danger, caution)
        "url":          (65, 30),
        "email":        (65, 30),
        "phone":        (60, 28),
        "sms":          (65, 30),
        "file":         (60, 28),
        "merchant":     (60, 25),
        "social":       (55, 25),
        "qr":           (65, 30),
        "ip":           (60, 28),
        "crypto":       (55, 25),
    }

    # Expected baseline fraud rates (from domain knowledge / Bayesian priors)
    _PRIOR_FRAUD_RATE: Dict[str, float] = {
        "url": 0.18, "email": 0.22, "phone": 0.18, "sms": 0.24,
        "file": 0.12, "merchant": 0.16, "social": 0.26,
        "qr": 0.20, "ip": 0.10, "crypto": 0.32,
    }

    def __init__(self) -> None:
        self._ema: Dict[str, float] = {}       # current observed fraud-rate EMA
        self._count: Dict[str, int] = defaultdict(int)

    def record(self, kind: str, score: int) -> None:
        """Update EMA after each scan."""
        base_danger, _ = self._BASE.get(kind, (65, 30))
        is_fraud = 1.0 if score >= base_danger else 0.0
        cur = self._ema.get(kind, self._PRIOR_FRAUD_RATE.get(kind, 0.18))
        self._ema[kind] = (1 - _EMA_ALPHA) * cur + _EMA_ALPHA * is_fraud
        self._count[kind] += 1

    def get(self, kind: str) -> Tuple[int, int]:
        """Return (danger_threshold, caution_threshold) for this kind."""
        base_danger, base_caution = self._BASE.get(kind, (65, 30))

        if self._count.get(kind, 0) < _MIN_SCANS_TO_ADAPT:
            return base_danger, base_caution

        observed  = self._ema.get(kind, self._PRIOR_FRAUD_RATE.get(kind, 0.18))
        expected  = self._PRIOR_FRAUD_RATE.get(kind, 0.18)
        rate_diff = observed - expected          # positive → more fraud than expected

        # Positive rate_diff → drift danger threshold DOWN (catch more)
        # Negative rate_diff → drift UP (reduce FP when things look quiet)
        drift = int(-rate_diff * 40)
        drift = max(-_THRESHOLD_MAX_DRIFT, min(_THRESHOLD_MAX_DRIFT, drift))

        danger  = max(45, min(85, base_danger  + drift))
        caution = max(15, min(45, base_caution + drift // 2))
        return danger, caution

    def summary(self) -> Dict:
        result = {}
        for kind, (bd, bc) in self._BASE.items():
            d, c  = self.get(kind)
            obs   = self._ema.get(kind, self._PRIOR_FRAUD_RATE.get(kind, 0.18))
            result[kind] = {
                "danger_threshold":  d,
                "caution_threshold": c,
                "base_danger":       bd,
                "base_caution":      bc,
                "drift":             d - bd,
                "observed_fraud_rate_pct": round(obs * 100, 1),
                "expected_fraud_rate_pct": round(self._PRIOR_FRAUD_RATE.get(kind, 0.18) * 100, 1),
                "scan_count": self._count.get(kind, 0),
                "adapted":    self._count.get(kind, 0) >= _MIN_SCANS_TO_ADAPT,
            }
        return result


# ══════════════════════════════════════════════════════════════════
# ②  Weighted signal calibration
# ══════════════════════════════════════════════════════════════════

class WeightedCalibrator:
    """
    Replaces the basic signal-count convergence in ml_engine.calibrate().

    Instead of counting signals 1-for-1, each signal gets a weight based on
    its source prefix and keyword severity.  A single [ML]+[Graph] combo can
    carry the same weight as 3+ plain heuristic signals.

    Signal-type weights (prefix-based, case-insensitive):
      [ml]          1.6  — independent Random Forest probability
      [ai]          1.4  — Claude semantic analysis
      [graph]       1.3  — network guilt-by-association
      [behavioral]  1.35 — anomaly from behavioral engine
      [context]     1.3  — cross-entity session correlation
      (plain)       1.0  — standard heuristic rule

    Keyword severity multiplier (applied after prefix weight):
      critical KW   ×1.5   (homograph, malware hash, DGA, header injection …)
      high KW       ×1.25  (phishing, scam, spoofing, brand, typosquat …)
      (default)     ×1.0

    Informational / whitelist signals: 0.3 each (barely counted)
    """

    _PREFIX_WEIGHTS: Dict[str, float] = {
        "[ml]":          1.6,
        "[ai]":          1.4,
        "[graph]":       1.3,
        "[behavioral]":  1.35,
        "[context]":     1.3,
        "[campaign]":    1.2,
    }

    _CRITICAL_KW = frozenset([
        "homograph", "malware", "hash match", "dga", "double extension",
        "vba macro", "header injection", "seed phrase", "private key",
        "dangerous destination", "exec", "shellcode",
    ])
    _HIGH_KW = frozenset([
        "phish", "scam", "spoof", "impersonat", "typosquat", "leet",
        "brand", "mixer", "tumbler", "ransomware", "exploit",
    ])

    def calibrate(
        self, raw_score: int, scan_type: str, reasons: List[str]
    ) -> Tuple[int, str]:
        """
        Returns (calibrated_score, calibration_note).
        """
        weighted_sum = 0.0
        for r in reasons:
            r_low = r.lower()

            # Informational / whitelist — minimal weight
            if r.startswith("No ") or "whitelist" in r_low or r.startswith("Address validates"):
                weighted_sum += 0.3
                continue

            # Base weight from signal-type prefix
            base_w = 1.0
            for prefix, w in self._PREFIX_WEIGHTS.items():
                if r_low.startswith(prefix):
                    base_w = w
                    break

            # Severity multiplier from keyword content
            if any(kw in r_low for kw in self._CRITICAL_KW):
                base_w *= 1.5
            elif any(kw in r_low for kw in self._HIGH_KW):
                base_w *= 1.25

            weighted_sum += base_w

        # Map weighted sum → adjustment
        if weighted_sum >= 8.0:
            adj, note_tag = +12, f"Very strong convergence (weighted={weighted_sum:.1f})"
        elif weighted_sum >= 5.5:
            adj, note_tag = +8,  f"Strong convergence (weighted={weighted_sum:.1f})"
        elif weighted_sum >= 3.5:
            adj, note_tag = +5,  f"Moderate convergence (weighted={weighted_sum:.1f})"
        elif weighted_sum >= 2.0:
            adj, note_tag = +2,  f"Weak convergence (weighted={weighted_sum:.1f})"
        elif weighted_sum >= 1.0:
            adj, note_tag = 0,   f"Single signal (weighted={weighted_sum:.1f})"
        else:
            adj, note_tag = -5,  "No positive signals — score reduced to limit false positives."

        # Trusted-domain false-positive suppression
        if any("whitelist" in r.lower() for r in reasons) and raw_score < 35:
            adj = min(adj, -8)
            note_tag = "Trusted domain — score suppressed."

        calibrated = max(0, min(100, raw_score + adj))
        return calibrated, f"{note_tag} → adjustment {adj:+d}"


# ══════════════════════════════════════════════════════════════════
# ③  Context-aware cross-entity scoring
# ══════════════════════════════════════════════════════════════════

class ContextAwareScorer:
    """
    Tracks scan results in a rolling 10-minute session window.
    When multiple distinct scan types all flag high-risk, each subsequent
    scan gets a corroboration boost — "multi-vector fraud campaign" signal.

    Cross-entity boosts
    -------------------
    3+ distinct kinds high-risk in window  → +15  multi-vector campaign
    2   distinct kinds high-risk           → +8   cross-entity corroboration
    Same domain seen in other kind scans   → +10  same-actor domain reuse
    Same target scanned in 2+ kinds        → +6   entity overlap
    """

    def __init__(self) -> None:
        # (ts, kind, target, score, domain)
        self._session: deque = deque(maxlen=500)

    def record(self, kind: str, target: str, score: int) -> None:
        domain = _domain_from(kind, target)
        self._session.appendleft((time.time(), kind, target, score, domain))

    def adjust(
        self, kind: str, target: str, score: int, reasons: List[str]
    ) -> Tuple[int, List[str]]:
        """
        Returns (score_adjustment, context_signals).
        Call BEFORE recording the current scan.
        """
        now    = time.time()
        window = [e for e in self._session if now - e[0] < _SESSION_WINDOW_SEC]
        if not window:
            return 0, []

        current_domain = _domain_from(kind, target)
        signals: List[str] = []
        adj = 0

        # ── High-risk entries from OTHER scan types ───────────────
        other_entries = [
            (k, tgt, sc, dom)
            for (ts, k, tgt, sc, dom) in window
            if k != kind and sc >= _SESSION_HIGH_FLOOR
        ]
        high_kinds = {k for k, _, _, _ in other_entries}

        if len(high_kinds) >= 3:
            adj += 15
            signals.append(
                f"[Context] Multi-vector campaign: {len(high_kinds)} scan types "
                f"({', '.join(sorted(high_kinds))}) all flagged high-risk in this session."
            )
        elif len(high_kinds) == 2:
            adj += 8
            signals.append(
                f"[Context] Cross-entity corroboration: "
                f"{' and '.join(sorted(high_kinds))} also flagged in session "
                f"— likely the same threat actor."
            )

        # ── Domain reuse across kinds ─────────────────────────────
        if current_domain:
            domain_matches = [
                k for (_, k, _, sc, dom) in window
                if dom == current_domain and k != kind and sc >= _SESSION_HIGH_FLOOR
            ]
            if domain_matches:
                matched_kinds = list(dict.fromkeys(domain_matches))  # ordered unique
                adj += 10
                signals.append(
                    f"[Context] Domain '{current_domain}' already flagged via "
                    f"{', '.join(matched_kinds[:3])} scan(s) — same-actor infrastructure reuse."
                )

        # ── Same target seen in multiple scan types ───────────────
        target_kinds = {
            k for (_, k, tgt, sc, _) in window
            if tgt == target and k != kind and sc >= _SESSION_HIGH_FLOOR
        }
        if target_kinds and not current_domain:  # avoid double-counting domain case
            adj += 6
            signals.append(
                f"[Context] Target '{target[:50]}' flagged in "
                f"{len(target_kinds)} other scan type(s) — entity overlap detected."
            )

        return min(adj, 20), signals[:2]

    def session_summary(self) -> Dict:
        """Snapshot of the current session window for the /api/scoring endpoint."""
        now    = time.time()
        window = [e for e in self._session if now - e[0] < _SESSION_WINDOW_SEC]
        by_kind: Dict[str, int] = defaultdict(int)
        high_by_kind: Dict[str, int] = defaultdict(int)
        for (_, k, _, sc, _) in window:
            by_kind[k] += 1
            if sc >= _SESSION_HIGH_FLOOR:
                high_by_kind[k] += 1
        high_kinds = {k for k in high_by_kind if high_by_kind[k] > 0}
        return {
            "window_seconds":     _SESSION_WINDOW_SEC,
            "total_in_window":    len(window),
            "scans_by_kind":      dict(by_kind),
            "high_risk_by_kind":  dict(high_by_kind),
            "multi_vector_active": len(high_kinds) >= 2,
            "active_kinds":        sorted(high_kinds),
        }


# ══════════════════════════════════════════════════════════════════
# ④  Unified ScoringEngine
# ══════════════════════════════════════════════════════════════════

class ScoringEngine:
    """
    Single facade used by main.py.

    Usage in each analyzer pipeline
    --------------------------------
    1. ... heuristic scoring ...
    2. score, _ = scoring_engine.calibrate(score, kind, reasons)
    3. ctx_adj, ctx_sigs = scoring_engine.context_adjust(kind, target, score, reasons)
       if ctx_sigs: reasons.extend(ctx_sigs); score += ctx_adj
    4. ... Claude AI ...
    5. level = scoring_engine.level_for(score, kind)
    6. record_alert() → internally calls scoring_engine.record(kind, target, score)
    """

    def __init__(self) -> None:
        self.thresholds = DynamicThresholds()
        self._calibrator = WeightedCalibrator()
        self._context    = ContextAwareScorer()

    # ── Core methods ─────────────────────────────────────────────

    def calibrate(
        self, raw_score: int, scan_type: str, reasons: List[str]
    ) -> Tuple[int, str]:
        """Weighted signal calibration (replaces ml_engine.calibrate)."""
        return self._calibrator.calibrate(raw_score, scan_type, reasons)

    def context_adjust(
        self, kind: str, target: str, score: int, reasons: List[str]
    ) -> Tuple[int, List[str]]:
        """Cross-entity session correlation adjustment."""
        return self._context.adjust(kind, target, score, reasons)

    def level_for(self, score: int, kind: str = "url") -> str:
        """Dynamic-threshold risk level classification."""
        danger, caution = self.thresholds.get(kind)
        if score >= danger:  return "danger"
        if score >= caution: return "caution"
        return "safe"

    def record(self, kind: str, target: str, score: int) -> None:
        """
        Must be called once per completed scan (inside record_alert).
        Updates threshold EMA and session window.
        """
        self.thresholds.record(kind, score)
        self._context.record(kind, target, score)

    # ── Introspection ─────────────────────────────────────────────

    def thresholds_summary(self) -> Dict:
        return self.thresholds.summary()

    def session_summary(self) -> Dict:
        return self._context.session_summary()

    def status(self) -> Dict:
        return {
            "thresholds": self.thresholds_summary(),
            "session":    self.session_summary(),
        }


# ── Singleton ────────────────────────────────────────────────────
scoring_engine = ScoringEngine()
