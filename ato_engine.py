"""
FRAUD-X — Account Takeover Detection Engine  v1.0
==================================================
§3  Account Takeover (ATO) Detection
§10 Adaptive User Behavioral Baselines

Detects account compromise by modeling each user's normal behavior
and flagging statistically significant deviations.

ATO Signals
-----------
  device_change      — new device fingerprint vs historical
  browser_change     — new user-agent / browser environment
  impossible_travel  — geo-location delta physically impossible (§3 Haversine)
  typing_mismatch    — biometric drift from established baseline
  login_time_anomaly — login at unusual hour vs historical pattern
  velocity_spike     — sudden surge in requests/transactions
  new_ip_class       — IP changed CIDR class (e.g., home→Tor exit)
  session_anomaly    — unusual session length or activity
  otp_rapid_attempts — multiple OTP attempts in short window

Score mapping
-------------
  0-25   : Normal behavior variation
  26-50  : Elevated risk — soft challenge (CAPTCHA/step-up auth)
  51-75  : High ATO probability — strong challenge (SMS OTP)
  76-100 : Confirmed ATO indicators — block + alert

§10 Adaptive Baseline
---------------------
  After enough observations (≥BASELINE_MIN_OBSERVATIONS), the engine
  shifts from heuristic scoring to deviation-from-baseline scoring.
  Baseline is an exponentially weighted moving average (α = BASELINE_ALPHA).
"""

from __future__ import annotations

import math
import statistics
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

# ── Haversine great-circle distance ──────────────────────────
def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    R  = 6371.0
    d1 = math.radians(lat2 - lat1)
    d2 = math.radians(lon2 - lon1)
    a  = math.sin(d1/2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(d2/2)**2
    return 2 * R * math.asin(math.sqrt(a))

MAX_TRAVEL_KM_PER_HOUR = 900.0     # ~transatlantic flight speed

# ── Baseline config (§10) ─────────────────────────────────────
BASELINE_ALPHA              = 0.05  # EMA smoothing factor
BASELINE_MIN_OBSERVATIONS   = 5     # minimum events before baseline activates
BASELINE_DRIFT_THRESHOLD    = 2.5   # Z-score threshold for anomaly flag

# ── ATO signal weights ────────────────────────────────────────
ATO_WEIGHTS: dict[str, float] = {
    "device_change":       25.0,
    "browser_change":      12.0,
    "impossible_travel":   35.0,
    "typing_mismatch":     15.0,
    "login_time_anomaly":  10.0,
    "velocity_spike":      18.0,
    "new_ip_class":        15.0,
    "session_anomaly":     12.0,
    "otp_rapid_attempts":  20.0,
}


# ═════════════════════════════════════════════════════════════
# Data classes
# ═════════════════════════════════════════════════════════════

@dataclass
class ATOInput:
    """All contextual data available for ATO assessment."""
    user_id:          str
    # Device / browser
    device_fp:        str   = ""    # current canvas+WebGL fingerprint
    browser_ua:       str   = ""
    # Geo
    lat:              float = 0.0
    lon:              float = 0.0
    ip:               str   = ""
    # Biometrics
    typing_speed:     float = 0.0   # chars/min
    mouse_precision:  float = 0.0   # 0-100
    # Session context
    session_id:       str   = ""
    hour_of_day:      int   = -1    # 0-23; -1 = unknown
    request_count:    int   = 0
    # OTP abuse
    otp_attempts:     int   = 0
    otp_window_s:     float = 300.0
    ts:               float = field(default_factory=time.time)


@dataclass
class ATOResult:
    """ATO detection output."""
    user_id:           str
    ato_score:         float          # 0-100
    identity_trust:    float          # 0-100 (100 = confirmed identity)
    session_trust:     float          # 0-100 (100 = fully legitimate session)
    triggered_signals: list[str]
    details:           dict
    recommended_action:str            # allow|challenge_soft|challenge_strong|block
    ts:                float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "user_id":           self.user_id,
            "ato_score":         round(self.ato_score, 2),
            "identity_trust":    round(self.identity_trust, 2),
            "session_trust":     round(self.session_trust, 2),
            "triggered_signals": self.triggered_signals,
            "details":           self.details,
            "recommended_action":self.recommended_action,
            "ts":                self.ts,
        }


# ═════════════════════════════════════════════════════════════
# §10 User Behavioral Baseline
# ═════════════════════════════════════════════════════════════

class UserBaseline:
    """
    Exponentially-weighted moving average model of a single user's
    normal behavior. Used by ATOEngine for personalized anomaly detection.
    """

    def __init__(self, user_id: str):
        self.user_id         = user_id
        self.observations    = 0
        # EMA fields — each updated on every observe() call
        self.avg_typing_speed: Optional[float] = None
        self.avg_mouse_prec : Optional[float]  = None
        self.known_devices  : set  = set()
        self.known_browsers : set  = set()
        self.known_ip_prefixes: set = set()     # /24 CIDR prefixes
        self.login_hours    : list = []         # hour-of-day histogram (24 bins)
        self.avg_requests   : Optional[float]  = None
        self._lock           = threading.Lock()
        self._last_lat       = 0.0
        self._last_lon       = 0.0
        self._last_ts        = 0.0

    def observe(self, inp: ATOInput):
        with self._lock:
            self.observations += 1
            α = BASELINE_ALPHA

            # Typing speed EMA
            if inp.typing_speed > 0:
                self.avg_typing_speed = (
                    inp.typing_speed if self.avg_typing_speed is None
                    else (1 - α) * self.avg_typing_speed + α * inp.typing_speed
                )

            # Mouse precision EMA
            if inp.mouse_precision > 0:
                self.avg_mouse_prec = (
                    inp.mouse_precision if self.avg_mouse_prec is None
                    else (1 - α) * self.avg_mouse_prec + α * inp.mouse_precision
                )

            # Known entities
            if inp.device_fp:
                self.known_devices.add(inp.device_fp[:32])
            if inp.browser_ua:
                self.known_browsers.add(inp.browser_ua[:60])
            if inp.ip:
                prefix = ".".join(inp.ip.split(".")[:3])
                self.known_ip_prefixes.add(prefix)

            # Login hours histogram
            if 0 <= inp.hour_of_day <= 23:
                self.login_hours.append(inp.hour_of_day)
                if len(self.login_hours) > 200:
                    self.login_hours = self.login_hours[-200:]

            # Request rate EMA
            if inp.request_count > 0:
                self.avg_requests = (
                    float(inp.request_count) if self.avg_requests is None
                    else (1 - α) * self.avg_requests + α * inp.request_count
                )

            # Geo memory
            self._last_lat = inp.lat
            self._last_lon = inp.lon
            self._last_ts  = inp.ts

    def is_established(self) -> bool:
        return self.observations >= BASELINE_MIN_OBSERVATIONS

    def to_dict(self) -> dict:
        with self._lock:
            return {
                "user_id":       self.user_id,
                "observations":  self.observations,
                "established":   self.is_established(),
                "known_devices": len(self.known_devices),
                "known_ips":     len(self.known_ip_prefixes),
                "avg_typing":    round(self.avg_typing_speed or 0, 1),
                "avg_requests":  round(self.avg_requests or 0, 1),
            }


# ═════════════════════════════════════════════════════════════
# §3 Account Takeover Engine
# ═════════════════════════════════════════════════════════════

class ATOEngine:
    """
    Detects account takeover by comparing each request against the
    user's established behavioral baseline.
    """

    def __init__(self):
        self._baselines: dict[str, UserBaseline] = {}
        self._recent   : deque                   = deque(maxlen=5000)
        self._lock      = threading.Lock()

    # ── Public API ────────────────────────────────────────────

    def assess(self, inp: ATOInput) -> ATOResult:
        """
        Main entry point. Returns an ATOResult with ATO probability
        and recommended action.
        """
        baseline = self._get_or_create(inp.user_id)
        signals, details = self._detect_signals(inp, baseline)

        # Raw ATO score = sum of triggered signal weights (capped at 100)
        raw_score = min(100.0, sum(ATO_WEIGHTS.get(s, 0) for s in signals))

        # If baseline is established, incorporate deviation score
        if baseline.is_established():
            dev_score = self._deviation_score(inp, baseline)
            # Blend: 60% signal score, 40% deviation
            raw_score = min(100.0, raw_score * 0.6 + dev_score * 0.4)

        identity_trust = max(0.0, 100.0 - raw_score)
        session_trust  = max(0.0, 100.0 - raw_score * 0.8)

        action = (
            "block"             if raw_score >= 76 else
            "challenge_strong"  if raw_score >= 51 else
            "challenge_soft"    if raw_score >= 26 else
            "allow"
        )

        result = ATOResult(
            user_id            = inp.user_id,
            ato_score          = raw_score,
            identity_trust     = identity_trust,
            session_trust      = session_trust,
            triggered_signals  = signals,
            details            = details,
            recommended_action = action,
        )

        # Update baseline after assessment
        baseline.observe(inp)

        with self._lock:
            self._recent.append({
                "user_id": inp.user_id, "score": raw_score,
                "signals": signals, "ts": inp.ts,
            })

        return result

    def get_baseline(self, user_id: str) -> Optional[dict]:
        b = self._baselines.get(user_id)
        return b.to_dict() if b else None

    def stats(self) -> dict:
        with self._lock:
            recent = list(self._recent)
        if not recent:
            return {"users_tracked": len(self._baselines), "recent_events": 0}
        high_ato = [e for e in recent if e["score"] >= 50]
        return {
            "users_tracked":  len(self._baselines),
            "recent_events":  len(recent),
            "high_ato_events":len(high_ato),
            "avg_score":      round(statistics.mean(e["score"] for e in recent), 2),
        }

    # ── Internal helpers ──────────────────────────────────────

    def _get_or_create(self, user_id: str) -> UserBaseline:
        with self._lock:
            if user_id not in self._baselines:
                self._baselines[user_id] = UserBaseline(user_id)
        return self._baselines[user_id]

    def _detect_signals(
        self, inp: ATOInput, baseline: UserBaseline
    ) -> tuple[list[str], dict]:
        signals: list[str] = []
        details: dict      = {}

        # Device change
        if inp.device_fp and baseline.known_devices:
            if inp.device_fp[:32] not in baseline.known_devices:
                signals.append("device_change")
                details["device_change"] = "New device fingerprint detected"

        # Browser change
        if inp.browser_ua and baseline.known_browsers:
            if inp.browser_ua[:60] not in baseline.known_browsers:
                signals.append("browser_change")
                details["browser_change"] = "New browser/user-agent detected"

        # Impossible travel (§3 Haversine)
        if (inp.lat and inp.lon and baseline._last_lat and baseline._last_ts):
            dist_km  = _haversine_km(baseline._last_lat, baseline._last_lon,
                                     inp.lat, inp.lon)
            hours    = max(0.001, (inp.ts - baseline._last_ts) / 3600.0)
            speed_kph= dist_km / hours
            if speed_kph > MAX_TRAVEL_KM_PER_HOUR and dist_km > 50:
                signals.append("impossible_travel")
                details["impossible_travel"] = (
                    f"Distance {dist_km:.0f} km in {hours:.1f}h "
                    f"({speed_kph:.0f} km/h > {MAX_TRAVEL_KM_PER_HOUR} km/h)"
                )

        # Typing mismatch (§10)
        if (inp.typing_speed > 0 and baseline.avg_typing_speed
                and baseline.avg_typing_speed > 0):
            deviation = abs(inp.typing_speed - baseline.avg_typing_speed) / baseline.avg_typing_speed
            if deviation > 0.6:    # >60% deviation from mean
                signals.append("typing_mismatch")
                details["typing_mismatch"] = f"Typing speed {inp.typing_speed:.0f} vs baseline {baseline.avg_typing_speed:.0f} chars/min"

        # Login time anomaly (§3)
        if inp.hour_of_day >= 0 and len(baseline.login_hours) >= 10:
            hour_counts  = [0] * 24
            for h in baseline.login_hours:
                hour_counts[h] += 1
            expected = hour_counts[inp.hour_of_day] / len(baseline.login_hours)
            if expected < 0.02:   # less than 2% of logins at this hour historically
                signals.append("login_time_anomaly")
                details["login_time_anomaly"] = f"Login at hour {inp.hour_of_day} is unusual for this user"

        # Velocity spike (§3)
        if (inp.request_count > 0 and baseline.avg_requests
                and baseline.avg_requests > 0):
            ratio = inp.request_count / baseline.avg_requests
            if ratio > 5.0:
                signals.append("velocity_spike")
                details["velocity_spike"] = f"Request count {inp.request_count} is {ratio:.1f}× baseline"

        # New IP class
        if inp.ip and baseline.known_ip_prefixes:
            prefix = ".".join(inp.ip.split(".")[:3])
            if prefix not in baseline.known_ip_prefixes:
                signals.append("new_ip_class")
                details["new_ip_class"] = f"New /24 subnet: {prefix}.0/24"

        # OTP rapid attempts
        if inp.otp_attempts > 0:
            attempts_per_min = inp.otp_attempts / max(1.0, inp.otp_window_s / 60.0)
            if attempts_per_min >= 3:
                signals.append("otp_rapid_attempts")
                details["otp_rapid_attempts"] = f"{inp.otp_attempts} OTP attempts in {inp.otp_window_s:.0f}s"

        return signals, details

    def _deviation_score(self, inp: ATOInput, baseline: UserBaseline) -> float:
        """
        Compute a Z-score-based deviation from established baseline.
        Returns 0-100.
        """
        deviations: list[float] = []

        if (inp.typing_speed > 0 and baseline.avg_typing_speed
                and baseline.avg_typing_speed > 0):
            z = abs(inp.typing_speed - baseline.avg_typing_speed) / max(1.0, baseline.avg_typing_speed * 0.2)
            deviations.append(z)

        if not deviations:
            return 0.0

        avg_z = statistics.mean(deviations)
        # Scale: Z=2.5 → 100, Z=0 → 0
        return min(100.0, (avg_z / BASELINE_DRIFT_THRESHOLD) * 100.0)


# ── Singleton ─────────────────────────────────────────────────
ato_engine = ATOEngine()
