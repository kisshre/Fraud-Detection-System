"""
FRAUD-X  ·  Transaction Velocity & Anomaly Engine
==================================================
Detects:
  - Rapid repeated transactions (velocity bursts)
  - Multiple card / account attempts
  - Impossible travel patterns (geo-jump detection)
  - Sudden geo-location changes
  - Abnormal spending spikes

Detection models used:
  - Isolation Forest    (unsupervised anomaly)
  - One-Class SVM       (novelty detection)
  - Rule-based velocity (high-speed, high-recall)
"""

from __future__ import annotations

import math
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Optional

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler


# ── In-memory velocity windows (per user / card / merchant / IP) ─────────────
_TX_WINDOWS: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))

# Isolation Forest + OC-SVM trained on bootstrap data
_iso_forest:   Optional[IsolationForest] = None
_oc_svm:       Optional[OneClassSVM]     = None
_scaler:       Optional[StandardScaler]  = None
_models_ready: bool                      = False

VELOCITY_WINDOW_SECONDS = 300   # 5-minute sliding window
BURST_THRESHOLD         = 5     # ≥5 tx in window → velocity flag
MAX_AMOUNT_RATIO        = 3.0   # spike if amount > 3× user mean


# ═════════════════════════════════════════════════════════════════════════════
# Geo helpers
# ═════════════════════════════════════════════════════════════════════════════

def _haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Great-circle distance in km."""
    R = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat / 2) ** 2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def _impossible_travel(prev_lat: float, prev_lon: float, prev_ts: float,
                        curr_lat: float, curr_lon: float, curr_ts: float) -> tuple[bool, float]:
    """Returns (is_impossible, speed_km_h). Speed > 900 km/h flags impossible travel."""
    elapsed_h = max((curr_ts - prev_ts) / 3600.0, 1 / 3600.0)
    dist_km   = _haversine_km(prev_lat, prev_lon, curr_lat, curr_lon)
    speed     = dist_km / elapsed_h
    return speed > 900, round(speed, 1)


# ═════════════════════════════════════════════════════════════════════════════
# Bootstrap model training
# ═════════════════════════════════════════════════════════════════════════════

def _train_models() -> None:
    global _iso_forest, _oc_svm, _scaler, _models_ready

    rng = np.random.default_rng(42)
    # Simulate normal transaction feature vectors
    # Features: [amount_z, tx_count_5min, hour_sin, hour_cos, is_new_merchant, is_new_ip]
    n = 800
    normal = np.column_stack([
        rng.normal(0, 1, n),                        # amount z-score (normal ≈ 0)
        rng.integers(0, 4, n).astype(float),        # tx count 5 min
        np.sin(rng.uniform(0, 2 * math.pi, n)),     # hour sin
        np.cos(rng.uniform(0, 2 * math.pi, n)),     # hour cos
        rng.choice([0, 1], n, p=[0.85, 0.15]).astype(float),  # new merchant
        rng.choice([0, 1], n, p=[0.90, 0.10]).astype(float),  # new ip
    ])

    _scaler    = StandardScaler().fit(normal)
    X          = _scaler.transform(normal)
    _iso_forest = IsolationForest(n_estimators=100, contamination=0.05, random_state=42).fit(X)
    _oc_svm    = OneClassSVM(kernel="rbf", nu=0.05, gamma="scale").fit(X)
    _models_ready = True


# Train at import time (lightweight, < 100ms)
_train_models()


# ═════════════════════════════════════════════════════════════════════════════
# Data structures
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class TransactionEvent:
    user_id:   str
    amount:    float
    currency:  str          = "USD"
    merchant:  str          = ""
    ip:        str          = ""
    lat:       float        = 0.0
    lon:       float        = 0.0
    card_last4: str         = ""
    timestamp: float        = field(default_factory=time.time)


@dataclass
class VelocityAnalysis:
    tx_count_5min:   int
    total_amount_5min: float
    burst_flag:      bool
    unique_merchants: int
    unique_ips:       int
    unique_cards:     int


@dataclass
class TransactionRiskScore:
    score:          int           # 0–100
    reasons:        list[str]
    velocity:       VelocityAnalysis
    is_anomaly_iso: bool
    is_anomaly_svm: bool
    impossible_travel: bool
    travel_speed_kmh:  float
    risk_level:     str           # none / low / medium / high / critical


# ═════════════════════════════════════════════════════════════════════════════
# Velocity analysis
# ═════════════════════════════════════════════════════════════════════════════

def _get_velocity(user_id: str, event: TransactionEvent) -> VelocityAnalysis:
    key = f"user:{user_id}"
    win = _TX_WINDOWS[key]
    now = event.timestamp
    cutoff = now - VELOCITY_WINDOW_SECONDS

    # Prune old entries
    while win and win[0]["ts"] < cutoff:
        win.popleft()

    recent = list(win)
    tx_count      = len(recent)
    total_amount  = sum(r["amount"] for r in recent)
    merchants     = {r["merchant"] for r in recent if r["merchant"]}
    ips           = {r["ip"]       for r in recent if r["ip"]}
    cards         = {r["card"]     for r in recent if r["card"]}

    # Record current
    win.append({
        "ts":       now,
        "amount":   event.amount,
        "merchant": event.merchant,
        "ip":       event.ip,
        "card":     event.card_last4,
        "lat":      event.lat,
        "lon":      event.lon,
    })

    return VelocityAnalysis(
        tx_count_5min    = tx_count + 1,
        total_amount_5min= total_amount + event.amount,
        burst_flag       = (tx_count + 1) >= BURST_THRESHOLD,
        unique_merchants = len(merchants | {event.merchant}) if event.merchant else len(merchants),
        unique_ips       = len(ips      | {event.ip})       if event.ip       else len(ips),
        unique_cards     = len(cards    | {event.card_last4}) if event.card_last4 else len(cards),
    )


# ═════════════════════════════════════════════════════════════════════════════
# ML anomaly detection
# ═════════════════════════════════════════════════════════════════════════════

def _user_mean_amount(user_id: str) -> float:
    win = _TX_WINDOWS.get(f"user:{user_id}", deque())
    amounts = [r["amount"] for r in win]
    return float(np.mean(amounts)) if amounts else 0.0


def _build_feature_vector(event: TransactionEvent, vel: VelocityAnalysis, user_id: str) -> np.ndarray:
    mean_amt   = _user_mean_amount(user_id) or event.amount
    amount_z   = (event.amount - mean_amt) / max(mean_amt * 0.3, 1.0)
    hour       = time.localtime(event.timestamp).tm_hour
    hour_sin   = math.sin(2 * math.pi * hour / 24)
    hour_cos   = math.cos(2 * math.pi * hour / 24)
    is_new_merchant = 1.0 if vel.unique_merchants > 3 else 0.0
    is_new_ip       = 1.0 if vel.unique_ips > 2       else 0.0

    return np.array([[amount_z, vel.tx_count_5min, hour_sin, hour_cos,
                      is_new_merchant, is_new_ip]])


def _run_anomaly_models(fv: np.ndarray) -> tuple[bool, bool]:
    if not _models_ready or _scaler is None:
        return False, False
    X_scaled = _scaler.transform(fv)
    iso_pred = _iso_forest.predict(X_scaled)[0]   # -1 = anomaly
    svm_pred = _oc_svm.predict(X_scaled)[0]        # -1 = anomaly
    return iso_pred == -1, svm_pred == -1


# ═════════════════════════════════════════════════════════════════════════════
# Impossible travel check (uses prior event per user)
# ═════════════════════════════════════════════════════════════════════════════

def _check_travel(user_id: str, event: TransactionEvent) -> tuple[bool, float]:
    win = _TX_WINDOWS.get(f"user:{user_id}", deque())
    # Find last event with a valid geo location (before appending current)
    for prev in reversed(list(win)[:-1]):   # skip the one we just appended
        if prev["lat"] != 0 or prev["lon"] != 0:
            if event.lat == 0 and event.lon == 0:
                break
            return _impossible_travel(
                prev["lat"], prev["lon"], prev["ts"],
                event.lat,  event.lon,  event.timestamp,
            )
    return False, 0.0


# ═════════════════════════════════════════════════════════════════════════════
# Main scoring entry point
# ═════════════════════════════════════════════════════════════════════════════

def analyze_transaction(event: TransactionEvent) -> TransactionRiskScore:
    """Synchronous; call from async context with asyncio.to_thread if needed."""
    vel     = _get_velocity(event.user_id, event)
    fv      = _build_feature_vector(event, vel, event.user_id)
    iso_anom, svm_anom = _run_anomaly_models(fv)
    travel_impossible, travel_speed = _check_travel(event.user_id, event)

    score   = 0
    reasons = []

    # ── Velocity rules ────────────────────────────────────────────
    if vel.tx_count_5min >= 10:
        score += 40
        reasons.append(f"[Velocity] {vel.tx_count_5min} transactions in 5 min — extreme burst")
    elif vel.tx_count_5min >= BURST_THRESHOLD:
        score += 22
        reasons.append(f"[Velocity] {vel.tx_count_5min} transactions in 5 min — burst detected")

    if vel.unique_cards >= 3:
        score += 30
        reasons.append(f"[Velocity] {vel.unique_cards} distinct card numbers in 5 min")
    elif vel.unique_cards == 2:
        score += 12
        reasons.append(f"[Velocity] Multiple card numbers used")

    if vel.unique_ips >= 3:
        score += 20
        reasons.append(f"[Velocity] {vel.unique_ips} distinct IPs in 5 min")

    # ── Amount spike ─────────────────────────────────────────────
    mean_amt = _user_mean_amount(event.user_id)
    if mean_amt > 0 and event.amount > mean_amt * MAX_AMOUNT_RATIO:
        ratio = event.amount / mean_amt
        score += min(25, int(ratio * 5))
        reasons.append(f"[Velocity] Amount ${event.amount:.2f} is {ratio:.1f}× user mean")

    # ── Impossible travel ─────────────────────────────────────────
    if travel_impossible:
        score += 45
        reasons.append(f"[GeoRisk] Impossible travel: {travel_speed:.0f} km/h between transactions")
    elif travel_speed > 300:
        score += 15
        reasons.append(f"[GeoRisk] Fast geo-jump: {travel_speed:.0f} km/h")

    # ── ML anomaly signals ────────────────────────────────────────
    if iso_anom and svm_anom:
        score += 20
        reasons.append("[AnomalyML] Both Isolation Forest and One-Class SVM flagged anomaly")
    elif iso_anom:
        score += 10
        reasons.append("[AnomalyML] Isolation Forest: transaction pattern is anomalous")
    elif svm_anom:
        score += 8
        reasons.append("[AnomalyML] One-Class SVM: transaction deviates from learned baseline")

    score = min(100, score)
    level = (
        "critical" if score >= 70 else
        "high"     if score >= 45 else
        "medium"   if score >= 20 else
        "low"      if score >= 5  else
        "none"
    )

    return TransactionRiskScore(
        score            = score,
        reasons          = reasons,
        velocity         = vel,
        is_anomaly_iso   = iso_anom,
        is_anomaly_svm   = svm_anom,
        impossible_travel= travel_impossible,
        travel_speed_kmh = travel_speed,
        risk_level       = level,
    )


# ═════════════════════════════════════════════════════════════════════════════
# Singleton
# ═════════════════════════════════════════════════════════════════════════════

class TransactionEngine:
    def analyze(self, event: TransactionEvent) -> TransactionRiskScore:
        return analyze_transaction(event)

    def clear_user(self, user_id: str) -> None:
        _TX_WINDOWS.pop(f"user:{user_id}", None)

    @property
    def active_users(self) -> int:
        return len(_TX_WINDOWS)


transaction_engine = TransactionEngine()
