"""
FRAUD-X — Sliding Window Real-Time Analytics  v1.0
===================================================
§2  Temporal fraud analysis using overlapping sliding windows
§21 Stream analytics integration point for Kafka/Redis Streams

Windows
-------
  MICRO    :  5 minutes  — burst detection, real-time alerts
  SHORT    : 30 minutes  — attack pattern recognition
  MEDIUM   : 24 hours   — daily fraud rate baseline
  LONG     :  7 days    — weekly trend + coordinated campaign detection

For each window the engine tracks:
  - Event count
  - Severity distribution (safe/suspicious/high/critical)
  - Mean and peak fraud scores
  - Unique URLs / IPs / sessions
  - Fraud burst detection (events > dynamic threshold)
  - Temporal anomaly score (0-100)

All windows are updated on every `record()` call. The engine is
fully in-memory and thread-safe. No external dependencies.
"""

from __future__ import annotations

import math
import statistics
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any

# ── Window definitions (seconds) ─────────────────────────────
WINDOWS: dict[str, int] = {
    "micro":  5   * 60,      #  5 minutes
    "short":  30  * 60,      # 30 minutes
    "medium": 24  * 3600,    # 24 hours
    "long":   7   * 86400,   #  7 days
}

# ── Burst detection: events-per-window multiplier over baseline ─
BURST_MULTIPLIER   = 3.0     # 3× baseline rate = burst
BURST_MIN_EVENTS   = 5       # need at least this many events to call a burst

# ── Max ring-buffer size (per window) ─────────────────────────
MAX_EVENTS: dict[str, int] = {
    "micro":  10_000,
    "short":  50_000,
    "medium": 200_000,
    "long":   500_000,
}


# ═════════════════════════════════════════════════════════════
# Event dataclass
# ═════════════════════════════════════════════════════════════

@dataclass
class FraudEvent:
    """Minimal event stored per window slot."""
    score:    float
    severity: str
    url:      str = ""
    ip:       str = ""
    session:  str = ""
    kind:     str = "url"   # url | payment | ato | session | campaign
    ts:       float = field(default_factory=time.time)


# ═════════════════════════════════════════════════════════════
# Single sliding window
# ═════════════════════════════════════════════════════════════

class SlidingWindow:
    """
    A single time-bounded sliding window over FraudEvents.

    Uses a deque; events older than `duration_s` are pruned on
    every call to `snapshot()` or `_prune()`.
    """

    def __init__(self, name: str, duration_s: int, maxlen: int):
        self.name       = name
        self.duration_s = duration_s
        self._buf       = deque(maxlen=maxlen)
        self._lock      = threading.Lock()
        # Rolling baseline for burst detection (events per window)
        self._baseline_samples: deque = deque(maxlen=20)
        self._last_baseline_ts = 0.0

    def push(self, event: FraudEvent):
        with self._lock:
            self._buf.append(event)

    def _prune(self) -> list[FraudEvent]:
        """Remove expired events and return fresh list."""
        cutoff = time.time() - self.duration_s
        while self._buf and self._buf[0].ts < cutoff:
            self._buf.popleft()
        return list(self._buf)

    def snapshot(self) -> dict:
        """Compute a full analytics snapshot for this window."""
        with self._lock:
            events = self._prune()

        if not events:
            return self._empty_snapshot()

        scores    = [e.score    for e in events]
        severities= [e.severity for e in events]
        severity_counts = Counter(severities)

        mean_score = statistics.mean(scores)
        peak_score = max(scores)
        std_score  = statistics.stdev(scores) if len(scores) > 1 else 0.0

        # Unique entity counts
        unique_urls     = len(set(e.url     for e in events if e.url))
        unique_ips      = len(set(e.ip      for e in events if e.ip))
        unique_sessions = len(set(e.session for e in events if e.session))

        # Fraud rate
        fraud_events = [e for e in events if e.severity in ("high","critical")]
        fraud_rate   = len(fraud_events) / len(events) if events else 0.0

        # Burst detection
        is_burst, burst_ratio = self._detect_burst(len(events))

        # Temporal anomaly score (0-100)
        # Weighted by: fraud rate (40%), mean score (30%), burst (20%), severity (10%)
        crit_ratio  = severity_counts.get("critical", 0) / len(events)
        anomaly     = min(100.0,
            fraud_rate * 40 +
            (mean_score / 100.0) * 30 +
            (min(burst_ratio, 5.0) / 5.0) * 20 +
            crit_ratio * 10
        )

        # Recent trend (compare first half vs second half of window)
        mid   = len(events) // 2
        trend = 0.0
        if mid > 0:
            first_half  = statistics.mean(e.score for e in events[:mid])
            second_half = statistics.mean(e.score for e in events[mid:])
            trend       = second_half - first_half    # +ve = getting worse

        return {
            "window":           self.name,
            "duration_s":       self.duration_s,
            "event_count":      len(events),
            "mean_score":       round(mean_score, 2),
            "peak_score":       round(peak_score, 2),
            "std_score":        round(std_score,  2),
            "fraud_rate":       round(fraud_rate, 4),
            "fraud_events":     len(fraud_events),
            "severity_counts":  dict(severity_counts),
            "unique_urls":      unique_urls,
            "unique_ips":       unique_ips,
            "unique_sessions":  unique_sessions,
            "is_burst":         is_burst,
            "burst_ratio":      round(burst_ratio, 2),
            "temporal_anomaly": round(anomaly, 2),
            "trend":            round(trend, 2),       # +ve = score rising
        }

    def _detect_burst(self, current_count: int) -> tuple[bool, float]:
        """
        Compare current window event count against rolling baseline.
        Returns (is_burst, ratio_over_baseline).
        """
        now = time.time()
        # Update baseline every 60 s
        if now - self._last_baseline_ts >= 60.0:
            self._baseline_samples.append(current_count)
            self._last_baseline_ts = now

        if len(self._baseline_samples) < 2:
            return False, 1.0

        baseline = statistics.mean(self._baseline_samples)
        if baseline < 1.0:
            return False, 1.0
        ratio = current_count / baseline
        return ratio >= BURST_MULTIPLIER and current_count >= BURST_MIN_EVENTS, ratio

    def _empty_snapshot(self) -> dict:
        return {
            "window": self.name, "duration_s": self.duration_s,
            "event_count": 0, "mean_score": 0.0, "peak_score": 0.0,
            "std_score": 0.0, "fraud_rate": 0.0, "fraud_events": 0,
            "severity_counts": {}, "unique_urls": 0, "unique_ips": 0,
            "unique_sessions": 0, "is_burst": False, "burst_ratio": 1.0,
            "temporal_anomaly": 0.0, "trend": 0.0,
        }


# ═════════════════════════════════════════════════════════════
# §2 Window Analytics Engine
# ═════════════════════════════════════════════════════════════

class WindowAnalyticsEngine:
    """
    Manages all four sliding windows simultaneously.

    Usage
    -----
    engine = WindowAnalyticsEngine()
    engine.record(score=75, severity="high", url="http://…", ip="1.2.3.4")
    report = engine.report()            # all windows
    micro  = engine.window("micro")     # single window snapshot
    burst  = engine.detect_burst()      # burst summary
    """

    def __init__(self):
        self._windows: dict[str, SlidingWindow] = {
            name: SlidingWindow(name, dur, MAX_EVENTS[name])
            for name, dur in WINDOWS.items()
        }
        self._lock          = threading.Lock()
        self._total_events  = 0
        self._last_report_ts= 0.0
        self._report_cache  : dict = {}
        self._CACHE_TTL     = 2.0   # seconds — cache report for 2 s under load

    def record(
        self,
        score:    float,
        severity: str,
        url:      str   = "",
        ip:       str   = "",
        session:  str   = "",
        kind:     str   = "url",
        ts:       float = 0.0,
    ):
        """Push a new fraud event into all four windows."""
        evt = FraudEvent(
            score    = max(0.0, min(100.0, score)),
            severity = severity,
            url      = url,
            ip       = ip,
            session  = session,
            kind     = kind,
            ts       = ts or time.time(),
        )
        for w in self._windows.values():
            w.push(evt)
        with self._lock:
            self._total_events += 1

    def window(self, name: str) -> dict:
        """Snapshot for a single named window."""
        w = self._windows.get(name)
        return w.snapshot() if w else {"error": f"Unknown window: {name}"}

    def report(self, use_cache: bool = True) -> dict:
        """Full report across all windows with burst + trend summary."""
        now = time.time()
        if use_cache and now - self._last_report_ts < self._CACHE_TTL:
            return self._report_cache

        snapshots = {name: w.snapshot() for name, w in self._windows.items()}

        # Global burst alert: any window bursting?
        bursting = [name for name, snap in snapshots.items() if snap["is_burst"]]

        # Top anomaly window
        top_anomaly = max(snapshots.items(), key=lambda kv: kv[1]["temporal_anomaly"])

        result = {
            "windows":        snapshots,
            "total_events":   self._total_events,
            "bursting":       bursting,
            "burst_alert":    len(bursting) > 0,
            "top_anomaly":    {"window": top_anomaly[0], "score": top_anomaly[1]["temporal_anomaly"]},
            "generated_at":   now,
        }

        with self._lock:
            self._report_cache  = result
            self._last_report_ts = now

        return result

    def detect_burst(self) -> dict:
        """Quick burst check — only reads micro and short windows."""
        micro = self._windows["micro"].snapshot()
        short = self._windows["short"].snapshot()
        return {
            "micro_burst":    micro["is_burst"],
            "short_burst":    short["is_burst"],
            "micro_anomaly":  micro["temporal_anomaly"],
            "short_anomaly":  short["temporal_anomaly"],
            "micro_events":   micro["event_count"],
            "short_events":   short["event_count"],
            "alert":          micro["is_burst"] or short["is_burst"],
        }

    def velocity_for_ip(self, ip: str, window: str = "micro") -> int:
        """Count how many events from a specific IP in the given window."""
        w = self._windows.get(window)
        if not w:
            return 0
        with w._lock:
            events = w._prune()
        return sum(1 for e in events if e.ip == ip)

    def velocity_for_url(self, url: str, window: str = "short") -> int:
        """Count hits on a specific URL in the given window."""
        w = self._windows.get(window)
        if not w:
            return 0
        with w._lock:
            events = w._prune()
        return sum(1 for e in events if e.url == url)


# ── Singleton ─────────────────────────────────────────────────
window_analytics = WindowAnalyticsEngine()
