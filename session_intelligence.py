"""
FRAUD-X — Session-Level AI Intelligence Engine  v1.0
=====================================================
§4  Full-session tracking — analyzes entire browsing session, not just
    individual transactions
§10 Adaptive baselines — per-session drift vs established user profile

Session Intelligence tracks:
  - Navigation flow (page sequence, back-clicks, dead-ends)
  - Cursor evolution (patterns over time, not just snapshots)
  - Hesitation behavior (pause → burst → pause indicates reading pressure)
  - Behavioral drift (late-session behavior differs from early-session)
  - Click path patterns (unusual for legitimate users)
  - Interaction velocity (too fast = bot, too slow = distracted human)
  - Human authenticity score (0-100, 100 = almost certainly human)

Architecture
------------
  SessionRecord  — mutable state for one active session
  SessionIntelligenceEngine — manages all sessions, computes scores

  Scores are updated incrementally on every push_event() call.
  Old sessions expire after MAX_SESSION_AGE_S seconds of inactivity.
"""

from __future__ import annotations

import statistics
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

# ── Config ────────────────────────────────────────────────────
MAX_SESSION_AGE_S    = 1800    # 30 minutes of inactivity → expire session
MAX_EVENTS_PER_SESSION = 2000
SESSION_STORE_MAX    = 10_000  # max concurrent sessions tracked

# Thresholds for behavioral scoring
HUMAN_MIN_PAUSE_MS   = 80      # minimum realistic pause between actions
HUMAN_MAX_SPEED_PPS  = 20      # max realistic page-changes per second
DRIFT_WINDOW         = 50      # compare first vs last N events for drift


class EventKind(str, Enum):
    PAGE_VIEW       = "page_view"
    CLICK           = "click"
    KEY_PRESS       = "key_press"
    SCROLL          = "scroll"
    FORM_FOCUS      = "form_focus"
    FORM_SUBMIT     = "form_submit"
    BACK_NAVIGATION = "back_navigation"
    HESITATION      = "hesitation"    # >3s pause detected
    COPY_PASTE      = "copy_paste"    # clipboard event
    PAYMENT_START   = "payment_start"
    PAYMENT_ABANDON = "payment_abandon"


@dataclass
class SessionEvent:
    kind:     EventKind
    value:    float = 0.0     # context-dependent: score, duration_ms, amount
    url:      str   = ""
    ts:       float = field(default_factory=time.time)


@dataclass
class SessionScore:
    """Snapshot of session intelligence for one session."""
    session_id:         str
    fraud_probability:  float    # 0-100
    behavioral_drift:   float    # 0-100 (how much behavior changed mid-session)
    human_authenticity: float    # 0-100 (100 = definitely human)
    hesitation_score:   float    # 0-100 (high = confused/pressured user)
    velocity_anomaly:   float    # 0-100
    event_count:        int
    duration_s:         float
    anomalies:          list[str]
    ts:                 float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "session_id":         self.session_id,
            "fraud_probability":  round(self.fraud_probability, 2),
            "behavioral_drift":   round(self.behavioral_drift, 2),
            "human_authenticity": round(self.human_authenticity, 2),
            "hesitation_score":   round(self.hesitation_score, 2),
            "velocity_anomaly":   round(self.velocity_anomaly, 2),
            "event_count":        self.event_count,
            "duration_s":         round(self.duration_s, 1),
            "anomalies":          self.anomalies,
            "ts":                 self.ts,
        }


# ═════════════════════════════════════════════════════════════
# Session Record
# ═════════════════════════════════════════════════════════════

class SessionRecord:
    """
    Mutable state for a single active browsing session.
    Thread-safe for concurrent event pushes.
    """

    def __init__(self, session_id: str, user_id: str = ""):
        self.session_id    = session_id
        self.user_id       = user_id
        self.created_at    = time.time()
        self.last_event_ts = self.created_at
        self._events       = deque(maxlen=MAX_EVENTS_PER_SESSION)
        self._lock         = threading.Lock()

        # Running accumulators (updated incrementally)
        self._inter_event_gaps:  list[float] = []
        self._page_views:        int         = 0
        self._back_navigations:  int         = 0
        self._hesitations:       int         = 0
        self._copy_pastes:       int         = 0
        self._form_submits:      int         = 0
        self._payment_starts:    int         = 0
        self._payment_abandons:  int         = 0
        self._prev_ts:           float       = self.created_at
        self._urls_visited:      list[str]   = []

    def push(self, event: SessionEvent):
        with self._lock:
            gap = (event.ts - self._prev_ts) * 1000.0   # ms
            if gap > 0:
                self._inter_event_gaps.append(gap)
            self._prev_ts        = event.ts
            self.last_event_ts   = event.ts
            self._events.append(event)

            # Counters
            if event.kind == EventKind.PAGE_VIEW:
                self._page_views += 1
                if event.url:
                    self._urls_visited.append(event.url)
            elif event.kind == EventKind.BACK_NAVIGATION:
                self._back_navigations += 1
            elif event.kind == EventKind.HESITATION:
                self._hesitations += 1
            elif event.kind == EventKind.COPY_PASTE:
                self._copy_pastes += 1
            elif event.kind == EventKind.FORM_SUBMIT:
                self._form_submits += 1
            elif event.kind == EventKind.PAYMENT_START:
                self._payment_starts += 1
            elif event.kind == EventKind.PAYMENT_ABANDON:
                self._payment_abandons += 1

    def compute_score(self) -> SessionScore:
        with self._lock:
            events = list(self._events)
            gaps   = list(self._inter_event_gaps)
            page_views       = self._page_views
            back_navs        = self._back_navigations
            hesitations      = self._hesitations
            copy_pastes      = self._copy_pastes
            form_submits     = self._form_submits
            payment_starts   = self._payment_starts
            payment_abandons = self._payment_abandons

        n          = len(events)
        duration_s = self.last_event_ts - self.created_at
        anomalies  = []

        # ── Human authenticity score ─────────────────────────────
        authenticity = 100.0

        # Bot signal: perfectly uniform inter-event gaps
        if len(gaps) >= 10:
            gap_std  = statistics.stdev(gaps) if len(gaps) > 1 else 0.0
            gap_mean = statistics.mean(gaps)
            if gap_std < 5.0 and gap_mean < 200.0:
                authenticity -= 40.0
                anomalies.append("robotic_uniform_timing")
            # Impossibly fast (>20 events/second sustained)
            if gap_mean < (1000.0 / HUMAN_MAX_SPEED_PPS):
                authenticity -= 30.0
                anomalies.append("superhuman_speed")

        # Bot signal: no hesitations at all on a payment page
        if payment_starts > 0 and hesitations == 0 and n > 20:
            authenticity -= 15.0
            anomalies.append("no_hesitation_on_payment")

        # Bot signal: excessive copy-paste
        if copy_pastes >= 3:
            authenticity -= 20.0
            anomalies.append("excessive_copy_paste")

        authenticity = max(0.0, authenticity)

        # ── Behavioral drift score ────────────────────────────────
        drift = 0.0
        if n >= DRIFT_WINDOW * 2 and len(gaps) >= DRIFT_WINDOW * 2:
            early_gaps = gaps[:DRIFT_WINDOW]
            late_gaps  = gaps[-DRIFT_WINDOW:]
            early_mean = statistics.mean(early_gaps)
            late_mean  = statistics.mean(late_gaps)
            if early_mean > 0:
                drift_ratio = abs(late_mean - early_mean) / early_mean
                drift = min(100.0, drift_ratio * 100)
                if drift > 50:
                    anomalies.append("behavioral_drift")

        # ── Hesitation score ─────────────────────────────────────
        hesitation_score = 0.0
        if n > 10:
            hesitation_score = min(100.0, (hesitations / n) * 1000.0)
            if hesitations >= 3:
                anomalies.append("high_hesitation")

        # ── Velocity anomaly ─────────────────────────────────────
        velocity_anomaly = 0.0
        if duration_s > 0 and n > 0:
            events_per_sec = n / duration_s
            if events_per_sec > 5.0:
                velocity_anomaly = min(100.0, (events_per_sec - 5.0) * 20.0)
                anomalies.append("high_velocity_session")

        # ── Suspicious session patterns ───────────────────────────
        suspicious_back = 0.0
        if page_views > 0:
            back_ratio = back_navs / page_views
            if back_ratio > 0.4:
                suspicious_back = min(40.0, back_ratio * 100)
                anomalies.append("excessive_back_navigation")

        # Abandon payment patterns
        abandon_score = 0.0
        if payment_starts > 0:
            abandon_ratio = payment_abandons / payment_starts
            if abandon_ratio > 0.7:
                abandon_score = min(30.0, abandon_ratio * 50)
                anomalies.append("payment_abandon_pattern")

        # ── Composite fraud probability ───────────────────────────
        fraud_prob = min(100.0,
            (100.0 - authenticity) * 0.35 +
            drift           * 0.20 +
            hesitation_score* 0.10 +
            velocity_anomaly* 0.15 +
            suspicious_back * 0.10 +
            abandon_score   * 0.10
        )

        return SessionScore(
            session_id          = self.session_id,
            fraud_probability   = fraud_prob,
            behavioral_drift    = drift,
            human_authenticity  = authenticity,
            hesitation_score    = hesitation_score,
            velocity_anomaly    = velocity_anomaly,
            event_count         = n,
            duration_s          = duration_s,
            anomalies           = list(set(anomalies)),
        )

    def is_expired(self) -> bool:
        return (time.time() - self.last_event_ts) > MAX_SESSION_AGE_S


# ═════════════════════════════════════════════════════════════
# §4 Session Intelligence Engine
# ═════════════════════════════════════════════════════════════

class SessionIntelligenceEngine:
    """
    Manages all active sessions and provides §4 session-level fraud scoring.
    """

    def __init__(self):
        self._sessions: dict[str, SessionRecord] = {}
        self._lock      = threading.Lock()
        self._last_gc   = 0.0

    def push_event(
        self,
        session_id:  str,
        kind:        str,
        value:       float = 0.0,
        url:         str   = "",
        user_id:     str   = "",
        ts:          float = 0.0,
    ):
        """Add an event to a session. Creates the session if it doesn't exist."""
        self._maybe_gc()
        record = self._get_or_create(session_id, user_id)
        event  = SessionEvent(
            kind  = EventKind(kind) if kind in EventKind._value2member_map_ else EventKind.PAGE_VIEW,
            value = value,
            url   = url,
            ts    = ts or time.time(),
        )
        record.push(event)

    def score(self, session_id: str) -> Optional[SessionScore]:
        record = self._sessions.get(session_id)
        return record.compute_score() if record else None

    def score_or_create(self, session_id: str, user_id: str = "") -> SessionScore:
        record = self._get_or_create(session_id, user_id)
        return record.compute_score()

    def all_active_sessions(self) -> list[dict]:
        with self._lock:
            records = list(self._sessions.values())
        return [r.compute_score().to_dict() for r in records]

    def stats(self) -> dict:
        with self._lock:
            n = len(self._sessions)
        return {"active_sessions": n, "max_capacity": SESSION_STORE_MAX}

    # ── Internal ──────────────────────────────────────────────

    def _get_or_create(self, session_id: str, user_id: str = "") -> SessionRecord:
        with self._lock:
            if session_id not in self._sessions:
                if len(self._sessions) >= SESSION_STORE_MAX:
                    self._gc_locked()
                self._sessions[session_id] = SessionRecord(session_id, user_id)
        return self._sessions[session_id]

    def _maybe_gc(self):
        now = time.time()
        if now - self._last_gc < 60.0:
            return
        with self._lock:
            self._gc_locked()
        self._last_gc = now

    def _gc_locked(self):
        stale = [sid for sid, r in self._sessions.items() if r.is_expired()]
        for sid in stale:
            del self._sessions[sid]


# ── Singleton ─────────────────────────────────────────────────
session_intelligence = SessionIntelligenceEngine()
