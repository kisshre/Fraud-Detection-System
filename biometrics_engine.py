"""
FRAUD-X  ·  Behavioral Biometrics & Device Fingerprint Engine
==============================================================
Processes client-side behavioral signals collected by the JavaScript
biometrics tracker embedded in the dashboard/extension.

Behavioral Signals Tracked:
  - Mouse movement velocity, acceleration, jitter
  - Keystroke dynamics (dwell time, flight time, rhythm)
  - Typing speed (WPM, character rate)
  - Scroll behavior (speed, direction changes)
  - Click patterns (precision, pressure simulation)
  - Navigation patterns
  - Copy-paste detection
  - Form interaction timing
  - Tab switching frequency
  - Idle time distribution

Device Fingerprint Signals:
  - Browser type, version
  - Screen resolution, color depth
  - GPU renderer (via WebGL)
  - Canvas fingerprint hash
  - Installed fonts subset
  - Timezone, locale
  - Platform / OS
  - Plugin list
  - Hardware concurrency
  - Memory estimate
  - Touch support
  - WebRTC leak detection

Scoring:
  - Trust Score        (0–100, higher = more trustworthy)
  - Bot Probability    (0.0–1.0)
  - Session Anomaly    (0–100)
  - Device Risk        (0–100)
  - Final Risk Delta   (0–35 added to overall fraud score)
"""

from __future__ import annotations

import hashlib
import math
import statistics
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Optional


# ═════════════════════════════════════════════════════════════════════════════
# Data models
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class BiometricSession:
    session_id:      str
    created_at:      float = field(default_factory=time.time)
    last_updated:    float = field(default_factory=time.time)

    # Mouse signals
    mouse_events:    list  = field(default_factory=list)   # [{x,y,t,type}]
    mouse_velocity:  list  = field(default_factory=list)   # px/ms
    mouse_jitter:    float = 0.0

    # Keyboard signals
    key_events:      list  = field(default_factory=list)   # [{key,dwell,flight,t}]
    typing_wpm:      float = 0.0
    keystroke_rhythm_var: float = 0.0   # std-dev of inter-key intervals

    # Scroll signals
    scroll_events:   list  = field(default_factory=list)   # [{delta,t,dir}]
    scroll_speed_avg: float = 0.0

    # Click signals
    click_events:    list  = field(default_factory=list)   # [{x,y,t,double}]
    click_precision: float = 1.0   # 0=imprecise (bot), 1=precise

    # Timing
    paste_count:     int   = 0
    tab_switches:    int   = 0
    idle_periods:    list  = field(default_factory=list)   # seconds idle
    form_autofilled: bool  = False

    # Device fingerprint
    fingerprint:     dict  = field(default_factory=dict)
    fingerprint_hash: str  = ""


@dataclass
class BiometricScore:
    trust_score:     int   = 100   # 0–100, higher = safer
    bot_probability: float = 0.0   # 0–1
    session_anomaly: int   = 0     # 0–100
    device_risk:     int   = 0     # 0–100
    risk_delta:      int   = 0     # added to fraud score (0–35)
    reasons:         list  = field(default_factory=list)
    signals:         dict  = field(default_factory=dict)


# ═════════════════════════════════════════════════════════════════════════════
# Session store  (in-memory, keyed by session_id)
# ═════════════════════════════════════════════════════════════════════════════

_SESSIONS: dict[str, BiometricSession] = {}
_DEVICE_HISTORY: dict[str, list] = defaultdict(list)  # fp_hash → [session_ids]
SESSION_TTL = 30 * 60   # 30 minutes


def _prune_sessions():
    now = time.time()
    expired = [k for k, v in _SESSIONS.items() if now - v.last_updated > SESSION_TTL]
    for k in expired:
        del _SESSIONS[k]


def get_or_create_session(session_id: str) -> BiometricSession:
    _prune_sessions()
    if session_id not in _SESSIONS:
        _SESSIONS[session_id] = BiometricSession(session_id=session_id)
    return _SESSIONS[session_id]


# ═════════════════════════════════════════════════════════════════════════════
# Behavioral analysis helpers
# ═════════════════════════════════════════════════════════════════════════════

def _analyse_mouse(events: list) -> dict:
    """
    Returns {velocities, avg_velocity, jitter, is_linear, straight_line_ratio}.
    Bots often produce perfectly linear or perfectly random mouse paths.
    """
    if len(events) < 5:
        return {"avg_velocity": 0, "jitter": 0, "is_linear": False, "straight_line_ratio": 0}

    velocities = []
    angles     = []
    prev = None
    for ev in events:
        if prev:
            dx = ev["x"] - prev["x"]
            dy = ev["y"] - prev["y"]
            dt = max(ev["t"] - prev["t"], 1)
            dist = math.sqrt(dx*dx + dy*dy)
            velocities.append(dist / dt)
            if dist > 0:
                angles.append(math.atan2(dy, dx))
        prev = ev

    avg_vel  = statistics.mean(velocities) if velocities else 0
    jitter   = statistics.stdev(velocities) if len(velocities) > 1 else 0

    # Linear detection: angle variance very low → bot-like straight lines
    angle_var = statistics.stdev(angles) if len(angles) > 1 else 0
    is_linear = angle_var < 0.05 and len(angles) > 10

    # Bezier-curve smoothness: real users move in arcs
    # Compute ratio of total path length to straight-line distance
    if len(events) >= 2:
        p0, p1 = events[0], events[-1]
        total_dist   = sum(
            math.sqrt((events[i]["x"]-events[i-1]["x"])**2 + (events[i]["y"]-events[i-1]["y"])**2)
            for i in range(1, len(events))
        )
        straight_dist = math.sqrt((p1["x"]-p0["x"])**2 + (p1["y"]-p0["y"])**2)
        straight_ratio = straight_dist / max(total_dist, 1)
    else:
        straight_ratio = 1.0

    return {
        "avg_velocity":      round(avg_vel, 2),
        "jitter":            round(jitter, 2),
        "is_linear":         is_linear,
        "straight_line_ratio": round(straight_ratio, 3),
    }


def _analyse_keystrokes(events: list) -> dict:
    """
    Returns {wpm, rhythm_variance, dwell_avg, is_robotic}.
    Robotic typing: perfectly uniform intervals.
    """
    if len(events) < 3:
        return {"wpm": 0, "rhythm_variance": 0, "dwell_avg": 0, "is_robotic": False}

    dwells   = [e.get("dwell", 80) for e in events if e.get("dwell")]
    flights  = [e.get("flight", 100) for e in events if e.get("flight")]
    chars    = len(events)

    # Time span from first to last key
    if events[0].get("t") and events[-1].get("t"):
        span_ms = max(events[-1]["t"] - events[0]["t"], 1)
        wpm     = round((chars / 5) / (span_ms / 60000), 1)
    else:
        wpm = 0

    dwell_avg   = statistics.mean(dwells)  if dwells  else 80
    rhythm_var  = statistics.stdev(flights) if len(flights) > 1 else 0

    # Very low variance = robotic (bot-like uniform timing)
    is_robotic  = rhythm_var < 5 and len(flights) > 5

    return {
        "wpm":              wpm,
        "rhythm_variance":  round(rhythm_var, 2),
        "dwell_avg":        round(dwell_avg, 2),
        "is_robotic":       is_robotic,
    }


def _analyse_scroll(events: list) -> dict:
    if not events:
        return {"avg_speed": 0, "direction_changes": 0, "is_bot_scroll": False}

    speeds    = []
    dirs      = []
    prev_t    = None
    for ev in events:
        if prev_t:
            dt = max(ev["t"] - prev_t, 1)
            speeds.append(abs(ev.get("delta", 0)) / dt)
        dirs.append(1 if ev.get("delta", 0) > 0 else -1)
        prev_t = ev["t"]

    dir_changes = sum(1 for i in range(1, len(dirs)) if dirs[i] != dirs[i-1])
    avg_speed   = statistics.mean(speeds) if speeds else 0

    # Bot scrolls: perfectly constant speed, no direction changes
    speed_var   = statistics.stdev(speeds) if len(speeds) > 1 else 0
    is_bot      = speed_var < 0.01 and len(speeds) > 5

    return {
        "avg_speed":        round(avg_speed, 3),
        "direction_changes": dir_changes,
        "is_bot_scroll":    is_bot,
    }


# ═════════════════════════════════════════════════════════════════════════════
# Device fingerprint risk scoring
# ═════════════════════════════════════════════════════════════════════════════

_KNOWN_EMULATORS = {"HeadlessChrome", "PhantomJS", "SlimerJS", "Selenium", "WebDriver"}
_BOT_UA_PATTERNS = ["headlesschrome", "phantomjs", "selenium", "puppeteer", "playwright", "bot", "crawl", "spider"]

def _score_device_fingerprint(fp: dict) -> tuple[int, list[str]]:
    """Returns (device_risk 0-100, reasons)."""
    if not fp:
        return 0, []

    risk    = 0
    reasons = []

    # User agent anomalies
    ua = (fp.get("user_agent") or "").lower()
    for pat in _BOT_UA_PATTERNS:
        if pat in ua:
            risk += 40
            reasons.append(f"[Biometrics] Automated browser detected (UA: {pat})")
            break

    # WebDriver flag — set by Selenium / Puppeteer
    if fp.get("webdriver"):
        risk += 45
        reasons.append("[Biometrics] navigator.webdriver=true — automation detected")

    # Headless: no plugins, no languages, no screen
    if not fp.get("plugins_count") and not fp.get("languages"):
        risk += 20
        reasons.append("[Biometrics] No browser plugins / languages — possible headless browser")

    # Canvas fingerprint spoofing: known blank hash
    canvas_hash = fp.get("canvas_hash", "")
    if canvas_hash in ("", "00000000", "none"):
        risk += 15
        reasons.append("[Biometrics] Canvas fingerprint blocked / spoofed")

    # Suspicious timezone vs locale mismatch
    tz    = fp.get("timezone", "")
    locale = fp.get("locale", "")
    if tz and locale:
        # Very rough: Indian locale should have India timezone
        if "IN" in locale.upper() and "Asia" not in tz and "Kolkata" not in tz:
            risk += 10
            reasons.append(f"[Biometrics] Locale/timezone mismatch ({locale} vs {tz})")

    # Emulator detection
    gpu = fp.get("gpu_renderer", "")
    if any(em.lower() in gpu.lower() for em in _KNOWN_EMULATORS):
        risk += 30
        reasons.append(f"[Biometrics] Emulated GPU renderer: {gpu}")

    # Screen size too perfect (automation)
    width  = fp.get("screen_width", 0)
    height = fp.get("screen_height", 0)
    if width in (800, 1024, 1280) and height in (600, 768, 720, 1024):
        if not fp.get("touch_support"):
            risk += 8
            reasons.append(f"[Biometrics] Suspiciously round screen resolution {width}×{height}")

    # No touch on mobile user agent
    if "mobile" in ua and not fp.get("touch_support"):
        risk += 12
        reasons.append("[Biometrics] Mobile UA but no touch support — spoofed UA")

    return min(risk, 100), reasons


# ═════════════════════════════════════════════════════════════════════════════
# Main scoring function
# ═════════════════════════════════════════════════════════════════════════════

def score_biometrics(payload: dict) -> BiometricScore:
    """
    Accepts a raw biometric payload from the JS tracker and returns
    a BiometricScore with trust/bot/anomaly/device scores.

    Payload structure (all fields optional):
    {
      "session_id":  str,
      "mouse":       [{x,y,t,type}, …],
      "keys":        [{key,dwell,flight,t}, …],
      "scroll":      [{delta,t}, …],
      "clicks":      [{x,y,t,double}, …],
      "paste_count": int,
      "tab_switches": int,
      "idle_periods": [seconds, …],
      "form_autofilled": bool,
      "device":      { ua, webdriver, canvas_hash, gpu_renderer, … }
    }
    """
    score     = BiometricScore()
    reasons   = []
    bot_votes = 0.0
    bot_total = 0.0

    # ── Mouse analysis ────────────────────────────────────────────
    mouse_data = _analyse_mouse(payload.get("mouse", []))
    if mouse_data["is_linear"]:
        bot_votes += 1.0
        reasons.append("[Biometrics] Mouse movement is perfectly linear — bot pattern")
    if mouse_data["straight_line_ratio"] > 0.95 and len(payload.get("mouse", [])) > 20:
        bot_votes += 0.5
        reasons.append("[Biometrics] Mouse path suspiciously straight (ratio > 0.95)")
    bot_total += 1.5
    score.signals["mouse"] = mouse_data

    # ── Keystroke analysis ────────────────────────────────────────
    key_data = _analyse_keystrokes(payload.get("keys", []))
    if key_data["is_robotic"]:
        bot_votes += 1.0
        reasons.append(f"[Biometrics] Keystroke timing uniform (variance {key_data['rhythm_variance']} ms) — robotic")
    if key_data["wpm"] > 250:
        bot_votes += 1.0
        reasons.append(f"[Biometrics] Typing speed {key_data['wpm']} WPM exceeds human maximum")
    bot_total += 2.0
    score.signals["keystrokes"] = key_data

    # ── Scroll analysis ───────────────────────────────────────────
    scroll_data = _analyse_scroll(payload.get("scroll", []))
    if scroll_data["is_bot_scroll"]:
        bot_votes += 0.5
        reasons.append("[Biometrics] Scroll behavior uniform — automated scrolling")
    bot_total += 0.5
    score.signals["scroll"] = scroll_data

    # ── Paste detection ───────────────────────────────────────────
    paste_count = payload.get("paste_count", 0)
    if paste_count >= 3:
        bot_votes += 0.3
        reasons.append(f"[Biometrics] {paste_count} paste events — credential stuffing risk")
    elif paste_count >= 1:
        reasons.append(f"[Biometrics] {paste_count} paste event(s) detected")
    score.signals["paste_count"] = paste_count

    # ── Tab switch frequency ──────────────────────────────────────
    tab_sw = payload.get("tab_switches", 0)
    if tab_sw > 10:
        bot_votes += 0.2
        reasons.append(f"[Biometrics] {tab_sw} tab switches — unusual session pattern")
    score.signals["tab_switches"] = tab_sw

    # ── Form autofill ─────────────────────────────────────────────
    if payload.get("form_autofilled"):
        # Autofill skips keystroke dynamics — flag for attention
        reasons.append("[Biometrics] Form auto-filled — keystroke dynamics unavailable")
    score.signals["form_autofilled"] = payload.get("form_autofilled", False)

    # ── Device fingerprint ────────────────────────────────────────
    device   = payload.get("device", {})
    dev_risk, dev_reasons = _score_device_fingerprint(device)
    reasons.extend(dev_reasons)
    score.device_risk = dev_risk
    score.signals["device"] = {
        "risk":   dev_risk,
        "ua":     device.get("user_agent", "")[:80],
        "canvas": device.get("canvas_hash", "")[:12],
        "gpu":    device.get("gpu_renderer", "")[:60],
    }

    # Compute fingerprint hash for device identity tracking
    fp_str  = "|".join(str(device.get(k, "")) for k in sorted(device.keys()))
    fp_hash = hashlib.sha256(fp_str.encode()).hexdigest()[:16]
    score.signals["fingerprint_hash"] = fp_hash

    # Device risk contributes to bot probability
    if dev_risk >= 40:
        bot_votes += 1.5
        bot_total += 1.5
    elif dev_risk >= 20:
        bot_votes += 0.5
        bot_total += 0.5

    # ── Bot probability ───────────────────────────────────────────
    if bot_total > 0:
        score.bot_probability = round(min(1.0, bot_votes / bot_total), 3)
    else:
        score.bot_probability = 0.0

    # ── Trust score (inverse of bot probability + device risk) ───
    trust = 100 - int(score.bot_probability * 60) - int(dev_risk * 0.4)
    score.trust_score = max(0, min(100, trust))

    # ── Session anomaly ───────────────────────────────────────────
    anomaly = 0
    if score.bot_probability > 0.7: anomaly += 50
    elif score.bot_probability > 0.4: anomaly += 25
    anomaly += int(dev_risk * 0.5)
    score.session_anomaly = min(100, anomaly)

    # ── Risk delta (0–35) ─────────────────────────────────────────
    delta = 0
    if score.bot_probability > 0.8:  delta = 35
    elif score.bot_probability > 0.6: delta = 25
    elif score.bot_probability > 0.4: delta = 15
    elif score.bot_probability > 0.2: delta = 8
    delta = max(delta, int(dev_risk * 0.3))
    score.risk_delta = min(35, delta)

    score.reasons = reasons
    return score


# Singleton
class BiometricsEngine:
    def score(self, payload: dict) -> BiometricScore:
        return score_biometrics(payload)

    @property
    def active_sessions(self) -> int:
        _prune_sessions()
        return len(_SESSIONS)


biometrics_engine = BiometricsEngine()
