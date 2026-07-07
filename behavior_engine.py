"""
FRAUD-X  ·  Behavioral Analysis Engine  v2
===========================================
Detects anomalies and coordinated patterns across the full scan session.

Detection layers
----------------
  Velocity        — same target scanned too often in a short window
  Persistence     — same target consistently scores high over lifetime
  Score drift     — target that used to score high now scores low (evasion)
  Burst           — sudden spike in a scan category
  Cluster         — many targets sharing a common prefix (coordinated sweep)
  Campaign        — ≥10 total scans or ≥5 high-risk hits on one entity
  Alert spike     — current alert rate ≥3× rolling baseline (system-wide surge)
  Domain sweep    — same domain reached via multiple scan types (URL + email + SMS)

Public API
----------
  analyze(kind, target, score)  → (adjustment, signals)   [before record()]
  record(kind, target, score)                              [after analyze()]
  post_alert(kind, target, score, alert_id) → List[str]   [called by record_alert()]
  get_campaigns(active_only)    → List[Dict]
  get_hot_targets(kind, top_n)  → List[Dict]
  kind_baseline(kind)           → Dict
  velocity_stats()              → Dict
"""
from __future__ import annotations

import math
import time
import uuid
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse


# ── Tunables ────────────────────────────────────────────────────
VELOCITY_WINDOW_SEC    = 300    # 5-minute window for rapid repeat detection
BURST_WINDOW_SEC       = 60     # 60-second window for category burst
SPIKE_SHORT_SEC        = 300    # last 5 min for spike numerator
SPIKE_LONG_SEC         = 3600   # last 60 min for spike denominator baseline
SPIKE_MULTIPLIER       = 3.0    # current rate must be ≥ 3× baseline to fire
CAMPAIGN_SCAN_THRESH   = 10     # lifetime scans before campaign is declared
CAMPAIGN_FRAUD_THRESH  = 5      # high-risk (≥65) hits before campaign declared
DOMAIN_SWEEP_THRESH    = 3      # distinct scan kinds on same domain before sweep alert
HIGH_RISK_CUTOFF       = 65     # score ≥ this counts as a fraud incident


def _extract_domain(kind: str, target: str) -> Optional[str]:
    """Best-effort domain extraction from a scan target."""
    try:
        if kind in ("url", "qr"):
            host = urlparse(target).hostname or ""
            return host.lower() or None
        if kind == "email" and "@" in target:
            return target.split("@")[-1].lower()
        if kind == "sms":
            # target might be the raw message — try to find a URL
            for token in target.split():
                h = urlparse(token).hostname
                if h:
                    return h.lower()
        if kind == "domain":
            return target.lower()
    except Exception:
        pass
    return None


class BehaviorEngine:

    def __init__(self, window_sec: int = 3600) -> None:
        self._window = window_sec

        # ── Per-scan circular buffer: (ts, key, kind, score) ────
        self._recent: deque = deque(maxlen=5000)

        # ── Per-target history ───────────────────────────────────
        self._target_ts:       Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self._target_scores:   Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))
        self._target_total:    Dict[str, int]   = defaultdict(int)
        self._target_fraud:    Dict[str, int]   = defaultdict(int)
        self._target_alert_ids: Dict[str, deque] = defaultdict(lambda: deque(maxlen=20))
        self._target_first_seen: Dict[str, float] = {}

        # ── Per-kind score buffers for baseline computation ──────
        self._kind_scores: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))

        # ── Cluster: 20-char prefix → unique targets ─────────────
        self._cluster: Dict[str, List[str]] = defaultdict(list)

        # ── Domain cross-kind sweep ──────────────────────────────
        # domain → set of scan kinds that encountered it
        self._domain_kinds: Dict[str, Set[str]] = defaultdict(set)
        self._domain_fraud_count: Dict[str, int] = defaultdict(int)

        # ── Campaign registry ────────────────────────────────────
        self._campaigns: Dict[str, Dict] = {}   # key → campaign dict

        # ── Alert timestamps (system-wide, for spike) ────────────
        self._alert_ts: deque = deque(maxlen=10000)

    # ── Internal key helpers ─────────────────────────────────────

    def _key(self, kind: str, target: str) -> str:
        return f"{kind}:{target[:100]}"

    # ── Recording ────────────────────────────────────────────────

    def record(self, kind: str, target: str, score: int) -> None:
        """Record one completed scan. Call AFTER analyze()."""
        now = time.time()
        key = self._key(kind, target)

        self._recent.append((now, key, kind, score))
        self._alert_ts.append(now)

        self._target_ts[key].append(now)
        self._target_scores[key].append(float(score))
        self._target_total[key] += 1
        if score >= HIGH_RISK_CUTOFF:
            self._target_fraud[key] += 1
        if key not in self._target_first_seen:
            self._target_first_seen[key] = now

        self._kind_scores[kind].append(float(score))

        # Cluster prefix
        ckey = f"{kind}:{target[:20]}"
        lst  = self._cluster[ckey]
        if target not in lst:
            lst.append(target)
        if len(lst) > 200:
            lst.pop(0)

        # Domain cross-kind tracking
        domain = _extract_domain(kind, target)
        if domain:
            self._domain_kinds[domain].add(kind)
            if score >= HIGH_RISK_CUTOFF:
                self._domain_fraud_count[domain] += 1

    def post_alert(
        self, kind: str, target: str, score: int, alert_id: str
    ) -> List[str]:
        """
        Called by record_alert() after every scan is persisted.
        Registers alert IDs against targets, promotes to campaign if thresholds hit.
        Returns any new campaign signals (informational, not score adjustments).
        """
        key = self._key(kind, target)
        self._target_alert_ids[key].appendleft(alert_id)

        signals: List[str] = []
        total  = self._target_total.get(key, 0)
        fraud  = self._target_fraud.get(key, 0)

        # ── Campaign threshold ────────────────────────────────
        triggered = False
        trigger   = ""
        if total >= CAMPAIGN_SCAN_THRESH and key not in self._campaigns:
            triggered = True
            trigger   = f"repeat_scan_{total}"
        elif fraud >= CAMPAIGN_FRAUD_THRESH and key not in self._campaigns:
            triggered = True
            trigger   = f"high_risk_hits_{fraud}"

        if triggered:
            scores = list(self._target_scores.get(key, []))
            avg    = sum(scores) / len(scores) if scores else 0.0
            domain = _extract_domain(kind, target)
            self._campaigns[key] = {
                "id":          str(uuid.uuid4()),
                "kind":        kind,
                "target":      target[:120],
                "domain":      domain,
                "trigger":     trigger,
                "scan_count":  total,
                "fraud_count": fraud,
                "avg_score":   round(avg, 1),
                "first_seen":  self._target_first_seen.get(key, time.time()),
                "last_seen":   time.time(),
                "alert_ids":   list(self._target_alert_ids[key])[:10],
                "is_active":   True,
            }
            signals.append(
                f"[Campaign] '{target[:60]}' promoted to active campaign "
                f"({total} scans, {fraud} fraud hits, avg score {avg:.0f}/100)."
            )
        elif key in self._campaigns:
            # Update existing campaign record
            c = self._campaigns[key]
            c["scan_count"]  = total
            c["fraud_count"] = fraud
            c["last_seen"]   = time.time()
            scores = list(self._target_scores.get(key, []))
            if scores:
                c["avg_score"] = round(sum(scores) / len(scores), 1)
            c["alert_ids"] = list(self._target_alert_ids[key])[:10]

        # ── Domain sweep ─────────────────────────────────────
        domain = _extract_domain(kind, target)
        if domain:
            kinds_seen = self._domain_kinds.get(domain, set())
            if (len(kinds_seen) >= DOMAIN_SWEEP_THRESH
                    and f"sweep:{domain}" not in self._campaigns):
                fc = self._domain_fraud_count.get(domain, 0)
                self._campaigns[f"sweep:{domain}"] = {
                    "id":          str(uuid.uuid4()),
                    "kind":        "domain_sweep",
                    "target":      domain,
                    "domain":      domain,
                    "trigger":     f"domain_sweep_{len(kinds_seen)}_kinds",
                    "scan_count":  0,
                    "fraud_count": fc,
                    "avg_score":   0.0,
                    "first_seen":  time.time(),
                    "last_seen":   time.time(),
                    "alert_ids":   [],
                    "is_active":   True,
                    "kinds":       list(kinds_seen),
                }
                signals.append(
                    f"[Campaign] Domain '{domain}' reached via {len(kinds_seen)} scan types "
                    f"({', '.join(sorted(kinds_seen))}) — multi-vector sweep."
                )

        return signals

    # ── Pre-scan analysis (returns score adjustment) ─────────────

    def analyze(
        self, kind: str, target: str, score: int
    ) -> Tuple[int, List[str]]:
        """
        Analyse behavioural context BEFORE recording the current scan.
        Returns (score_adjustment, behavioral_signals).

        Checks (in order):
          1. Velocity      — same target scanned ≥3× in 5 min
          2. Campaign      — target already registered as an active campaign
          3. Persistence   — consistently high scores over lifetime
          4. Score drift   — high → low transition (evasion)
          5. Burst         — category scan spike in 60 s
          6. Cluster       — many similar targets scanned together
          7. Alert spike   — system-wide surge
        """
        now     = time.time()
        key     = self._key(kind, target)
        signals: List[str] = []
        adj     = 0

        ts_buf    = self._target_ts.get(key, deque())
        score_buf = self._target_scores.get(key, deque())
        total     = self._target_total.get(key, 0)
        fraud_ct  = self._target_fraud.get(key, 0)

        # 1 ── Velocity: same target in last 5 min ───────────────
        recent_5m = sum(1 for t in ts_buf if now - t < VELOCITY_WINDOW_SEC)
        if recent_5m >= 10:
            adj += 15
            signals.append(
                f"[Behavioral] Campaign velocity: '{target[:45]}' scanned "
                f"{recent_5m}× in 5 min — automated scanning campaign."
            )
        elif recent_5m >= 5:
            adj += 12
            signals.append(
                f"[Behavioral] High velocity: '{target[:45]}' scanned "
                f"{recent_5m}× in 5 min — possible automated probing."
            )
        elif recent_5m >= 3:
            adj += 6
            signals.append(
                f"[Behavioral] Repeated scan: '{target[:45]}' seen "
                f"{recent_5m}× recently."
            )

        # 2 ── Active campaign membership ────────────────────────
        if key in self._campaigns and self._campaigns[key]["is_active"]:
            c = self._campaigns[key]
            adj += 10
            signals.append(
                f"[Behavioral] Active campaign: this {kind} is part of an ongoing "
                f"fraud campaign ({c['scan_count']} scans, "
                f"{c['fraud_count']} fraud hits, avg {c['avg_score']}/100)."
            )
        elif total >= CAMPAIGN_SCAN_THRESH:
            adj += 8
            signals.append(
                f"[Behavioral] Recurring target: '{target[:45]}' has been scanned "
                f"{total} times total ({fraud_ct} as high-risk)."
            )

        # 3 ── Persistence: consistently high ────────────────────
        if len(score_buf) >= 3:
            recent_avg = sum(list(score_buf)[-3:]) / 3
            if recent_avg >= 55 and score <= 20:
                # Score drop — likely evasion
                signals.append(
                    f"[Behavioral] Score drop on known-bad {kind}: previously "
                    f"avg {recent_avg:.0f}/100 but now {score}/100 — possible obfuscation."
                )
            elif recent_avg >= 55 and score >= 55:
                adj += 8
                signals.append(
                    f"[Behavioral] Persistent high-risk {kind}: consistently "
                    f"scores ≥55 (recent avg {recent_avg:.0f}/100)."
                )

        # 4 ── Burst: category spike ──────────────────────────────
        kind_last_60s = sum(
            1 for ts, _, k, _ in self._recent
            if k == kind and now - ts < BURST_WINDOW_SEC
        )
        if kind_last_60s >= 30:
            adj += 5
            signals.append(
                f"[Behavioral] Burst: {kind_last_60s} {kind} scans in 60 s — "
                f"unusual scan volume."
            )

        # 5 ── Cluster: coordinated sweep ────────────────────────
        ckey           = f"{kind}:{target[:20]}"
        cluster        = self._cluster.get(ckey, [])
        unique_cluster = len(set(cluster))
        if unique_cluster >= 8:
            adj += 7
            signals.append(
                f"[Behavioral] Campaign cluster: {unique_cluster} distinct {kind} targets "
                f"share a common prefix — coordinated fraud wave."
            )

        # 6 ── System-wide alert spike ────────────────────────────
        spike, spike_msg = self._alert_spike()
        if spike:
            signals.append(spike_msg)
            adj += 3   # small bump; the spike itself is the main signal

        return min(adj, 25), signals[:3]

    # ── Alert spike detection ─────────────────────────────────────

    def _alert_spike(self) -> Tuple[bool, str]:
        """
        Returns (True, message) if the current alert rate is ≥ SPIKE_MULTIPLIER
        times the rolling hourly baseline.
        """
        now       = time.time()
        short_win = sum(1 for t in self._alert_ts if now - t < SPIKE_SHORT_SEC)
        long_win  = sum(1 for t in self._alert_ts if now - t < SPIKE_LONG_SEC)

        # Normalise to the same per-second rate
        short_rate = short_win / SPIKE_SHORT_SEC
        long_rate  = long_win  / SPIKE_LONG_SEC

        # Need enough data before declaring a spike
        if long_win < 20 or long_rate == 0:
            return False, ""

        if short_rate >= SPIKE_MULTIPLIER * long_rate:
            ratio = short_rate / long_rate
            return True, (
                f"[Behavioral] Alert spike: {short_win} scans in last 5 min "
                f"({ratio:.1f}× the hourly baseline) — surge detected."
            )
        return False, ""

    # ── Campaign queries ──────────────────────────────────────────

    def get_campaigns(self, active_only: bool = True) -> List[Dict]:
        """Return campaign records, sorted by fraud_count descending."""
        campaigns = list(self._campaigns.values())
        if active_only:
            campaigns = [c for c in campaigns if c.get("is_active", True)]
        return sorted(campaigns, key=lambda c: (-c["fraud_count"], -c["scan_count"]))

    def mark_campaign_resolved(self, campaign_id: str) -> bool:
        """Mark a campaign as no longer active."""
        for c in self._campaigns.values():
            if c["id"] == campaign_id:
                c["is_active"] = False
                return True
        return False

    def get_hot_targets(
        self,
        kind: Optional[str] = None,
        top_n: int = 10,
        window_sec: int = 3600,
    ) -> List[Dict]:
        """
        Return the most-scanned targets in the last `window_sec` seconds.
        Optionally filter to a single scan kind.
        """
        now   = time.time()
        counts: Dict[str, int] = defaultdict(int)
        fraud:  Dict[str, int] = defaultdict(int)

        for ts, key, k, sc in self._recent:
            if now - ts > window_sec:
                continue
            if kind and k != kind:
                continue
            counts[key] += 1
            if sc >= HIGH_RISK_CUTOFF:
                fraud[key] += 1

        result = []
        for key, cnt in sorted(counts.items(), key=lambda x: -x[1])[:top_n]:
            k, target = key.split(":", 1) if ":" in key else ("?", key)
            scores    = list(self._target_scores.get(key, []))
            avg       = round(sum(scores) / len(scores), 1) if scores else 0.0
            total     = self._target_total.get(key, cnt)
            result.append({
                "key":            key,
                "kind":           k,
                "target":         target,
                "scans_in_window": cnt,
                "total_scans":    total,
                "fraud_hits":     fraud.get(key, 0),
                "avg_score":      avg,
                "is_campaign":    key in self._campaigns,
            })
        return result

    def get_domain_sweep_summary(self) -> List[Dict]:
        """Return domains that have appeared in multiple scan types."""
        result = []
        for domain, kinds in self._domain_kinds.items():
            if len(kinds) < 2:
                continue
            result.append({
                "domain":      domain,
                "scan_kinds":  sorted(kinds),
                "kind_count":  len(kinds),
                "fraud_count": self._domain_fraud_count.get(domain, 0),
                "is_sweep":    len(kinds) >= DOMAIN_SWEEP_THRESH,
            })
        return sorted(result, key=lambda x: (-x["kind_count"], -x["fraud_count"]))

    # ── Baselines ─────────────────────────────────────────────────

    def kind_baseline(self, kind: str) -> Dict:
        scores = list(self._kind_scores.get(kind, []))
        if not scores:
            return {"mean": 0.0, "std": 0.0, "count": 0, "high_risk_pct": 0.0}
        mean = sum(scores) / len(scores)
        var  = sum((s - mean) ** 2 for s in scores) / len(scores)
        return {
            "mean":          round(mean, 1),
            "std":           round(math.sqrt(var), 1),
            "count":         len(scores),
            "high_risk_pct": round(100 * sum(1 for s in scores if s >= HIGH_RISK_CUTOFF) / len(scores), 1),
        }

    def velocity_stats(self) -> Dict:
        now     = time.time()
        last_hr = [(ts, kind, sc) for ts, _, kind, sc in self._recent if now - ts < 3600]
        last_5m = [x for x in last_hr if now - x[0] < 300]
        by_kind: Dict[str, int] = defaultdict(int)
        for _, k, _ in last_hr:
            by_kind[k] += 1
        spike, spike_msg = self._alert_spike()
        return {
            "last_hour":      len(last_hr),
            "last_5min":      len(last_5m),
            "by_kind":        dict(by_kind),
            "danger_count":   sum(1 for _, _, sc in last_hr if sc >= HIGH_RISK_CUTOFF),
            "avg_score":      round(sum(sc for _, _, sc in last_hr) / max(len(last_hr), 1), 1),
            "active_campaigns": len([c for c in self._campaigns.values() if c.get("is_active")]),
            "alert_spike":    spike,
            "spike_message":  spike_msg if spike else None,
        }


# ── Singleton ────────────────────────────────────────────────────
behavior_engine = BehaviorEngine()
