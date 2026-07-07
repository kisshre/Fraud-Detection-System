"""
FRAUD-X  ·  Analyst Feedback & Online Learning Engine
======================================================
Closes the feedback loop between analyst decisions and the ML models.

Features
--------
  SQLite ledger       — every decision + analyst label persisted
  Online learning     — triggers partial_fit on fraud_ensemble after N cases
  Drift detection     — PSI (Population Stability Index) on score distributions
  Risk engine update  — forwards confirmed outcomes to adaptive weight tracker
  REST-ready          — designed to be called from main.py endpoints

Usage
-----
  fb = FeedbackEngine()
  fb.record(transaction_id, signal_scores, final_score, predicted_band,
            analyst_label, analyst_id)
  report = fb.drift_report()
  fb.retrain_trigger()       # manual trigger of online learning pass
"""

from __future__ import annotations

import json
import logging
import math
import sqlite3
import statistics
import time
from collections import defaultdict, deque
from pathlib import Path
from threading import Lock
from typing import Dict, List, Optional

logger = logging.getLogger("fraudx.feedback")

_DB_PATH = Path(__file__).parent / "models" / "feedback.db"
_DB_PATH.parent.mkdir(exist_ok=True)

# Trigger online learning pass after this many new confirmed labels
ONLINE_LEARN_BATCH = 20

# PSI buckets for drift detection
PSI_BUCKETS = 10

# Rolling window size for recent score distribution comparison
RECENT_WINDOW = 500


# ═════════════════════════════════════════════════════════════════════════════
# SQLite schema
# ═════════════════════════════════════════════════════════════════════════════

_DDL = """
CREATE TABLE IF NOT EXISTS feedback_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    transaction_id  TEXT    NOT NULL,
    ts              REAL    NOT NULL,
    final_score     INTEGER NOT NULL,
    predicted_band  TEXT    NOT NULL,
    analyst_label   INTEGER,          -- 1=fraud, 0=legit, NULL=pending
    analyst_id      TEXT,
    resolved_at     REAL,
    signal_scores   TEXT,             -- JSON blob of per-engine scores
    was_correct     INTEGER           -- 1 correct, 0 incorrect, NULL pending
);

CREATE TABLE IF NOT EXISTS drift_snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL    NOT NULL,
    psi         REAL    NOT NULL,
    mean_score  REAL    NOT NULL,
    std_score   REAL    NOT NULL,
    fraud_rate  REAL    NOT NULL,
    sample_n    INTEGER NOT NULL,
    details     TEXT                  -- JSON
);

CREATE INDEX IF NOT EXISTS idx_feedback_ts  ON feedback_log(ts);
CREATE INDEX IF NOT EXISTS idx_feedback_tid ON feedback_log(transaction_id);
"""


# ═════════════════════════════════════════════════════════════════════════════
# PSI helper
# ═════════════════════════════════════════════════════════════════════════════

def _psi(expected: List[float], actual: List[float], buckets: int = PSI_BUCKETS) -> float:
    """Population Stability Index between two score distributions."""
    if len(expected) < buckets or len(actual) < buckets:
        return 0.0
    edges = [i / buckets for i in range(buckets + 1)]
    eps = 1e-7

    def _bucket_fracs(vals):
        n = len(vals)
        fracs = []
        for lo, hi in zip(edges[:-1], edges[1:]):
            count = sum(1 for v in vals if lo <= v < hi)
            fracs.append(max(count / n, eps))
        # last bucket inclusive
        fracs[-1] = max(sum(1 for v in vals if v >= edges[-2]) / n, eps)
        return fracs

    e_fracs = _bucket_fracs([v / 100 for v in expected])
    a_fracs = _bucket_fracs([v / 100 for v in actual])
    psi_val = sum((a - e) * math.log(a / e) for a, e in zip(a_fracs, e_fracs))
    return round(psi_val, 6)


# ═════════════════════════════════════════════════════════════════════════════
# FeedbackEngine
# ═════════════════════════════════════════════════════════════════════════════

class FeedbackEngine:

    def __init__(self) -> None:
        self._lock      = Lock()
        self._pending   = 0          # labels received since last online pass
        self._baseline: List[float] = []   # first RECENT_WINDOW scores = baseline
        self._recent:   deque       = deque(maxlen=RECENT_WINDOW)
        self._conn      = self._init_db()
        self._load_baseline()

    # ── DB setup ──────────────────────────────────────────────────────────────

    def _init_db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(_DB_PATH), check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(_DDL)
        conn.commit()
        logger.info("[FB] SQLite feedback DB at %s", _DB_PATH)
        return conn

    def _load_baseline(self) -> None:
        rows = self._conn.execute(
            "SELECT final_score FROM feedback_log ORDER BY ts LIMIT ?",
            (RECENT_WINDOW,),
        ).fetchall()
        if len(rows) >= PSI_BUCKETS * 2:
            self._baseline = [r[0] for r in rows]
        for r in rows:
            self._recent.append(r[0])
        logger.debug("[FB] Loaded %d baseline scores", len(self._baseline))

    # ── Record a new decision ─────────────────────────────────────────────────

    def record(
        self,
        transaction_id: str,
        signal_scores: Dict[str, float],
        final_score: int,
        predicted_band: str,
        analyst_label: Optional[int] = None,
        analyst_id: Optional[str] = None,
    ) -> int:
        """
        Persist a fraud decision. Returns the row id.
        analyst_label: 1=confirmed fraud, 0=confirmed legit, None=pending review.
        """
        now = time.time()
        with self._lock:
            cur = self._conn.execute(
                """INSERT INTO feedback_log
                   (transaction_id, ts, final_score, predicted_band,
                    analyst_label, analyst_id, resolved_at, signal_scores, was_correct)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    transaction_id, now, final_score, predicted_band,
                    analyst_label, analyst_id,
                    now if analyst_label is not None else None,
                    json.dumps(signal_scores),
                    self._correctness(final_score, predicted_band, analyst_label),
                ),
            )
            self._conn.commit()
            row_id = cur.lastrowid

        self._recent.append(final_score)
        if not self._baseline and len(self._recent) >= RECENT_WINDOW:
            self._baseline = list(self._recent)

        if analyst_label is not None:
            self._on_label_received(signal_scores, bool(analyst_label))

        return row_id

    def resolve(
        self,
        transaction_id: str,
        analyst_label: int,
        analyst_id: Optional[str] = None,
    ) -> bool:
        """Update a pending decision with analyst label."""
        row = self._conn.execute(
            "SELECT id, final_score, predicted_band, signal_scores FROM feedback_log "
            "WHERE transaction_id = ? ORDER BY ts DESC LIMIT 1",
            (transaction_id,),
        ).fetchone()
        if not row:
            return False

        rid, final_score, band, sigs_json = row
        sigs = json.loads(sigs_json or "{}")
        correct = self._correctness(final_score, band, analyst_label)

        with self._lock:
            self._conn.execute(
                "UPDATE feedback_log SET analyst_label=?, analyst_id=?, "
                "resolved_at=?, was_correct=? WHERE id=?",
                (analyst_label, analyst_id, time.time(), correct, rid),
            )
            self._conn.commit()

        self._on_label_received(sigs, bool(analyst_label))
        return True

    # ── Internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _correctness(score: int, band: str, label: Optional[int]) -> Optional[int]:
        if label is None:
            return None
        predicted_fraud = band in ("high", "critical")
        return int(predicted_fraud == bool(label))

    def _on_label_received(self, signal_scores: Dict[str, float], was_fraud: bool) -> None:
        """Called whenever a confirmed label arrives."""
        # Update adaptive weights in risk engine
        try:
            from risk_engine_v2 import risk_engine_v2
            risk_engine_v2.report_outcome(signal_scores, was_fraud)
        except Exception as exc:
            logger.debug("[FB] Risk engine update failed: %s", exc)

        self._pending += 1
        if self._pending >= ONLINE_LEARN_BATCH:
            self._run_online_learning()
            self._pending = 0

    def _run_online_learning(self) -> None:
        """Fetch recent confirmed rows and partial_fit the ensemble."""
        try:
            from advanced_ml_engine import fraud_ensemble
            if not fraud_ensemble.is_ready:
                return

            rows = self._conn.execute(
                """SELECT signal_scores, analyst_label FROM feedback_log
                   WHERE analyst_label IS NOT NULL
                   ORDER BY resolved_at DESC LIMIT ?""",
                (ONLINE_LEARN_BATCH * 2,),
            ).fetchall()

            if len(rows) < 5:
                return

            import numpy as np
            X, y = [], []
            for sigs_json, label in rows:
                sigs = json.loads(sigs_json or "{}")
                if sigs:
                    vec = list(sigs.values())
                    X.append(vec)
                    y.append(int(label))

            if len(X) >= 5:
                X_arr = np.array(X, dtype=float)
                y_arr = np.array(y, dtype=int)
                fraud_ensemble.partial_fit(X_arr, y_arr)
                logger.info("[FB] Online learning pass: %d samples", len(X))
        except Exception as exc:
            logger.warning("[FB] Online learning failed: %s", exc)

    # ── Drift detection ───────────────────────────────────────────────────────

    def drift_report(self) -> Dict:
        """
        Compare recent score distribution to baseline.
        PSI < 0.1 = stable, 0.1–0.2 = moderate drift, > 0.2 = significant drift.
        """
        recent_scores = list(self._recent)
        if len(recent_scores) < PSI_BUCKETS:
            return {"status": "insufficient_data", "sample_n": len(recent_scores)}

        psi = _psi(self._baseline or recent_scores, recent_scores)
        mean_s = round(statistics.mean(recent_scores), 2)
        std_s  = round(statistics.stdev(recent_scores) if len(recent_scores) > 1 else 0, 2)

        # Recent fraud rate
        rows = self._conn.execute(
            "SELECT analyst_label FROM feedback_log "
            "WHERE analyst_label IS NOT NULL ORDER BY ts DESC LIMIT ?",
            (RECENT_WINDOW,),
        ).fetchall()
        labels = [r[0] for r in rows]
        fraud_rate = round(sum(labels) / len(labels), 4) if labels else 0.0

        drift_level = (
            "stable"     if psi < 0.10 else
            "moderate"   if psi < 0.20 else
            "significant"
        )

        report = {
            "psi":         psi,
            "drift_level": drift_level,
            "mean_score":  mean_s,
            "std_score":   std_s,
            "fraud_rate":  fraud_rate,
            "sample_n":    len(recent_scores),
            "baseline_n":  len(self._baseline),
            "recommendation": (
                "Monitor closely — retrain recommended" if psi > 0.20 else
                "Minor distribution shift detected"     if psi > 0.10 else
                "Distribution stable"
            ),
        }

        # Persist snapshot
        with self._lock:
            self._conn.execute(
                "INSERT INTO drift_snapshots (ts, psi, mean_score, std_score, fraud_rate, sample_n, details) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (time.time(), psi, mean_s, std_s, fraud_rate,
                 len(recent_scores), json.dumps(report)),
            )
            self._conn.commit()

        logger.info("[FB] Drift report: PSI=%.4f (%s)", psi, drift_level)
        return report

    # ── Retrain trigger ───────────────────────────────────────────────────────

    def retrain_trigger(self, force: bool = False) -> Dict:
        """
        Manually trigger online learning pass or full retrain advisory.
        Returns status dict.
        """
        report = self.drift_report()
        if force or report.get("drift_level") in ("moderate", "significant"):
            self._run_online_learning()
            return {
                "action":      "online_learning_triggered",
                "drift_level": report.get("drift_level"),
                "psi":         report.get("psi"),
            }
        return {
            "action":      "no_action",
            "drift_level": report.get("drift_level"),
            "psi":         report.get("psi"),
        }

    # ── Summaries ─────────────────────────────────────────────────────────────

    def stats(self) -> Dict:
        rows = self._conn.execute(
            "SELECT COUNT(*), SUM(analyst_label), SUM(was_correct), "
            "AVG(final_score) FROM feedback_log"
        ).fetchone()
        total, fraud_count, correct, avg_score = rows
        total      = total or 0
        labeled    = self._conn.execute(
            "SELECT COUNT(*) FROM feedback_log WHERE analyst_label IS NOT NULL"
        ).fetchone()[0]
        return {
            "total_decisions":  total,
            "labeled":          labeled,
            "pending_review":   total - labeled,
            "confirmed_fraud":  int(fraud_count or 0),
            "correct_calls":    int(correct or 0),
            "accuracy":         round(correct / labeled, 4) if labeled else None,
            "avg_final_score":  round(avg_score or 0, 1),
            "pending_learn":    self._pending,
        }

    def recent_errors(self, limit: int = 20) -> List[Dict]:
        """Return recent incorrect predictions for analyst review."""
        rows = self._conn.execute(
            "SELECT transaction_id, ts, final_score, predicted_band, "
            "analyst_label, analyst_id, signal_scores FROM feedback_log "
            "WHERE was_correct = 0 ORDER BY ts DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            {
                "transaction_id": r[0],
                "ts":             r[1],
                "final_score":    r[2],
                "predicted_band": r[3],
                "analyst_label":  r[4],
                "analyst_id":     r[5],
                "signal_scores":  json.loads(r[6] or "{}"),
            }
            for r in rows
        ]

    def reset_baseline(self) -> None:
        """Reset drift baseline to the current score distribution."""
        self._baseline = list(self._recent)
        logger.info("[FB] Drift baseline reset to %d samples", len(self._baseline))

    def close(self) -> None:
        self._conn.close()


# ── Singleton ──────────────────────────────────────────────────────────────────
feedback_engine = FeedbackEngine()
