"""
FRAUD-X  ·  SQLite Persistence Layer
=====================================
Stores alerts, entity links, and scan patterns.

Schema
------
  alerts        — every scan result (primary alert store)
  entity_links  — directed edges between fraud entities
  scan_patterns — per-target scan frequency counters

All writes use WAL mode for concurrent read safety.
"""
import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, List, Optional

DB_PATH = Path(__file__).parent / "fraudx.db"


@contextmanager
def _conn():
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    try:
        yield con
        con.commit()
    finally:
        con.close()


def init_db() -> None:
    with _conn() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          TEXT PRIMARY KEY,
            kind        TEXT NOT NULL,
            target      TEXT NOT NULL,
            risk_score  INTEGER NOT NULL,
            risk_level  TEXT NOT NULL,
            reasons     TEXT NOT NULL,
            ai_analysis TEXT DEFAULT '',
            ledger_hash TEXT DEFAULT '',
            timestamp   REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_alerts_kind  ON alerts(kind);
        CREATE INDEX IF NOT EXISTS ix_alerts_level ON alerts(risk_level);
        CREATE INDEX IF NOT EXISTS ix_alerts_ts    ON alerts(timestamp DESC);
        CREATE INDEX IF NOT EXISTS ix_alerts_tgt   ON alerts(target);

        CREATE TABLE IF NOT EXISTS ledger_blocks (
            idx          INTEGER PRIMARY KEY,
            timestamp    REAL NOT NULL,
            alert_id     TEXT NOT NULL,
            payload_hash TEXT NOT NULL,
            prev_hash    TEXT NOT NULL,
            block_hash   TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS entity_links (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            src_type     TEXT NOT NULL,
            src_value    TEXT NOT NULL,
            dst_type     TEXT NOT NULL,
            dst_value    TEXT NOT NULL,
            relation     TEXT NOT NULL,
            alert_id     TEXT DEFAULT '',
            timestamp    REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS ix_links_src ON entity_links(src_type, src_value);
        CREATE INDEX IF NOT EXISTS ix_links_dst ON entity_links(dst_type, dst_value);

        CREATE TABLE IF NOT EXISTS scan_patterns (
            pattern_key  TEXT NOT NULL,
            kind         TEXT NOT NULL,
            scan_count   INTEGER DEFAULT 1,
            last_seen    REAL NOT NULL,
            first_seen   REAL NOT NULL,
            avg_score    REAL DEFAULT 0.0,
            PRIMARY KEY (pattern_key, kind)
        );
        """)
        # Schema migration: add notes column to existing databases
        existing = {r[1] for r in con.execute("PRAGMA table_info(alerts)").fetchall()}
        if "notes" not in existing:
            con.execute("ALTER TABLE alerts ADD COLUMN notes TEXT DEFAULT ''")


# ═══════════════════════════════════════════════════════════════════
# Alert writes
# ═══════════════════════════════════════════════════════════════════

def save_alert(
    alert_id: str, kind: str, target: str, risk_score: int,
    risk_level: str, reasons: List[str], ai_analysis: str,
    ledger_hash: str, timestamp: float,
) -> None:
    with _conn() as con:
        con.execute(
            """
            INSERT OR REPLACE INTO alerts
              (id, kind, target, risk_score, risk_level, reasons,
               ai_analysis, ledger_hash, timestamp)
            VALUES (?,?,?,?,?,?,?,?,?)
            """,
            (alert_id, kind, target, risk_score, risk_level,
             json.dumps(reasons), ai_analysis, ledger_hash, timestamp),
        )
        key = f"{kind}:{target[:100]}"
        con.execute(
            """
            INSERT INTO scan_patterns (pattern_key, kind, scan_count, last_seen, first_seen, avg_score)
            VALUES (?,?,1,?,?,?)
            ON CONFLICT(pattern_key, kind) DO UPDATE SET
                scan_count = scan_count + 1,
                last_seen  = excluded.last_seen,
                avg_score  = (avg_score * scan_count + excluded.avg_score) / (scan_count + 1)
            """,
            (key, kind, timestamp, timestamp, float(risk_score)),
        )


# ═══════════════════════════════════════════════════════════════════
# Alert CRUD
# ═══════════════════════════════════════════════════════════════════

def get_alert_by_id(alert_id: str) -> Optional[Dict]:
    with _conn() as con:
        row = con.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    if not row:
        return None
    d = dict(row)
    try:
        d["reasons"] = json.loads(d["reasons"])
    except Exception:
        pass
    return d


def delete_alert(alert_id: str) -> bool:
    with _conn() as con:
        cur = con.execute("DELETE FROM alerts WHERE id = ?", (alert_id,))
    return cur.rowcount > 0


def clear_all_alerts() -> int:
    """Delete every alert, reset scan_pattern counters, and clear ledger. Returns deleted count."""
    with _conn() as con:
        n = con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        con.execute("DELETE FROM alerts")
        con.execute("DELETE FROM scan_patterns")
        con.execute("DELETE FROM ledger_blocks")
    return n


# ═══════════════════════════════════════════════════════════════════
# Ledger persistence
# ═══════════════════════════════════════════════════════════════════

def save_ledger_block(
    idx: int, timestamp: float, alert_id: str,
    payload_hash: str, prev_hash: str, block_hash: str,
) -> None:
    with _conn() as con:
        con.execute(
            """
            INSERT OR REPLACE INTO ledger_blocks
              (idx, timestamp, alert_id, payload_hash, prev_hash, block_hash)
            VALUES (?,?,?,?,?,?)
            """,
            (idx, timestamp, alert_id, payload_hash, prev_hash, block_hash),
        )


def load_ledger_blocks() -> List[Dict]:
    """Return all ledger blocks ordered by index."""
    with _conn() as con:
        rows = con.execute(
            "SELECT * FROM ledger_blocks ORDER BY idx"
        ).fetchall()
    return [dict(r) for r in rows]


def update_alert_notes(alert_id: str, notes: str) -> bool:
    with _conn() as con:
        cur = con.execute(
            "UPDATE alerts SET notes = ? WHERE id = ?", (notes, alert_id)
        )
    return cur.rowcount > 0


def get_alerts_paginated(
    page: int = 1,
    per_page: int = 50,
    kind: Optional[str] = None,
    level: Optional[str] = None,
    min_score: Optional[int] = None,
    max_score: Optional[int] = None,
    search: Optional[str] = None,
    start_ts: Optional[float] = None,
    end_ts: Optional[float] = None,
) -> Dict:
    """
    Paginated, filtered alert list.

    Returns
    -------
    {total, page, per_page, pages, alerts: [...]}
    """
    page     = max(1, page)
    per_page = max(1, min(per_page, 200))
    offset   = (page - 1) * per_page

    where:  List[str] = []
    params: list      = []

    if kind:
        where.append("kind = ?");        params.append(kind)
    if level:
        where.append("risk_level = ?");  params.append(level)
    if min_score is not None:
        where.append("risk_score >= ?"); params.append(min_score)
    if max_score is not None:
        where.append("risk_score <= ?"); params.append(max_score)
    if search:
        where.append("target LIKE ?");   params.append(f"%{search}%")
    if start_ts is not None:
        where.append("timestamp >= ?");  params.append(start_ts)
    if end_ts is not None:
        where.append("timestamp <= ?");  params.append(end_ts)

    clause = ("WHERE " + " AND ".join(where)) if where else ""

    with _conn() as con:
        total = con.execute(
            f"SELECT COUNT(*) FROM alerts {clause}", params
        ).fetchone()[0]
        rows = con.execute(
            f"SELECT * FROM alerts {clause} ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params + [per_page, offset],
        ).fetchall()

    alerts = []
    for r in rows:
        d = dict(r)
        try:
            d["reasons"] = json.loads(d["reasons"])
        except Exception:
            pass
        alerts.append(d)

    return {
        "total":    total,
        "page":     page,
        "per_page": per_page,
        "pages":    max(1, (total + per_page - 1) // per_page),
        "alerts":   alerts,
    }


# ═══════════════════════════════════════════════════════════════════
# Basic query helpers (kept for backward compatibility)
# ═══════════════════════════════════════════════════════════════════

def get_recent_alerts(limit: int = 100, kind: Optional[str] = None) -> List[Dict]:
    with _conn() as con:
        if kind:
            rows = con.execute(
                "SELECT * FROM alerts WHERE kind=? ORDER BY timestamp DESC LIMIT ?",
                (kind, limit),
            ).fetchall()
        else:
            rows = con.execute(
                "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
    return [dict(r) for r in rows]


def get_target_history(target: str, kind: Optional[str] = None) -> List[Dict]:
    with _conn() as con:
        if kind:
            rows = con.execute(
                "SELECT * FROM alerts WHERE target=? AND kind=? ORDER BY timestamp DESC LIMIT 20",
                (target, kind),
            ).fetchall()
        else:
            rows = con.execute(
                "SELECT * FROM alerts WHERE target=? ORDER BY timestamp DESC LIMIT 20",
                (target,),
            ).fetchall()
    return [dict(r) for r in rows]


def get_db_stats() -> Dict:
    with _conn() as con:
        total    = con.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        by_level = con.execute(
            "SELECT risk_level, COUNT(*) c FROM alerts GROUP BY risk_level"
        ).fetchall()
        by_kind  = con.execute(
            "SELECT kind, risk_level, COUNT(*) c FROM alerts GROUP BY kind, risk_level"
        ).fetchall()

    levels = {r["risk_level"]: r["c"] for r in by_level}
    kinds: Dict[str, Dict] = {}
    for r in by_kind:
        k = r["kind"]
        kinds.setdefault(k, {"total": 0, "safe": 0, "caution": 0, "danger": 0})
        kinds[k][r["risk_level"]] = r["c"]
        kinds[k]["total"] += r["c"]

    return {
        "total":   total,
        "safe":    levels.get("safe", 0),
        "caution": levels.get("caution", 0),
        "danger":  levels.get("danger", 0),
        "by_kind": kinds,
    }


def get_trend_from_db(hours: int = 6) -> List[Dict]:
    now     = time.time()
    buckets = []
    with _conn() as con:
        for i in range(hours - 1, -1, -1):
            start = now - (i + 1) * 3600
            end   = now - i * 3600
            rows  = con.execute(
                "SELECT risk_level, COUNT(*) c FROM alerts "
                "WHERE timestamp>=? AND timestamp<? GROUP BY risk_level",
                (start, end),
            ).fetchall()
            lvl = {r["risk_level"]: r["c"] for r in rows}
            buckets.append({
                "label":   f"{i}h ago" if i > 0 else "now",
                "total":   sum(lvl.values()),
                "danger":  lvl.get("danger", 0),
                "caution": lvl.get("caution", 0),
                "safe":    lvl.get("safe", 0),
            })
    return buckets


# ═══════════════════════════════════════════════════════════════════
# Analytics
# ═══════════════════════════════════════════════════════════════════

def get_score_distribution(kind: Optional[str] = None) -> List[Dict]:
    """
    Risk-score histogram in 10-point buckets (0-9, 10-19, … 90-100).
    Useful for a distribution bar chart on the dashboard.
    """
    where  = "WHERE kind = ?" if kind else ""
    params = [kind] if kind else []
    with _conn() as con:
        rows = con.execute(
            f"SELECT risk_score FROM alerts {where}", params
        ).fetchall()

    counts = [0] * 10
    for r in rows:
        counts[min(9, r["risk_score"] // 10)] += 1

    return [
        {"range": f"{i*10}-{i*10+9}", "min": i * 10, "max": i * 10 + 9, "count": counts[i]}
        for i in range(10)
    ]


def get_top_targets(
    kind: Optional[str] = None,
    level: Optional[str] = None,
    limit: int = 10,
    hours: int = 24,
) -> List[Dict]:
    """Most-flagged targets within the last `hours` hours."""
    limit = max(1, min(limit, 100))
    since = time.time() - hours * 3600

    where:  List[str] = ["timestamp >= ?"]
    params: list      = [since]
    if kind:
        where.append("kind = ?");       params.append(kind)
    if level:
        where.append("risk_level = ?"); params.append(level)

    clause = "WHERE " + " AND ".join(where)

    with _conn() as con:
        rows = con.execute(
            f"""
            SELECT target, kind,
                   COUNT(*)                                             AS scan_count,
                   AVG(risk_score)                                      AS avg_score,
                   MAX(risk_score)                                      AS max_score,
                   SUM(CASE WHEN risk_level='danger'  THEN 1 ELSE 0 END) AS danger_count,
                   SUM(CASE WHEN risk_level='caution' THEN 1 ELSE 0 END) AS caution_count,
                   MAX(timestamp)                                       AS last_seen
            FROM alerts {clause}
            GROUP BY target, kind
            ORDER BY scan_count DESC, avg_score DESC
            LIMIT ?
            """,
            params + [limit],
        ).fetchall()

    return [
        {
            "target":        r["target"],
            "kind":          r["kind"],
            "scan_count":    r["scan_count"],
            "avg_score":     round(r["avg_score"], 1),
            "max_score":     r["max_score"],
            "danger_count":  r["danger_count"],
            "caution_count": r["caution_count"],
            "last_seen":     r["last_seen"],
        }
        for r in rows
    ]


def get_kind_timeline(hours: int = 24, interval_min: int = 60) -> Dict:
    """
    Per-kind scan counts across equal time intervals.

    Returns
    -------
    {interval_minutes, hours, buckets: [{label, start_ts, total, by_kind: {kind: count}}]}
    """
    hours        = max(1, min(hours, 168))
    interval_min = max(5, min(interval_min, 1440))
    n_buckets    = min(168, int(hours * 60 / interval_min))
    interval_sec = interval_min * 60
    now          = time.time()
    since        = now - n_buckets * interval_sec

    with _conn() as con:
        rows = con.execute(
            "SELECT kind, timestamp FROM alerts WHERE timestamp >= ? ORDER BY timestamp",
            (since,),
        ).fetchall()

    buckets = []
    for i in range(n_buckets - 1, -1, -1):
        b_start = now - (i + 1) * interval_sec
        b_end   = now - i * interval_sec
        by_kind: Dict[str, int] = {}
        for r in rows:
            if b_start <= r["timestamp"] < b_end:
                by_kind[r["kind"]] = by_kind.get(r["kind"], 0) + 1
        label = (f"{i}h ago" if i > 0 else "now") if interval_min >= 60 else (f"{i*interval_min}m ago" if i > 0 else "now")
        buckets.append({
            "label":    label,
            "start_ts": round(b_start),
            "total":    sum(by_kind.values()),
            "by_kind":  by_kind,
        })

    return {"interval_minutes": interval_min, "hours": hours, "buckets": buckets}


# ═══════════════════════════════════════════════════════════════════
# Entity links
# ═══════════════════════════════════════════════════════════════════

def add_entity_link(
    src_type: str, src_val: str,
    dst_type: str, dst_val: str,
    relation: str, alert_id: str = "",
) -> None:
    with _conn() as con:
        con.execute(
            """
            INSERT INTO entity_links
              (src_type, src_value, dst_type, dst_value, relation, alert_id, timestamp)
            VALUES (?,?,?,?,?,?,?)
            """,
            (src_type, src_val[:200], dst_type, dst_val[:200], relation, alert_id, time.time()),
        )


def get_entity_graph(entity_type: str, entity_value: str, depth: int = 2) -> Dict:
    visited: set      = set()
    nodes:   List[Dict] = []
    edges:   List[Dict] = []

    def traverse(etype: str, eval_: str, d: int) -> None:
        key = f"{etype}:{eval_}"
        if key in visited or d < 0:
            return
        visited.add(key)
        with _conn() as con:
            r = con.execute(
                "SELECT AVG(risk_score) avg, COUNT(*) cnt FROM alerts WHERE kind=? AND target LIKE ?",
                (etype, eval_[:80] + "%"),
            ).fetchone()
        avg_score = r["avg"] or 0.0
        cnt       = r["cnt"] or 0
        nodes.append({
            "id": key, "type": etype, "value": eval_,
            "avg_score":  round(avg_score, 1),
            "scan_count": cnt,
            "risk_level": "danger" if avg_score >= 65 else "caution" if avg_score >= 30 else "safe",
        })

        with _conn() as con:
            fwd = con.execute(
                "SELECT * FROM entity_links WHERE src_type=? AND src_value=? LIMIT 30",
                (etype, eval_[:200]),
            ).fetchall()
            rev = con.execute(
                "SELECT * FROM entity_links WHERE dst_type=? AND dst_value=? LIMIT 30",
                (etype, eval_[:200]),
            ).fetchall()

        for row in fwd:
            edges.append({
                "source":   key,
                "target":   f"{row['dst_type']}:{row['dst_value']}",
                "relation": row["relation"],
            })
            traverse(row["dst_type"], row["dst_value"], d - 1)

        for row in rev:
            edges.append({
                "source":   f"{row['src_type']}:{row['src_value']}",
                "target":   key,
                "relation": row["relation"],
            })
            traverse(row["src_type"], row["src_value"], d - 1)

    traverse(entity_type, entity_value, depth)
    return {"nodes": nodes, "edges": edges, "center": f"{entity_type}:{entity_value}"}
