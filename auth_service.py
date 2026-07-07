"""
FRAUD-X — Enterprise Authentication Service
============================================
JWT + RBAC + TOTP-MFA + User Management

Roles (least → most privileged):
  user              — read-only access to own alerts
  analyst           — fraud investigation, case management
  investigator      — full case + threat intel access
  admin             — user management, model config
  super_admin       — all permissions + system config
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3
import time
import threading
import secrets
import base64
from dataclasses import dataclass, asdict
from typing import Optional

import bcrypt
import jwt

# ── Config ─────────────────────────────────────────────────────
JWT_SECRET   = os.environ.get("FRAUDX_JWT_SECRET", secrets.token_urlsafe(32))
JWT_ALG      = "HS256"
ACCESS_TTL   = 3600          # 1 hour
REFRESH_TTL  = 86400 * 7    # 7 days
DB_PATH      = os.environ.get("FRAUDX_DB", "fraudx.db")

ROLES = ["user", "analyst", "investigator", "admin", "super_admin"]

ROLE_PERMISSIONS: dict[str, set[str]] = {
    "user":         {"alerts:read", "profile:read"},
    "analyst":      {"alerts:read", "cases:read", "cases:write", "transactions:read",
                     "intelligence:read", "profile:read"},
    "investigator": {"alerts:read", "alerts:write", "cases:read", "cases:write",
                     "transactions:read", "intelligence:read", "intelligence:write",
                     "devices:read", "simulation:read", "profile:read"},
    "admin":        {"*:read", "*:write", "users:manage", "models:manage"},
    "super_admin":  {"*"},
}

# ── DB schema ───────────────────────────────────────────────────
_SCHEMA = """
CREATE TABLE IF NOT EXISTS fx_users (
    id          TEXT PRIMARY KEY,
    email       TEXT UNIQUE NOT NULL,
    name        TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'analyst',
    mfa_secret  TEXT,
    mfa_enabled INTEGER NOT NULL DEFAULT 0,
    is_active   INTEGER NOT NULL DEFAULT 1,
    created_at  REAL NOT NULL,
    last_login  REAL,
    login_count INTEGER NOT NULL DEFAULT 0,
    avatar_color TEXT NOT NULL DEFAULT '#6366f1'
);

CREATE TABLE IF NOT EXISTS fx_sessions (
    token_id    TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    created_at  REAL NOT NULL,
    expires_at  REAL NOT NULL,
    ip          TEXT,
    user_agent  TEXT,
    revoked     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS fx_audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     TEXT,
    action      TEXT NOT NULL,
    detail      TEXT,
    ip          TEXT,
    ts          REAL NOT NULL
);
"""

_lock = threading.Lock()


def _db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_auth_db():
    with _lock:
        conn = _db()
        conn.executescript(_SCHEMA)
        conn.commit()
        # Seed default super_admin if no users exist
        cur = conn.execute("SELECT COUNT(*) FROM fx_users")
        if cur.fetchone()[0] == 0:
            _seed_default_users(conn)
        conn.close()


def _seed_default_users(conn: sqlite3.Connection):
    import uuid
    defaults = [
        ("super_admin@fraudx.ai",  "FRAUD-X Super Admin", "FraudX@Admin2025!", "super_admin", "#ef4444"),
        ("admin@fraudx.ai",        "System Administrator", "Admin@2025!",       "admin",       "#f59e0b"),
        ("analyst@fraudx.ai",      "Fraud Analyst",        "Analyst@2025!",     "analyst",     "#6366f1"),
        ("investigator@fraudx.ai", "Lead Investigator",    "Invest@2025!",      "investigator","#22d3ee"),
    ]
    now = time.time()
    for email, name, pw, role, color in defaults:
        uid = str(uuid.uuid4())
        pw_hash = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
        conn.execute(
            "INSERT INTO fx_users VALUES (?,?,?,?,?,NULL,0,1,?,NULL,0,?)",
            (uid, email, name, pw_hash, role, now, color),
        )
    conn.commit()


# ═══════════════════════════════════════════════════════════════
# User operations
# ═══════════════════════════════════════════════════════════════

@dataclass
class User:
    id:            str
    email:         str
    name:          str
    role:          str
    mfa_enabled:   bool
    is_active:     bool
    created_at:    float
    last_login:    Optional[float]
    login_count:   int
    avatar_color:  str

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items()}

    def has_permission(self, perm: str) -> bool:
        allowed = ROLE_PERMISSIONS.get(self.role, set())
        if "*" in allowed:
            return True
        ns = perm.split(":")[0]
        if f"{ns}:*" in allowed or "*:*" in allowed:
            return True
        return perm in allowed


def get_user_by_email(email: str) -> Optional[dict]:
    with _lock:
        conn = _db()
        row = conn.execute("SELECT * FROM fx_users WHERE email=? AND is_active=1", (email,)).fetchone()
        conn.close()
        return dict(row) if row else None


def get_user_by_id(uid: str) -> Optional[User]:
    with _lock:
        conn = _db()
        row = conn.execute("SELECT * FROM fx_users WHERE id=? AND is_active=1", (uid,)).fetchone()
        conn.close()
        if not row:
            return None
        r = dict(row)
        return User(
            id=r["id"], email=r["email"], name=r["name"], role=r["role"],
            mfa_enabled=bool(r["mfa_enabled"]), is_active=bool(r["is_active"]),
            created_at=r["created_at"], last_login=r["last_login"],
            login_count=r["login_count"], avatar_color=r["avatar_color"],
        )


def list_users() -> list[dict]:
    with _lock:
        conn = _db()
        rows = conn.execute(
            "SELECT id,email,name,role,mfa_enabled,is_active,created_at,last_login,login_count,avatar_color "
            "FROM fx_users ORDER BY created_at DESC"
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]


def create_user(email: str, name: str, password: str, role: str = "analyst") -> User:
    import uuid
    if role not in ROLES:
        raise ValueError(f"Invalid role: {role}")
    uid      = str(uuid.uuid4())
    pw_hash  = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    now      = time.time()
    colors   = ["#6366f1","#22d3ee","#f59e0b","#22c55e","#ec4899","#8b5cf6"]
    color    = colors[int(uid[:2], 16) % len(colors)]
    with _lock:
        conn = _db()
        conn.execute(
            "INSERT INTO fx_users VALUES (?,?,?,?,?,NULL,0,1,?,NULL,0,?)",
            (uid, email, name, pw_hash, role, now, color),
        )
        conn.commit()
        conn.close()
    return get_user_by_id(uid)


def update_user_role(uid: str, role: str):
    if role not in ROLES:
        raise ValueError(f"Invalid role: {role}")
    with _lock:
        conn = _db()
        conn.execute("UPDATE fx_users SET role=? WHERE id=?", (role, uid))
        conn.commit()
        conn.close()


def deactivate_user(uid: str):
    with _lock:
        conn = _db()
        conn.execute("UPDATE fx_users SET is_active=0 WHERE id=?", (uid,))
        conn.commit()
        conn.close()


def verify_password(email: str, password: str) -> Optional[dict]:
    user_row = get_user_by_email(email)
    if not user_row:
        return None
    if not bcrypt.checkpw(password.encode(), user_row["password_hash"].encode()):
        return None
    return user_row


def update_last_login(uid: str):
    with _lock:
        conn = _db()
        conn.execute(
            "UPDATE fx_users SET last_login=?, login_count=login_count+1 WHERE id=?",
            (time.time(), uid),
        )
        conn.commit()
        conn.close()


# ═══════════════════════════════════════════════════════════════
# JWT operations
# ═══════════════════════════════════════════════════════════════

def create_access_token(user: dict, token_id: str | None = None) -> str:
    if token_id is None:
        token_id = secrets.token_urlsafe(16)
    payload = {
        "sub":   user["id"],
        "email": user["email"],
        "name":  user["name"],
        "role":  user["role"],
        "jti":   token_id,
        "iat":   int(time.time()),
        "exp":   int(time.time()) + ACCESS_TTL,
        "type":  "access",
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def create_refresh_token(user_id: str) -> tuple[str, str]:
    token_id = secrets.token_urlsafe(24)
    payload  = {
        "sub":  user_id,
        "jti":  token_id,
        "iat":  int(time.time()),
        "exp":  int(time.time()) + REFRESH_TTL,
        "type": "refresh",
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)
    with _lock:
        conn = _db()
        conn.execute(
            "INSERT INTO fx_sessions VALUES (?,?,?,?,NULL,NULL,0)",
            (token_id, user_id, time.time(), time.time() + REFRESH_TTL),
        )
        conn.commit()
        conn.close()
    return token, token_id


def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def revoke_session(token_id: str):
    with _lock:
        conn = _db()
        conn.execute("UPDATE fx_sessions SET revoked=1 WHERE token_id=?", (token_id,))
        conn.commit()
        conn.close()


def is_session_revoked(token_id: str) -> bool:
    with _lock:
        conn = _db()
        row = conn.execute(
            "SELECT revoked FROM fx_sessions WHERE token_id=?", (token_id,)
        ).fetchone()
        conn.close()
        if not row:
            return True
        return bool(row["revoked"])


# ═══════════════════════════════════════════════════════════════
# TOTP MFA (RFC 6238)
# ═══════════════════════════════════════════════════════════════

def _hotp(secret: bytes, counter: int) -> int:
    msg = counter.to_bytes(8, "big")
    h   = hmac.new(secret, msg, hashlib.sha1).digest()
    off = h[-1] & 0x0F
    code = ((h[off] & 0x7F) << 24 | h[off+1] << 16 | h[off+2] << 8 | h[off+3]) % 10**6
    return code


def generate_totp(secret_b32: str) -> int:
    secret = base64.b32decode(secret_b32.upper().replace(" ", ""))
    counter = int(time.time()) // 30
    return _hotp(secret, counter)


def verify_totp(secret_b32: str, code: int, window: int = 1) -> bool:
    secret  = base64.b32decode(secret_b32.upper().replace(" ", ""))
    counter = int(time.time()) // 30
    for delta in range(-window, window + 1):
        if _hotp(secret, counter + delta) == code:
            return True
    return False


def generate_mfa_secret() -> str:
    raw    = secrets.token_bytes(20)
    return base64.b32encode(raw).decode()


def enable_mfa(uid: str, secret: str):
    with _lock:
        conn = _db()
        conn.execute(
            "UPDATE fx_users SET mfa_secret=?, mfa_enabled=1 WHERE id=?",
            (secret, uid),
        )
        conn.commit()
        conn.close()


def get_mfa_secret(uid: str) -> Optional[str]:
    with _lock:
        conn = _db()
        row = conn.execute(
            "SELECT mfa_secret FROM fx_users WHERE id=?", (uid,)
        ).fetchone()
        conn.close()
        return row["mfa_secret"] if row else None


# ═══════════════════════════════════════════════════════════════
# Audit log
# ═══════════════════════════════════════════════════════════════

def audit(user_id: Optional[str], action: str, detail: str = "", ip: str = ""):
    with _lock:
        conn = _db()
        conn.execute(
            "INSERT INTO fx_audit_log (user_id,action,detail,ip,ts) VALUES (?,?,?,?,?)",
            (user_id, action, detail, ip, time.time()),
        )
        conn.commit()
        conn.close()


def get_audit_log(limit: int = 100) -> list[dict]:
    with _lock:
        conn = _db()
        rows = conn.execute(
            "SELECT * FROM fx_audit_log ORDER BY ts DESC LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]


# ── Pending MFA challenges (in-memory) ────────────────────────
_pending_mfa: dict[str, dict] = {}
_pending_lock = threading.Lock()


def create_mfa_challenge(user_id: str, user_row: dict) -> str:
    challenge_id = secrets.token_urlsafe(24)
    with _pending_lock:
        _pending_mfa[challenge_id] = {
            "user_id":  user_id,
            "user_row": user_row,
            "created":  time.time(),
        }
    return challenge_id


def resolve_mfa_challenge(challenge_id: str, code: int) -> Optional[dict]:
    with _pending_lock:
        challenge = _pending_mfa.get(challenge_id)
        if not challenge:
            return None
        if time.time() - challenge["created"] > 300:
            del _pending_mfa[challenge_id]
            return None
    uid    = challenge["user_id"]
    secret = get_mfa_secret(uid)
    if not secret or not verify_totp(secret, code):
        return None
    with _pending_lock:
        del _pending_mfa[challenge_id]
    return challenge["user_row"]


# ── Init ──────────────────────────────────────────────────────
init_auth_db()
