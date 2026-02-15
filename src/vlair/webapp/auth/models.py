"""
Authentication data models backed by SQLite.

Schema:
  users      - accounts with roles and MFA settings
  api_keys   - hashed API keys per user
  audit_log  - immutable record of every authenticated action
"""

import os
import sqlite3
import secrets
import hashlib
import enum
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List


# ---------------------------------------------------------------------------
# Role hierarchy
# ---------------------------------------------------------------------------


class Role(str, enum.Enum):
    VIEWER = "viewer"  # read-only: view past results
    ANALYST = "analyst"  # run tools, submit IOCs
    SENIOR_ANALYST = "senior_analyst"  # approve findings, manage feeds
    ADMIN = "admin"  # user management, system config

    # Ordered list for comparison (lowest → highest privilege)
    @staticmethod
    def ordered() -> List["Role"]:
        return [Role.VIEWER, Role.ANALYST, Role.SENIOR_ANALYST, Role.ADMIN]

    def level(self) -> int:
        return Role.ordered().index(self)

    def has_at_least(self, required: "Role") -> bool:
        return self.level() >= required.level()


# ---------------------------------------------------------------------------
# Database path
# ---------------------------------------------------------------------------

_DEFAULT_DB_PATH = Path.home() / ".vlair" / "webapp.db"


def _get_db_path() -> Path:
    path = Path(os.getenv("VLAIR_WEBAPP_DB", str(_DEFAULT_DB_PATH)))
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


@contextmanager
def _connect():
    conn = sqlite3.connect(str(_get_db_path()), detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def init_db() -> None:
    """Create tables if they do not exist. Safe to call on every startup."""
    with _connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                username    TEXT    NOT NULL UNIQUE,
                email       TEXT    NOT NULL UNIQUE,
                password_hash TEXT  NOT NULL,
                role        TEXT    NOT NULL DEFAULT 'analyst',
                is_active   INTEGER NOT NULL DEFAULT 1,
                mfa_secret  TEXT,
                mfa_enabled INTEGER NOT NULL DEFAULT 0,
                created_at  TEXT    NOT NULL,
                last_login  TEXT
            );

            CREATE TABLE IF NOT EXISTS api_keys (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                name        TEXT    NOT NULL,
                key_hash    TEXT    NOT NULL UNIQUE,
                key_prefix  TEXT    NOT NULL,
                is_active   INTEGER NOT NULL DEFAULT 1,
                created_at  TEXT    NOT NULL,
                last_used   TEXT,
                expires_at  TEXT
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,
                username    TEXT,
                action      TEXT    NOT NULL,
                resource    TEXT,
                ip_address  TEXT,
                user_agent  TEXT,
                status_code INTEGER,
                detail      TEXT,
                timestamp   TEXT    NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_api_keys_hash    ON api_keys(key_hash);
            CREATE INDEX IF NOT EXISTS idx_audit_user       ON audit_log(user_id);
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp  ON audit_log(timestamp);
        """
        )


# ---------------------------------------------------------------------------
# User CRUD
# ---------------------------------------------------------------------------


def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
    return f"{salt}${dk.hex()}"


def _verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt, dk_hex = stored_hash.split("$", 1)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 260_000)
        return secrets.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


def create_user(username: str, email: str, password: str, role: Role = Role.ANALYST) -> Dict:
    """
    Create a new user. Raises ValueError on duplicate username/email.

    Returns the created user dict (no password_hash).
    """
    now = datetime.utcnow().isoformat()
    pw_hash = _hash_password(password)
    with _connect() as conn:
        try:
            conn.execute(
                """
                INSERT INTO users (username, email, password_hash, role, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (username.lower(), email.lower(), pw_hash, role.value, now),
            )
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"Username or email already exists: {exc}") from exc
    return get_user_by_username(username)


def get_user_by_id(user_id: int) -> Optional[Dict]:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return _row_to_user(row)


def get_user_by_username(username: str) -> Optional[Dict]:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username.lower(),)).fetchone()
    return _row_to_user(row)


def get_user_by_email(email: str) -> Optional[Dict]:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email.lower(),)).fetchone()
    return _row_to_user(row)


def authenticate_user(username: str, password: str) -> Optional[Dict]:
    """
    Verify credentials. Returns user dict on success, None on failure.
    Does NOT check is_active – callers should verify that separately.
    """
    with _connect() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username.lower(),)).fetchone()
    if row is None:
        return None
    if not _verify_password(password, row["password_hash"]):
        return None
    # Update last_login
    with _connect() as conn:
        conn.execute(
            "UPDATE users SET last_login = ? WHERE id = ?",
            (datetime.utcnow().isoformat(), row["id"]),
        )
    return _row_to_user(row)


def update_user_role(user_id: int, role: Role) -> None:
    with _connect() as conn:
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (role.value, user_id))


def deactivate_user(user_id: int) -> None:
    with _connect() as conn:
        conn.execute("UPDATE users SET is_active = 0 WHERE id = ?", (user_id,))


def activate_user(user_id: int) -> None:
    with _connect() as conn:
        conn.execute("UPDATE users SET is_active = 1 WHERE id = ?", (user_id,))


def list_users() -> List[Dict]:
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    return [_row_to_user(r) for r in rows if r]


def _row_to_user(row) -> Optional[Dict]:
    if row is None:
        return None
    d = dict(row)
    d.pop("password_hash", None)
    d.pop("mfa_secret", None)
    d["is_active"] = bool(d["is_active"])
    d["mfa_enabled"] = bool(d["mfa_enabled"])
    return d


# ---------------------------------------------------------------------------
# MFA helpers
# ---------------------------------------------------------------------------


def set_mfa_secret(user_id: int, secret: str) -> None:
    with _connect() as conn:
        conn.execute("UPDATE users SET mfa_secret = ? WHERE id = ?", (secret, user_id))


def enable_mfa(user_id: int) -> None:
    with _connect() as conn:
        conn.execute("UPDATE users SET mfa_enabled = 1 WHERE id = ?", (user_id,))


def disable_mfa(user_id: int) -> None:
    with _connect() as conn:
        conn.execute(
            "UPDATE users SET mfa_enabled = 0, mfa_secret = NULL WHERE id = ?",
            (user_id,),
        )


def get_mfa_secret(user_id: int) -> Optional[str]:
    with _connect() as conn:
        row = conn.execute("SELECT mfa_secret FROM users WHERE id = ?", (user_id,)).fetchone()
    return row["mfa_secret"] if row else None


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------


def create_api_key(user_id: int, name: str, expires_at: Optional[str] = None) -> str:
    """
    Generate a new API key, store only its hash.
    Returns the *plaintext* key (shown once, never again).
    Format: ``vlair_<32 random hex chars>``
    """
    raw_key = f"vlair_{secrets.token_hex(32)}"
    key_prefix = raw_key[:12]  # "vlair_XXXXXX" – safe to store/display
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    now = datetime.utcnow().isoformat()
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO api_keys (user_id, name, key_hash, key_prefix, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, name, key_hash, key_prefix, now, expires_at),
        )
    return raw_key


def lookup_api_key(raw_key: str) -> Optional[Dict]:
    """
    Validate a raw API key. Returns {user_id, key_id, name} or None.
    Updates ``last_used`` timestamp on hit.
    """
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT k.id, k.user_id, k.name, k.is_active, k.expires_at
            FROM api_keys k
            WHERE k.key_hash = ?
            """,
            (key_hash,),
        ).fetchone()
        if row is None:
            return None
        if not row["is_active"]:
            return None
        if row["expires_at"]:
            if datetime.utcnow().isoformat() > row["expires_at"]:
                return None
        conn.execute(
            "UPDATE api_keys SET last_used = ? WHERE id = ?",
            (datetime.utcnow().isoformat(), row["id"]),
        )
    return {"user_id": row["user_id"], "key_id": row["id"], "name": row["name"]}


def list_api_keys(user_id: int) -> List[Dict]:
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT id, name, key_prefix, is_active, created_at, last_used, expires_at
            FROM api_keys WHERE user_id = ? ORDER BY created_at DESC
            """,
            (user_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def revoke_api_key(key_id: int, user_id: int) -> bool:
    """Revoke key, enforcing ownership. Returns True if revoked."""
    with _connect() as conn:
        result = conn.execute(
            "UPDATE api_keys SET is_active = 0 WHERE id = ? AND user_id = ?",
            (key_id, user_id),
        )
    return result.rowcount > 0


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------


def log_action(
    action: str,
    *,
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    resource: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    status_code: Optional[int] = None,
    detail: Optional[str] = None,
) -> None:
    """Write a single audit record. Fire-and-forget; never raises."""
    try:
        now = datetime.utcnow().isoformat()
        with _connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_log
                  (user_id, username, action, resource, ip_address,
                   user_agent, status_code, detail, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    user_id,
                    username,
                    action,
                    resource,
                    ip_address,
                    user_agent,
                    status_code,
                    detail,
                    now,
                ),
            )
    except Exception:
        pass  # audit failures must not break the request


def get_audit_log(
    user_id: Optional[int] = None,
    limit: int = 100,
    offset: int = 0,
) -> List[Dict]:
    with _connect() as conn:
        if user_id:
            rows = conn.execute(
                """
                SELECT * FROM audit_log WHERE user_id = ?
                ORDER BY timestamp DESC LIMIT ? OFFSET ?
                """,
                (user_id, limit, offset),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
    return [dict(r) for r in rows]
