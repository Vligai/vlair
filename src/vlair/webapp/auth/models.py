"""
Authentication data models backed by SQLite.

Schema:
  users        - accounts with roles and MFA settings
  api_keys     - hashed API keys per user
  backup_codes - one-time MFA recovery codes per user
  audit_log    - immutable record of every authenticated action
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
                request_id  TEXT,
                timestamp   TEXT    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS revoked_tokens (
                jti         TEXT PRIMARY KEY,
                user_id     INTEGER NOT NULL,
                revoked_at  TEXT NOT NULL,
                expires_at  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS backup_codes (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                code_hash   TEXT    NOT NULL,
                used_at     TEXT,
                created_at  TEXT    NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_backup_codes_user ON backup_codes(user_id);
            CREATE INDEX IF NOT EXISTS idx_revoked_tokens_user ON revoked_tokens(user_id);
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
    revoke_all_user_tokens(user_id)


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
# Backup codes (MFA recovery)
# ---------------------------------------------------------------------------


def generate_backup_codes(user_id: int, count: int = 10) -> List[str]:
    """
    Generate one-time MFA backup codes for a user.

    Deletes any existing unused codes first, then creates ``count`` new
    random 8-digit numeric codes.  Each code is hashed with PBKDF2 +
    per-code salt (same pattern as ``_hash_api_key``).

    Returns the plaintext codes (shown once to the user, never again).
    """
    now = datetime.utcnow().isoformat()

    with _connect() as conn:
        # Remove existing unused codes
        conn.execute(
            "DELETE FROM backup_codes WHERE user_id = ? AND used_at IS NULL",
            (user_id,),
        )

    if count <= 0:
        return []

    plaintext_codes: List[str] = []
    with _connect() as conn:
        for _ in range(count):
            code = f"{secrets.randbelow(10**8):08d}"
            salt = secrets.token_hex(16)
            code_hash = f"{salt}${_hash_api_key(code, salt)}"
            conn.execute(
                "INSERT INTO backup_codes (user_id, code_hash, created_at) VALUES (?, ?, ?)",
                (user_id, code_hash, now),
            )
            plaintext_codes.append(code)

    return plaintext_codes


def verify_backup_code(user_id: int, code: str) -> bool:
    """
    Verify a one-time backup code for MFA recovery.

    Checks all unused codes for the user with constant-time comparison.
    If a match is found the code is marked as used (``used_at`` set) so
    it cannot be reused.
    """
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, code_hash FROM backup_codes WHERE user_id = ? AND used_at IS NULL",
            (user_id,),
        ).fetchall()

    for row in rows:
        stored = row["code_hash"]
        if "$" not in stored:
            continue
        salt, expected = stored.split("$", 1)
        if secrets.compare_digest(_hash_api_key(code, salt), expected):
            with _connect() as conn:
                conn.execute(
                    "UPDATE backup_codes SET used_at = ? WHERE id = ?",
                    (datetime.utcnow().isoformat(), row["id"]),
                )
            return True

    return False


def get_backup_code_count(user_id: int) -> int:
    """Return the number of unused backup codes remaining for a user."""
    with _connect() as conn:
        row = conn.execute(
            "SELECT COUNT(*) AS cnt FROM backup_codes WHERE user_id = ? AND used_at IS NULL",
            (user_id,),
        ).fetchone()
    return row["cnt"] if row else 0


def delete_backup_codes(user_id: int) -> None:
    """Delete all backup codes (used and unused) for a user."""
    with _connect() as conn:
        conn.execute("DELETE FROM backup_codes WHERE user_id = ?", (user_id,))


# ---------------------------------------------------------------------------
# API keys
# ---------------------------------------------------------------------------


def _hash_api_key(raw_key: str, salt: str) -> str:
    """Hash an API key with a per-key salt using PBKDF2."""
    dk = hashlib.pbkdf2_hmac("sha256", raw_key.encode(), salt.encode(), 100_000)
    return dk.hex()


def create_api_key(user_id: int, name: str, expires_at: Optional[str] = None) -> str:
    """
    Generate a new API key, store only its salted hash.
    Returns the *plaintext* key (shown once, never again).
    Format: ``vlair_<32 random hex chars>``
    """
    raw_key = f"vlair_{secrets.token_hex(32)}"
    key_prefix = raw_key[:12]  # "vlair_XXXXXX" – safe to store/display
    salt = secrets.token_hex(16)
    key_hash = f"{salt}${_hash_api_key(raw_key, salt)}"
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

    Supports both legacy (unsalted SHA256) and new (salted PBKDF2) key hashes.
    """
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT k.id, k.user_id, k.name, k.is_active, k.expires_at, k.key_hash
            FROM api_keys k
            WHERE k.key_prefix = ? AND k.is_active = 1
            """,
            (raw_key[:12],),
        ).fetchall()

    for row in rows:
        stored_hash = row["key_hash"]
        if "$" in stored_hash:
            # New salted format: salt$hash
            salt, expected = stored_hash.split("$", 1)
            if not secrets.compare_digest(_hash_api_key(raw_key, salt), expected):
                continue
        else:
            # Legacy unsalted SHA256 format
            if not secrets.compare_digest(
                hashlib.sha256(raw_key.encode()).hexdigest(), stored_hash
            ):
                continue

        # Match found — check expiration
        if row["expires_at"]:
            if datetime.utcnow().isoformat() > row["expires_at"]:
                return None
        with _connect() as conn:
            conn.execute(
                "UPDATE api_keys SET last_used = ? WHERE id = ?",
                (datetime.utcnow().isoformat(), row["id"]),
            )
        return {"user_id": row["user_id"], "key_id": row["id"], "name": row["name"]}

    return None


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
# Token revocation
# ---------------------------------------------------------------------------


def revoke_token(jti: str, user_id: int, expires_at: str) -> None:
    """Add a JWT ID to the revocation list."""
    now = datetime.utcnow().isoformat()
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO revoked_tokens (jti, user_id, revoked_at, expires_at) VALUES (?, ?, ?, ?)",
                (jti, user_id, now, expires_at),
            )
    except Exception:
        pass  # best-effort; auth check still validates is_active


def is_token_revoked(jti: str) -> bool:
    """Check if a token has been explicitly revoked."""
    with _connect() as conn:
        row = conn.execute("SELECT 1 FROM revoked_tokens WHERE jti = ?", (jti,)).fetchone()
    return row is not None


def revoke_all_user_tokens(user_id: int) -> None:
    """Revoke all tokens for a user (e.g. on deactivation)."""
    now = datetime.utcnow().isoformat()
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO revoked_tokens (jti, user_id, revoked_at, expires_at) "
                "SELECT '__all_before_' || ?, ?, ?, datetime(?, '+7 days')",
                (now, user_id, now, now),
            )
    except Exception:
        pass


def cleanup_expired_revocations() -> int:
    """Remove revocation entries for tokens that have already expired. Returns count removed."""
    now = datetime.utcnow().isoformat()
    with _connect() as conn:
        result = conn.execute("DELETE FROM revoked_tokens WHERE expires_at < ?", (now,))
    return result.rowcount


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
    request_id: Optional[str] = None,
) -> None:
    """Write a single audit record. Fire-and-forget; never raises."""
    try:
        now = datetime.utcnow().isoformat()
        with _connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_log
                  (user_id, username, action, resource, ip_address,
                   user_agent, status_code, detail, request_id, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    request_id,
                    now,
                ),
            )
    except Exception:
        pass  # audit failures must not break the request


def rotate_audit_logs(keep_days: int = 90) -> dict:
    """Archive and remove audit log entries older than keep_days.

    Exports old entries to a gzipped JSON file in ~/.vlair/audit_archive/,
    then deletes them from the database.

    Returns: {"archived_count": int, "archive_path": str or None}
    """
    import gzip
    from datetime import timedelta

    cutoff = (datetime.utcnow() - timedelta(days=keep_days)).isoformat()

    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_log WHERE timestamp < ? ORDER BY timestamp ASC",
            (cutoff,),
        ).fetchall()

    if not rows:
        return {"archived_count": 0, "archive_path": None}

    records = [dict(r) for r in rows]

    archive_dir = Path.home() / ".vlair" / "audit_archive"
    archive_dir.mkdir(parents=True, exist_ok=True)
    filename = f"audit_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json.gz"
    archive_path = archive_dir / filename

    with gzip.open(str(archive_path), "wt", encoding="utf-8") as f:
        import json as _json

        _json.dump(records, f, indent=2)

    # Delete archived records from the database
    ids = [r["id"] for r in records]
    with _connect() as conn:
        # SQLite has a limit on variables; delete in batches
        batch_size = 500
        for i in range(0, len(ids), batch_size):
            batch = ids[i : i + batch_size]
            placeholders = ",".join("?" for _ in batch)
            conn.execute(f"DELETE FROM audit_log WHERE id IN ({placeholders})", batch)

    return {"archived_count": len(records), "archive_path": str(archive_path)}


def get_audit_stats() -> dict:
    """Return audit log statistics: total_entries, oldest_entry, newest_entry, size_by_action."""
    with _connect() as conn:
        total_row = conn.execute("SELECT COUNT(*) AS cnt FROM audit_log").fetchone()
        total = total_row["cnt"] if total_row else 0

        oldest_row = conn.execute("SELECT MIN(timestamp) AS ts FROM audit_log").fetchone()
        oldest = oldest_row["ts"] if oldest_row else None

        newest_row = conn.execute("SELECT MAX(timestamp) AS ts FROM audit_log").fetchone()
        newest = newest_row["ts"] if newest_row else None

        action_rows = conn.execute(
            "SELECT action, COUNT(*) AS cnt FROM audit_log GROUP BY action ORDER BY cnt DESC"
        ).fetchall()
        size_by_action = {r["action"]: r["cnt"] for r in action_rows}

    return {
        "total_entries": total,
        "oldest_entry": oldest,
        "newest_entry": newest,
        "size_by_action": size_by_action,
    }


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
