"""
vlair Bot Context — SQLite-backed per-channel conversation context and rate limiting.

Database is stored at ~/.vlair/bot.db by default.
"""

import sqlite3
import time
from pathlib import Path
from typing import Dict, List, Optional


_DEFAULT_DB = Path.home() / ".vlair" / "bot.db"


class BotContext:
    """
    Manages per-channel conversation context and per-user rate limiting.

    Tables
    ------
    messages
        Stores every message exchanged through the bot, keyed by
        (platform, channel_id, thread_ts).
    rate_limits
        Rolling counts of requests per user for rate-limit enforcement.
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = Path(db_path) if db_path else _DEFAULT_DB
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS messages (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    platform    TEXT    NOT NULL,
                    channel_id  TEXT    NOT NULL,
                    thread_ts   TEXT    NOT NULL DEFAULT '',
                    user_id     TEXT    NOT NULL DEFAULT '',
                    role        TEXT    NOT NULL,
                    content     TEXT    NOT NULL,
                    created_at  REAL    NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_messages_thread
                    ON messages (channel_id, thread_ts);

                CREATE TABLE IF NOT EXISTS rate_limits (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id     TEXT    NOT NULL,
                    requested_at REAL   NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_rate_limits_user
                    ON rate_limits (user_id, requested_at);
                """
            )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Message storage
    # ------------------------------------------------------------------

    def add_message(
        self,
        platform: str,
        channel_id: str,
        thread_ts: str,
        user_id: str,
        role: str,
        content: str,
    ) -> None:
        """Persist a message to the conversation history."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO messages (platform, channel_id, thread_ts, user_id, role, content, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (platform, channel_id, thread_ts, user_id, role, content, time.time()),
            )

    def get_thread_context(
        self,
        channel_id: str,
        thread_ts: str,
        limit: int = 10,
    ) -> List[Dict]:
        """
        Return the most recent *limit* messages for the given thread,
        ordered oldest-first (suitable for building an LLM prompt).
        """
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT role, content, user_id, created_at
                FROM messages
                WHERE channel_id = ? AND thread_ts = ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (channel_id, thread_ts, limit),
            ).fetchall()

        # Reverse so we get chronological order
        return [dict(r) for r in reversed(rows)]

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    def check_rate_limit(self, user_id: str, limit_per_hour: int = 20) -> bool:
        """
        Return True if the user is allowed to make another request.

        Records the request attempt in the database regardless of outcome
        so that callers do not need to make a separate "record" call.
        """
        window_start = time.time() - 3600  # rolling 1-hour window
        now = time.time()

        with self._connect() as conn:
            count = conn.execute(
                """
                SELECT COUNT(*) FROM rate_limits
                WHERE user_id = ? AND requested_at >= ?
                """,
                (user_id, window_start),
            ).fetchone()[0]

            if count >= limit_per_hour:
                return False

            conn.execute(
                "INSERT INTO rate_limits (user_id, requested_at) VALUES (?, ?)",
                (user_id, now),
            )

        return True

    # ------------------------------------------------------------------
    # Maintenance
    # ------------------------------------------------------------------

    def cleanup_old_messages(self, days: int = 7) -> int:
        """Delete messages older than *days* days. Returns the row count deleted."""
        cutoff = time.time() - days * 86400
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM messages WHERE created_at < ?",
                (cutoff,),
            )
            deleted = cursor.rowcount

            # Also clean up old rate-limit rows (keep 2-hour window for safety)
            conn.execute(
                "DELETE FROM rate_limits WHERE requested_at < ?",
                (time.time() - 7200,),
            )

        return deleted
