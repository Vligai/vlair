"""
vlair AI Cache — SQLite-backed persistent cache with token usage tracking.
"""

import json
import sqlite3
import time
from pathlib import Path
from typing import Optional

# Cost estimates per 1 000 tokens (input + output averaged)
# Source: approximate public pricing as of 2026-Q1
_COST_PER_1K: dict = {
    "anthropic": 0.009,  # claude-sonnet ~$0.003 in + $0.015 out → ~$0.009 blended
    "openai": 0.02,  # gpt-4-turbo ~$0.01 in + $0.03 out → ~$0.02 blended
    "ollama": 0.0,  # local — free
}


class AIResponseCache:
    """
    SQLite-backed persistent cache for AI responses with per-request usage tracking.

    Schema
    ------
    cache:
        key TEXT PRIMARY KEY
        result_json TEXT
        tokens_used INTEGER
        provider TEXT
        model TEXT
        created_at REAL   (Unix epoch float)

    usage_log:
        id INTEGER PRIMARY KEY AUTOINCREMENT
        request_time REAL
        cache_hit INTEGER  (0 / 1)
        tokens_used INTEGER
        provider TEXT
        model TEXT
    """

    def __init__(self, db_path: Optional[str] = None, ttl_hours: int = 24) -> None:
        if db_path is None:
            vlair_dir = Path.home() / ".vlair"
            vlair_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(vlair_dir / "ai_cache.db")
        self.db_path = db_path
        self.ttl_seconds = ttl_hours * 3600
        self._init_db()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, cache_key: str) -> Optional[dict]:
        """Return the cached result dict if present and not expired, else None."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT result_json, tokens_used, provider, model, created_at "
                "FROM cache WHERE key = ?",
                (cache_key,),
            ).fetchone()

        if row is None:
            return None

        result_json, tokens_used, provider, model, created_at = row
        if time.time() - created_at > self.ttl_seconds:
            self._delete(cache_key)
            return None

        self._log_request(cache_hit=True, tokens_used=tokens_used, provider=provider, model=model)
        return json.loads(result_json)

    def set(
        self,
        cache_key: str,
        result: dict,
        tokens_used: int = 0,
        provider: str = "",
        model: str = "",
    ) -> None:
        """Store a result and append a usage log entry."""
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO cache (key, result_json, tokens_used, provider, model, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    cache_key,
                    json.dumps(result, default=str),
                    tokens_used,
                    provider,
                    model,
                    time.time(),
                ),
            )
        self._log_request(cache_hit=False, tokens_used=tokens_used, provider=provider, model=model)

    def get_stats(self) -> dict:
        """
        Return aggregated usage statistics.

        Keys: today_requests, today_tokens, month_requests, month_tokens,
              cache_hit_rate, cost_estimate_today, cost_estimate_month,
              provider_breakdown.
        """
        now = time.time()
        day_start = now - 86400
        month_start = now - 86400 * 30

        with self._connect() as conn:
            # Today
            today = conn.execute(
                "SELECT COUNT(*), SUM(tokens_used), SUM(cache_hit) FROM usage_log WHERE request_time >= ?",
                (day_start,),
            ).fetchone()
            # Month
            month = conn.execute(
                "SELECT COUNT(*), SUM(tokens_used), SUM(cache_hit) FROM usage_log WHERE request_time >= ?",
                (month_start,),
            ).fetchone()
            # Provider breakdown (today)
            provider_rows = conn.execute(
                "SELECT provider, COUNT(*), SUM(tokens_used) FROM usage_log "
                "WHERE request_time >= ? AND cache_hit = 0 GROUP BY provider",
                (day_start,),
            ).fetchall()
            # All-time totals for hit rate
            total = conn.execute("SELECT COUNT(*), SUM(cache_hit) FROM usage_log").fetchone()

        today_requests = today[0] or 0
        today_tokens = today[1] or 0
        today_hits = today[2] or 0
        month_requests = month[0] or 0
        month_tokens = month[1] or 0
        all_requests = total[0] or 0
        all_hits = total[1] or 0

        hit_rate = round(all_hits / all_requests * 100, 1) if all_requests > 0 else 0.0

        # Cost estimate — only non-cached (real API) requests matter
        today_non_cache = today_requests - today_hits
        month_non_cache = month_requests - (month[2] or 0)

        # Estimate cost from provider breakdown
        cost_today = 0.0
        cost_month = 0.0
        for pname, count, toks in provider_rows:
            rate = _COST_PER_1K.get(pname, 0.009)
            cost_today += ((toks or 0) / 1000) * rate

        # Rough month cost: scale today cost by (month_non_cache / today_non_cache)
        if today_non_cache > 0 and month_non_cache > 0:
            scale = month_non_cache / today_non_cache
            cost_month = cost_today * scale
        else:
            cost_month = cost_today

        provider_breakdown = {
            pname: {"requests": cnt, "tokens": toks or 0} for pname, cnt, toks in provider_rows
        }

        return {
            "today_requests": today_requests,
            "today_tokens": today_tokens,
            "month_requests": month_requests,
            "month_tokens": month_tokens,
            "cache_hit_rate": hit_rate,
            "cost_estimate_today": round(cost_today, 4),
            "cost_estimate_month": round(cost_month, 4),
            "provider_breakdown": provider_breakdown,
        }

    def clear_expired(self) -> int:
        """Delete expired cache entries. Returns number of rows deleted."""
        cutoff = time.time() - self.ttl_seconds
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM cache WHERE created_at < ?", (cutoff,))
            return cur.rowcount

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS cache (
                    key TEXT PRIMARY KEY,
                    result_json TEXT NOT NULL,
                    tokens_used INTEGER DEFAULT 0,
                    provider TEXT DEFAULT '',
                    model TEXT DEFAULT '',
                    created_at REAL NOT NULL
                )"""
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS usage_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_time REAL NOT NULL,
                    cache_hit INTEGER NOT NULL DEFAULT 0,
                    tokens_used INTEGER DEFAULT 0,
                    provider TEXT DEFAULT '',
                    model TEXT DEFAULT ''
                )"""
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_usage_time ON usage_log (request_time)")

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _delete(self, cache_key: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM cache WHERE key = ?", (cache_key,))

    def _log_request(self, cache_hit: bool, tokens_used: int, provider: str, model: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO usage_log (request_time, cache_hit, tokens_used, provider, model) "
                "VALUES (?, ?, ?, ?, ?)",
                (time.time(), int(cache_hit), tokens_used, provider, model),
            )
