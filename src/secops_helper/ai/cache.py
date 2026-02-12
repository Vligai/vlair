"""
AI Response Caching

Caches AI responses to reduce API costs and latency.
Uses SQLite for persistence.
"""

import hashlib
import json
import sqlite3
import time
from dataclasses import asdict
from pathlib import Path
from typing import Optional, Dict, Any

from .providers.base import AIResponse


class AIResponseCache:
    """Cache AI responses to reduce API costs and latency"""

    DEFAULT_CACHE_PATH = "~/.secops/ai_cache.db"
    DEFAULT_TTL_HOURS = 24

    def __init__(self, cache_path: Optional[str] = None, ttl_hours: int = DEFAULT_TTL_HOURS):
        """
        Initialize the AI response cache.

        Args:
            cache_path: Path to SQLite cache database
            ttl_hours: Time-to-live for cached responses in hours
        """
        if cache_path is None:
            cache_path = self.DEFAULT_CACHE_PATH

        self.cache_path = Path(cache_path).expanduser()
        self.ttl = ttl_hours * 3600  # Convert to seconds
        self._init_db()

    def _init_db(self):
        """Initialize the SQLite database schema"""
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)

        with sqlite3.connect(self.cache_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ai_responses (
                    cache_key TEXT PRIMARY KEY,
                    response_json TEXT NOT NULL,
                    model TEXT NOT NULL,
                    tokens_used INTEGER NOT NULL,
                    created_at INTEGER NOT NULL
                )
            """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_created_at
                ON ai_responses(created_at)
            """
            )
            conn.commit()

    def get_cache_key(self, input_value: str, input_type: str, prompt_hash: str, model: str) -> str:
        """
        Generate a cache key from input parameters.

        Args:
            input_value: The IOC or input being analyzed
            input_type: Type of input (hash, domain, etc.)
            prompt_hash: Hash of the prompt template used
            model: AI model being used

        Returns:
            SHA256 cache key
        """
        key_data = f"{input_value}:{input_type}:{prompt_hash}:{model}"
        return hashlib.sha256(key_data.encode()).hexdigest()

    def get(self, cache_key: str) -> Optional[AIResponse]:
        """
        Retrieve a cached response if valid.

        Args:
            cache_key: The cache key to look up

        Returns:
            Cached AIResponse or None if not found/expired
        """
        with sqlite3.connect(self.cache_path) as conn:
            cursor = conn.execute(
                """
                SELECT response_json, model, tokens_used, created_at
                FROM ai_responses
                WHERE cache_key = ?
                """,
                (cache_key,),
            )
            row = cursor.fetchone()

            if row is None:
                return None

            response_json, model, tokens_used, created_at = row

            # Check if expired
            if time.time() - created_at > self.ttl:
                # Delete expired entry
                conn.execute("DELETE FROM ai_responses WHERE cache_key = ?", (cache_key,))
                conn.commit()
                return None

            # Reconstruct AIResponse
            response_data = json.loads(response_json)
            return AIResponse(
                content=response_data.get("content", ""),
                confidence=response_data.get("confidence", 0.5),
                tokens_used=tokens_used,
                model=model,
                cached=True,
                verdict=response_data.get("verdict"),
                severity=response_data.get("severity"),
                key_findings=response_data.get("key_findings", []),
                threat_context=response_data.get("threat_context"),
                threat_type=response_data.get("threat_type"),
                threat_actor=response_data.get("threat_actor"),
                recommended_actions=response_data.get("recommended_actions", []),
                mitre_attack=response_data.get("mitre_attack", []),
                iocs=response_data.get("iocs", {}),
                siem_queries=response_data.get("siem_queries", {}),
                confidence_notes=response_data.get("confidence_notes"),
            )

    def set(self, cache_key: str, response: AIResponse):
        """
        Store a response in the cache.

        Args:
            cache_key: The cache key
            response: The AIResponse to cache
        """
        # Serialize response to JSON (excluding some fields)
        response_data = {
            "content": response.content,
            "confidence": response.confidence,
            "verdict": response.verdict.value if response.verdict else None,
            "severity": response.severity.value if response.severity else None,
            "key_findings": response.key_findings,
            "threat_context": response.threat_context,
            "threat_type": response.threat_type,
            "threat_actor": response.threat_actor,
            "recommended_actions": [
                {"priority": a.priority, "action": a.action, "details": a.details}
                for a in response.recommended_actions
            ],
            "mitre_attack": response.mitre_attack,
            "iocs": response.iocs,
            "siem_queries": response.siem_queries,
            "confidence_notes": response.confidence_notes,
        }

        with sqlite3.connect(self.cache_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO ai_responses
                (cache_key, response_json, model, tokens_used, created_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    cache_key,
                    json.dumps(response_data),
                    response.model,
                    response.tokens_used,
                    int(time.time()),
                ),
            )
            conn.commit()

    def clear_expired(self) -> int:
        """
        Remove all expired entries from the cache.

        Returns:
            Number of entries removed
        """
        cutoff = int(time.time()) - self.ttl

        with sqlite3.connect(self.cache_path) as conn:
            cursor = conn.execute("DELETE FROM ai_responses WHERE created_at < ?", (cutoff,))
            conn.commit()
            return cursor.rowcount

    def clear_all(self):
        """Remove all entries from the cache"""
        with sqlite3.connect(self.cache_path) as conn:
            conn.execute("DELETE FROM ai_responses")
            conn.commit()

    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache statistics
        """
        with sqlite3.connect(self.cache_path) as conn:
            # Total entries
            total = conn.execute("SELECT COUNT(*) FROM ai_responses").fetchone()[0]

            # Valid entries (not expired)
            cutoff = int(time.time()) - self.ttl
            valid = conn.execute(
                "SELECT COUNT(*) FROM ai_responses WHERE created_at >= ?", (cutoff,)
            ).fetchone()[0]

            # Total tokens cached
            tokens = conn.execute("SELECT SUM(tokens_used) FROM ai_responses").fetchone()[0] or 0

            # Models used
            models = conn.execute("SELECT DISTINCT model FROM ai_responses").fetchall()

            return {
                "total_entries": total,
                "valid_entries": valid,
                "expired_entries": total - valid,
                "total_tokens_cached": tokens,
                "models": [m[0] for m in models],
                "cache_path": str(self.cache_path),
                "ttl_hours": self.ttl // 3600,
            }
