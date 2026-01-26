#!/usr/bin/env python3
"""
Unified Cache Manager for SecOps Helper

Provides Redis-based caching with fallback to in-memory/SQLite caching.
Supports TTL, namespacing, and statistics tracking.
"""

import os
import json
import time
import hashlib
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta

try:
    import redis

    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False


class CacheManager:
    """
    Unified cache manager with Redis backend and fallback support.

    Features:
    - Redis-based distributed caching
    - Automatic TTL management
    - Namespace support for different tools
    - Cache statistics tracking
    - Fallback to in-memory dict if Redis unavailable
    """

    def __init__(self, redis_url: str = None, default_ttl: int = 86400):
        """
        Initialize cache manager.

        Args:
            redis_url: Redis connection URL (default: redis://localhost:6379/0)
            default_ttl: Default time-to-live in seconds (default: 24 hours)
        """
        self.default_ttl = default_ttl
        self.redis_client = None
        self.fallback_cache = {}  # In-memory fallback
        self.stats = {"hits": 0, "misses": 0, "sets": 0, "deletes": 0, "errors": 0}

        # Try to connect to Redis
        if REDIS_AVAILABLE:
            if not redis_url:
                redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")

            try:
                self.redis_client = redis.from_url(
                    redis_url, decode_responses=True, socket_connect_timeout=2, socket_timeout=2
                )
                # Test connection
                self.redis_client.ping()
                self.backend = "redis"
            except (redis.ConnectionError, redis.TimeoutError) as e:
                print(f"Warning: Redis connection failed ({e}). Using in-memory cache.")
                self.redis_client = None
                self.backend = "memory"
        else:
            print("Warning: redis-py not installed. Using in-memory cache.")
            self.backend = "memory"

    def _make_key(self, namespace: str, key: str) -> str:
        """Generate namespaced cache key"""
        return f"secops:{namespace}:{key}"

    def _make_stats_key(self, namespace: str) -> str:
        """Generate stats key for namespace"""
        return f"secops:stats:{namespace}"

    def get(self, key: str, namespace: str = "default") -> Optional[Any]:
        """
        Get value from cache.

        Args:
            key: Cache key
            namespace: Cache namespace (tool name)

        Returns:
            Cached value or None if not found/expired
        """
        cache_key = self._make_key(namespace, key)

        try:
            if self.redis_client:
                # Try Redis
                value = self.redis_client.get(cache_key)
                if value:
                    self.stats["hits"] += 1
                    self._update_stats(namespace, "hits")
                    return json.loads(value)
                else:
                    self.stats["misses"] += 1
                    self._update_stats(namespace, "misses")
                    return None
            else:
                # Fallback to in-memory
                if cache_key in self.fallback_cache:
                    entry = self.fallback_cache[cache_key]
                    # Check TTL
                    if entry["expires_at"] > time.time():
                        self.stats["hits"] += 1
                        return entry["value"]
                    else:
                        # Expired, remove it
                        del self.fallback_cache[cache_key]
                        self.stats["misses"] += 1
                        return None
                else:
                    self.stats["misses"] += 1
                    return None

        except Exception as e:
            self.stats["errors"] += 1
            print(f"Cache get error: {e}")
            return None

    def set(self, key: str, value: Any, namespace: str = "default", ttl: int = None) -> bool:
        """
        Set value in cache.

        Args:
            key: Cache key
            value: Value to cache (must be JSON-serializable)
            namespace: Cache namespace (tool name)
            ttl: Time-to-live in seconds (default: self.default_ttl)

        Returns:
            True if successful, False otherwise
        """
        if ttl is None:
            ttl = self.default_ttl

        cache_key = self._make_key(namespace, key)

        try:
            value_json = json.dumps(value)

            if self.redis_client:
                # Store in Redis with TTL
                self.redis_client.setex(cache_key, ttl, value_json)
            else:
                # Store in memory with expiry time
                self.fallback_cache[cache_key] = {"value": value, "expires_at": time.time() + ttl}

            self.stats["sets"] += 1
            self._update_stats(namespace, "sets")
            return True

        except Exception as e:
            self.stats["errors"] += 1
            print(f"Cache set error: {e}")
            return False

    def delete(self, key: str, namespace: str = "default") -> bool:
        """
        Delete value from cache.

        Args:
            key: Cache key
            namespace: Cache namespace

        Returns:
            True if successful, False otherwise
        """
        cache_key = self._make_key(namespace, key)

        try:
            if self.redis_client:
                self.redis_client.delete(cache_key)
            else:
                if cache_key in self.fallback_cache:
                    del self.fallback_cache[cache_key]

            self.stats["deletes"] += 1
            self._update_stats(namespace, "deletes")
            return True

        except Exception as e:
            self.stats["errors"] += 1
            print(f"Cache delete error: {e}")
            return False

    def clear_namespace(self, namespace: str) -> int:
        """
        Clear all keys in a namespace.

        Args:
            namespace: Namespace to clear

        Returns:
            Number of keys deleted
        """
        try:
            if self.redis_client:
                pattern = self._make_key(namespace, "*")
                keys = self.redis_client.keys(pattern)
                if keys:
                    return self.redis_client.delete(*keys)
                return 0
            else:
                # Clear from memory cache
                pattern = f"secops:{namespace}:"
                keys_to_delete = [k for k in self.fallback_cache.keys() if k.startswith(pattern)]
                for key in keys_to_delete:
                    del self.fallback_cache[key]
                return len(keys_to_delete)

        except Exception as e:
            self.stats["errors"] += 1
            print(f"Cache clear error: {e}")
            return 0

    def clear_all(self) -> bool:
        """
        Clear entire cache.

        Returns:
            True if successful
        """
        try:
            if self.redis_client:
                keys = self.redis_client.keys("secops:*")
                if keys:
                    self.redis_client.delete(*keys)
            else:
                self.fallback_cache.clear()
            return True

        except Exception as e:
            self.stats["errors"] += 1
            print(f"Cache clear all error: {e}")
            return False

    def get_stats(self, namespace: str = None) -> Dict[str, Any]:
        """
        Get cache statistics.

        Args:
            namespace: Get stats for specific namespace, or overall if None

        Returns:
            Dictionary with cache statistics
        """
        if namespace and self.redis_client:
            # Get namespace-specific stats from Redis
            stats_key = self._make_stats_key(namespace)
            stats = self.redis_client.hgetall(stats_key)
            if stats:
                return {k: int(v) for k, v in stats.items()}
            else:
                return {"hits": 0, "misses": 0, "sets": 0}
        else:
            # Return overall stats
            stats = self.stats.copy()

            # Add additional info
            if self.redis_client:
                try:
                    info = self.redis_client.info("stats")
                    stats["backend"] = "redis"
                    stats["total_keys"] = self.redis_client.dbsize()
                    stats["memory_used"] = self.redis_client.info("memory").get("used_memory_human", "N/A")
                    stats["uptime_seconds"] = info.get("uptime_in_seconds", 0)
                except:
                    pass
            else:
                stats["backend"] = "memory"
                stats["total_keys"] = len(self.fallback_cache)

            # Calculate hit rate
            total_requests = stats["hits"] + stats["misses"]
            if total_requests > 0:
                stats["hit_rate"] = round(stats["hits"] / total_requests * 100, 2)
            else:
                stats["hit_rate"] = 0.0

            return stats

    def _update_stats(self, namespace: str, stat_type: str):
        """Update namespace-specific statistics in Redis"""
        if self.redis_client:
            stats_key = self._make_stats_key(namespace)
            try:
                self.redis_client.hincrby(stats_key, stat_type, 1)
            except:
                pass

    def get_namespaces(self) -> List[str]:
        """
        Get list of active namespaces.

        Returns:
            List of namespace names
        """
        try:
            if self.redis_client:
                keys = self.redis_client.keys("secops:*:*")
                namespaces = set()
                for key in keys:
                    parts = key.split(":")
                    if len(parts) >= 2 and parts[1] != "stats":
                        namespaces.add(parts[1])
                return sorted(list(namespaces))
            else:
                namespaces = set()
                for key in self.fallback_cache.keys():
                    parts = key.split(":")
                    if len(parts) >= 2:
                        namespaces.add(parts[1])
                return sorted(list(namespaces))

        except Exception as e:
            print(f"Error getting namespaces: {e}")
            return []

    def health_check(self) -> Dict[str, Any]:
        """
        Check cache health status.

        Returns:
            Health status dictionary
        """
        health = {"backend": self.backend, "healthy": True, "error": None}

        if self.redis_client:
            try:
                # Test Redis connection
                self.redis_client.ping()
                info = self.redis_client.info("server")
                health["version"] = info.get("redis_version", "unknown")
                health["uptime_seconds"] = self.redis_client.info("stats").get("uptime_in_seconds", 0)
            except Exception as e:
                health["healthy"] = False
                health["error"] = str(e)
        else:
            health["note"] = "Using in-memory fallback cache"

        return health


# Global cache instance
_cache_instance = None


def get_cache() -> CacheManager:
    """
    Get global cache instance (singleton pattern).

    Returns:
        CacheManager instance
    """
    global _cache_instance
    if _cache_instance is None:
        _cache_instance = CacheManager()
    return _cache_instance


def hash_key(*args) -> str:
    """
    Generate consistent hash key from arguments.

    Args:
        *args: Values to hash

    Returns:
        SHA256 hash string
    """
    key_str = ":".join(str(arg) for arg in args)
    return hashlib.sha256(key_str.encode()).hexdigest()[:16]
