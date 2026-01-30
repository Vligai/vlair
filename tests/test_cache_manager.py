#!/usr/bin/env python3
"""
Unit tests for Cache Manager
Tests in-memory cache fallback functionality
"""

import pytest
import sys
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from vlair.common.cache_manager import CacheManager, get_cache, hash_key


class TestCacheManager:
    """Test CacheManager class"""

    def test_init_memory_backend(self):
        """Test initialization with memory backend when Redis unavailable"""
        with patch("vlair.common.cache_manager.REDIS_AVAILABLE", False):
            cache = CacheManager()
            assert cache.backend == "memory"
            assert cache.redis_client is None
            assert cache.fallback_cache == {}

    def test_make_key(self):
        """Test key generation with namespace"""
        cache = CacheManager()
        key = cache._make_key("test_ns", "my_key")
        assert key == "secops:test_ns:my_key"

    def test_make_stats_key(self):
        """Test stats key generation"""
        cache = CacheManager()
        key = cache._make_stats_key("test_ns")
        assert key == "secops:stats:test_ns"

    def test_set_and_get_memory(self):
        """Test set and get with memory backend"""
        with patch("vlair.common.cache_manager.REDIS_AVAILABLE", False):
            cache = CacheManager()

            # Set a value
            result = cache.set("test_key", {"data": "test_value"}, namespace="test")
            assert result is True
            assert cache.stats["sets"] == 1

            # Get the value
            value = cache.get("test_key", namespace="test")
            assert value == {"data": "test_value"}
            assert cache.stats["hits"] == 1

    def test_get_miss_memory(self):
        """Test get miss with memory backend"""
        with patch("vlair.common.cache_manager.REDIS_AVAILABLE", False):
            cache = CacheManager()

            value = cache.get("nonexistent_key", namespace="test")
            assert value is None
            assert cache.stats["misses"] == 1

    def test_delete_memory(self):
        """Test delete with memory backend"""
        with patch("vlair.common.cache_manager.REDIS_AVAILABLE", False):
            cache = CacheManager()

            # Set then delete
            cache.set("test_key", {"data": "test"}, namespace="test")
            result = cache.delete("test_key", namespace="test")
            assert result is True
            assert cache.stats["deletes"] == 1

            # Verify deleted
            value = cache.get("test_key", namespace="test")
            assert value is None

    def test_ttl_expiration_memory(self):
        """Test TTL expiration with memory backend"""
        with patch("vlair.common.cache_manager.REDIS_AVAILABLE", False):
            cache = CacheManager()

            # Set with 1 second TTL
            cache.set("expiring_key", {"data": "test"}, namespace="test", ttl=1)

            # Should be available immediately
            value = cache.get("expiring_key", namespace="test")
            assert value == {"data": "test"}

            # Wait for expiration
            time.sleep(1.1)

            # Should be expired
            value = cache.get("expiring_key", namespace="test")
            assert value is None

    def test_clear_namespace_memory(self):
        """Test clear namespace with memory backend"""
        with patch("vlair.common.cache_manager.REDIS_AVAILABLE", False):
            cache = CacheManager()

            # Set multiple keys in different namespaces
            cache.set("key1", "value1", namespace="ns1")
            cache.set("key2", "value2", namespace="ns1")
            cache.set("key3", "value3", namespace="ns2")

            # Clear ns1
            deleted = cache.clear_namespace("ns1")
            assert deleted == 2

            # ns1 keys should be gone
            assert cache.get("key1", namespace="ns1") is None
            assert cache.get("key2", namespace="ns1") is None

            # ns2 key should still exist
            assert cache.get("key3", namespace="ns2") == "value3"

    def test_clear_all_memory(self):
        """Test clear all with memory backend"""
        with patch("vlair.common.cache_manager.REDIS_AVAILABLE", False):
            cache = CacheManager()

            cache.set("key1", "value1", namespace="ns1")
            cache.set("key2", "value2", namespace="ns2")

            result = cache.clear_all()
            assert result is True
            assert len(cache.fallback_cache) == 0

    def test_get_stats_memory(self):
        """Test get stats with memory backend"""
        with patch("vlair.common.cache_manager.REDIS_AVAILABLE", False):
            cache = CacheManager()

            cache.set("key1", "value1", namespace="test")
            cache.get("key1", namespace="test")  # hit
            cache.get("nonexistent", namespace="test")  # miss

            stats = cache.get_stats()
            assert stats["backend"] == "memory"
            assert stats["hits"] == 1
            assert stats["misses"] == 1
            assert stats["sets"] == 1
            assert stats["hit_rate"] == 50.0

    def test_get_namespaces_memory(self):
        """Test get namespaces with memory backend"""
        with patch("vlair.common.cache_manager.REDIS_AVAILABLE", False):
            cache = CacheManager()

            cache.set("key1", "value1", namespace="ns1")
            cache.set("key2", "value2", namespace="ns2")
            cache.set("key3", "value3", namespace="ns1")

            namespaces = cache.get_namespaces()
            assert sorted(namespaces) == ["ns1", "ns2"]

    def test_health_check_memory(self):
        """Test health check with memory backend"""
        with patch("vlair.common.cache_manager.REDIS_AVAILABLE", False):
            cache = CacheManager()

            health = cache.health_check()
            assert health["backend"] == "memory"
            assert health["healthy"] is True
            assert "note" in health

    def test_default_namespace(self):
        """Test default namespace"""
        with patch("vlair.common.cache_manager.REDIS_AVAILABLE", False):
            cache = CacheManager()

            cache.set("key1", "value1")
            value = cache.get("key1")
            assert value == "value1"

    def test_custom_default_ttl(self):
        """Test custom default TTL"""
        with patch("vlair.common.cache_manager.REDIS_AVAILABLE", False):
            cache = CacheManager(default_ttl=3600)
            assert cache.default_ttl == 3600


class TestHashKey:
    """Test hash_key function"""

    def test_hash_key_single_arg(self):
        """Test hash_key with single argument"""
        key = hash_key("test")
        assert len(key) == 16
        assert isinstance(key, str)

    def test_hash_key_multiple_args(self):
        """Test hash_key with multiple arguments"""
        key = hash_key("arg1", "arg2", "arg3")
        assert len(key) == 16

    def test_hash_key_consistency(self):
        """Test hash_key produces consistent results"""
        key1 = hash_key("test", "data")
        key2 = hash_key("test", "data")
        assert key1 == key2

    def test_hash_key_different_inputs(self):
        """Test hash_key produces different results for different inputs"""
        key1 = hash_key("test1")
        key2 = hash_key("test2")
        assert key1 != key2


class TestGetCache:
    """Test get_cache singleton function"""

    def test_get_cache_returns_instance(self):
        """Test get_cache returns CacheManager instance"""
        with patch("vlair.common.cache_manager.REDIS_AVAILABLE", False):
            with patch("vlair.common.cache_manager._cache_instance", None):
                cache = get_cache()
                assert isinstance(cache, CacheManager)

    def test_get_cache_singleton(self):
        """Test get_cache returns same instance"""
        with patch("vlair.common.cache_manager.REDIS_AVAILABLE", False):
            with patch("vlair.common.cache_manager._cache_instance", None):
                cache1 = get_cache()
                cache2 = get_cache()
                assert cache1 is cache2
