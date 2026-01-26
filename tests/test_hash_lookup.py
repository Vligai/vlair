#!/usr/bin/env python3
"""
Unit tests for Hash Lookup
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from hashLookup.lookup import HashValidator, RateLimiter
from common.cache_manager import CacheManager


class TestHashValidator:
    """Test hash validation"""

    def test_validate_md5(self):
        """Test MD5 validation"""
        is_valid, hash_type = HashValidator.validate("5d41402abc4b2a76b9719d911017c592")
        assert is_valid is True
        assert hash_type == "md5"

    def test_validate_sha1(self):
        """Test SHA1 validation"""
        is_valid, hash_type = HashValidator.validate("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
        assert is_valid is True
        assert hash_type == "sha1"

    def test_validate_sha256(self):
        """Test SHA256 validation"""
        is_valid, hash_type = HashValidator.validate("2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae")
        assert is_valid is True
        assert hash_type == "sha256"

    def test_validate_sha512(self):
        """Test SHA512 validation"""
        hash_value = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" * 2  # 128 chars
        is_valid, hash_type = HashValidator.validate(hash_value[:128])
        assert is_valid is True
        assert hash_type == "sha512"

    def test_validate_invalid_length(self):
        """Test invalid hash length"""
        is_valid, hash_type = HashValidator.validate("invalid123")
        assert is_valid is False
        assert hash_type is None

    def test_validate_invalid_characters(self):
        """Test invalid characters in hash"""
        is_valid, hash_type = HashValidator.validate("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")  # 32 chars but invalid
        assert is_valid is False
        assert hash_type is None

    def test_normalize(self):
        """Test hash normalization"""
        normalized = HashValidator.normalize("  5D41402ABC4B2A76B9719D911017C592  ")
        assert normalized == "5d41402abc4b2a76b9719d911017c592"


class TestCacheManager:
    """Test cache management"""

    def test_cache_set_and_get(self):
        """Test setting and getting from cache"""
        cache = CacheManager(default_ttl=3600)

        test_data = {"verdict": "malicious", "score": 85}
        cache.set("test_hash", test_data, namespace="test")

        result = cache.get("test_hash", namespace="test")
        assert result is not None
        assert result["verdict"] == "malicious"
        assert result["score"] == 85

    def test_cache_miss(self):
        """Test cache miss"""
        cache = CacheManager()

        result = cache.get("nonexistent_hash", namespace="test_miss")
        assert result is None

    def test_cache_stats(self):
        """Test cache statistics"""
        cache = CacheManager()

        # Generate some hits and misses
        cache.set("hash1", {"data": "test"}, namespace="test_stats")
        cache.get("hash1", namespace="test_stats")  # Hit
        cache.get("nonexistent", namespace="test_stats")  # Miss

        stats = cache.get_stats()
        assert stats["hits"] >= 1
        assert stats["misses"] >= 1


class TestRateLimiter:
    """Test rate limiting"""

    def test_rate_limiter_init(self):
        """Test rate limiter initialization"""
        limiter = RateLimiter(requests_per_minute=60)
        assert limiter.requests_per_minute == 60
        assert limiter.interval == 1.0

    def test_rate_limiter_interval(self):
        """Test rate limiter interval calculation"""
        limiter = RateLimiter(requests_per_minute=4)
        assert limiter.interval == 15.0  # 60 seconds / 4 requests

    def test_rate_limiter_wait(self):
        """Test rate limiter wait (basic test)"""
        limiter = RateLimiter(requests_per_minute=60)
        # Just verify it doesn't raise an exception
        limiter.wait()
        assert limiter.last_request > 0


class TestHashLookupIntegration:
    """Integration tests for hash lookup (mocked APIs)"""

    @patch("hashLookup.lookup.VirusTotalAPI")
    @patch("hashLookup.lookup.MalwareBazaarAPI")
    @patch("hashLookup.lookup.get_cache")
    def test_lookup_with_mocked_apis(self, mock_get_cache, mock_mb, mock_vt, tmp_path):
        """Test hash lookup with mocked APIs"""
        from hashLookup.lookup import HashLookup

        # Mock cache
        mock_cache_instance = Mock()
        mock_cache_instance.get.return_value = None
        mock_get_cache.return_value = mock_cache_instance

        # Mock VT response
        mock_vt_instance = Mock()
        mock_vt_instance.lookup_hash.return_value = {
            "source": "virustotal",
            "verdict": "malicious",
            "detection_ratio": "45/65",
            "malicious": 45,
        }
        mock_vt.return_value = mock_vt_instance

        # Mock MB response
        mock_mb_instance = Mock()
        mock_mb_instance.lookup_hash.return_value = {
            "source": "malwarebazaar",
            "verdict": "malicious",
            "signature": "TrickBot",
        }
        mock_mb.return_value = mock_mb_instance

        # Create lookup with mocked APIs
        with patch.dict("os.environ", {"VT_API_KEY": "test_key"}):
            lookup = HashLookup(cache_enabled=True, verbose=False)

            # Lookup hash
            result = lookup.lookup("5d41402abc4b2a76b9719d911017c592")

            assert result["hash_type"] == "md5"
            assert result["verdict"] == "malicious"
            # At least one source should be present
            assert len(result["sources"]) > 0
            assert "malwarebazaar" in result["sources"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
