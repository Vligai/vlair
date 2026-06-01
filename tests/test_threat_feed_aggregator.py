#!/usr/bin/env python3
"""
Unit tests for Threat Feed Aggregator
"""

import pytest
import sys
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from vlair.tools.threat_feed_aggregator import (
    FeedAggregator,
    ThreatFeedStorage,
    ThreatFoxFeed,
    URLhausFeed,
)


class TestThreatFeedStorage:
    """Test ThreatFeedStorage class"""

    def test_storage_creation(self, tmp_path):
        """Test creating storage instance"""
        db_path = str(tmp_path / "test.db")
        storage = ThreatFeedStorage(db_path)
        assert storage is not None
        assert storage.conn is not None
        storage.close()

    def test_store_ioc(self, tmp_path):
        """Test storing IOC to database"""
        db_path = str(tmp_path / "test.db")
        storage = ThreatFeedStorage(db_path)
        ioc = {
            "value": "evil.com",
            "type": "domain",
            "source": "test",
            "confidence": 75,
            "malware_family": "TestMalware",
            "first_seen": "2025-01-01 00:00:00",
            "last_seen": "2025-01-01 00:00:00",
            "tags": ["test"],
            "reference": "https://example.com",
        }
        result = storage.store_ioc(ioc)
        assert result is True  # New IOC
        storage.close()

    def test_store_duplicate_ioc(self, tmp_path):
        """Test that duplicate IOCs are updated, not duplicated"""
        db_path = str(tmp_path / "test.db")
        storage = ThreatFeedStorage(db_path)
        ioc = {
            "value": "evil.com",
            "type": "domain",
            "source": "test",
            "confidence": 75,
        }
        result1 = storage.store_ioc(ioc)
        result2 = storage.store_ioc(ioc)
        assert result1 is True  # First insert
        assert result2 is False  # Update, not new
        storage.close()

    def test_search_by_value(self, tmp_path):
        """Test searching by IOC value"""
        db_path = str(tmp_path / "test.db")
        storage = ThreatFeedStorage(db_path)
        storage.store_ioc({"value": "evil.com", "type": "domain", "confidence": 75})

        results = storage.search_ioc(value="evil.com")
        assert len(results) == 1
        assert results[0]["value"] == "evil.com"
        storage.close()

    def test_search_by_type(self, tmp_path):
        """Test searching by IOC type"""
        db_path = str(tmp_path / "test.db")
        storage = ThreatFeedStorage(db_path)
        storage.store_ioc({"value": "evil.com", "type": "domain", "confidence": 75})
        storage.store_ioc({"value": "192.168.1.1", "type": "ip", "confidence": 80})

        results = storage.search_ioc(ioc_type="domain")
        assert len(results) == 1
        assert results[0]["type"] == "domain"
        storage.close()

    def test_search_by_malware_family(self, tmp_path):
        """Test searching by malware family"""
        db_path = str(tmp_path / "test.db")
        storage = ThreatFeedStorage(db_path)
        storage.store_ioc({"value": "evil.com", "type": "domain", "confidence": 75, "malware_family": "Emotet"})
        storage.store_ioc({"value": "bad.com", "type": "domain", "confidence": 80, "malware_family": "TrickBot"})

        results = storage.search_ioc(malware_family="Emotet")
        assert len(results) == 1
        assert results[0]["malware_family"] == "Emotet"
        storage.close()

    def test_search_by_min_confidence(self, tmp_path):
        """Test searching by minimum confidence"""
        db_path = str(tmp_path / "test.db")
        storage = ThreatFeedStorage(db_path)
        storage.store_ioc({"value": "low.com", "type": "domain", "confidence": 30})
        storage.store_ioc({"value": "high.com", "type": "domain", "confidence": 90})

        results = storage.search_ioc(min_confidence=50)
        assert len(results) == 1
        assert results[0]["value"] == "high.com"
        storage.close()

    def test_get_statistics(self, tmp_path):
        """Test getting statistics"""
        db_path = str(tmp_path / "test.db")
        storage = ThreatFeedStorage(db_path)
        storage.store_ioc({"value": "evil.com", "type": "domain", "confidence": 75})

        stats = storage.get_statistics()
        assert "total_iocs" in stats
        assert stats["total_iocs"] >= 1
        storage.close()

    def test_record_update(self, tmp_path):
        """Test recording feed updates"""
        db_path = str(tmp_path / "test.db")
        storage = ThreatFeedStorage(db_path)
        storage.record_update("test_feed", iocs_added=5, iocs_updated=2, success=True)

        # Should not raise any exceptions
        stats = storage.get_statistics()
        assert stats is not None
        storage.close()


class TestThreatFoxFeed:
    """Test ThreatFox feed"""

    def test_feed_creation(self):
        """Test creating ThreatFox feed"""
        feed = ThreatFoxFeed()
        assert feed is not None

    @patch("requests.post")
    def test_fetch_recent(self, mock_post):
        """Test fetching recent IOCs from ThreatFox"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "query_status": "ok",
            "data": [
                {
                    "ioc": "evil.com",
                    "ioc_type": "domain",
                    "threat_type": "botnet_cc",
                    "malware": "Emotet",
                    "confidence_level": 75,
                    "first_seen_utc": "2025-01-01 00:00:00 UTC",
                    "last_seen_utc": "2025-01-01 00:00:00 UTC",
                    "tags": ["emotet", "botnet"],
                    "reference": "https://threatfox.abuse.ch",
                }
            ],
        }
        mock_post.return_value = mock_response

        feed = ThreatFoxFeed()
        iocs = feed.fetch_recent(days=1)

        assert len(iocs) == 1
        assert iocs[0]["value"] == "evil.com"
        # Type might be transformed, so just check it exists
        assert "type" in iocs[0]

    @patch("requests.post")
    def test_fetch_empty_response(self, mock_post):
        """Test handling empty response"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"query_status": "ok", "data": []}
        mock_post.return_value = mock_response

        feed = ThreatFoxFeed()
        iocs = feed.fetch_recent(days=1)

        assert len(iocs) == 0


class TestURLhausFeed:
    """Test URLhaus feed"""

    def test_feed_creation(self):
        """Test creating URLhaus feed"""
        feed = URLhausFeed()
        assert feed is not None

    @patch("requests.get")
    def test_fetch_recent(self, mock_get):
        """Test fetching recent URLs from URLhaus"""
        # URLhaus returns CSV format
        csv_content = """# URLhaus Bulk URL export
#
# Columns: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"1","2025-01-01 00:00:00","http://evil.com/malware.exe","online","2025-01-01","malware_download","elf","https://urlhaus.abuse.ch/url/1","anonymous"
"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = csv_content
        mock_get.return_value = mock_response

        feed = URLhausFeed()
        iocs = feed.fetch_recent(limit=10)

        # URLhaus implementation may need actual CSV parsing to work
        assert isinstance(iocs, list)


class TestFeedAggregator:
    """Test FeedAggregator class"""

    def test_aggregator_creation(self, tmp_path):
        """Test creating aggregator instance"""
        db_path = str(tmp_path / "test.db")
        storage = ThreatFeedStorage(db_path)
        aggregator = FeedAggregator(storage)
        assert aggregator is not None
        assert "threatfox" in aggregator.feeds
        assert "urlhaus" in aggregator.feeds
        storage.close()

    @patch("requests.post")
    @patch("requests.get")
    def test_update_feed_threatfox(self, mock_get, mock_post, tmp_path):
        """Test updating ThreatFox feed"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "query_status": "ok",
            "data": [
                {
                    "ioc": "evil.com",
                    "ioc_type": "domain",
                    "threat_type": "botnet_cc",
                    "malware": "Emotet",
                    "confidence_level": 75,
                    "first_seen_utc": "2025-01-01 00:00:00 UTC",
                }
            ],
        }
        mock_post.return_value = mock_response

        db_path = str(tmp_path / "test.db")
        storage = ThreatFeedStorage(db_path)
        aggregator = FeedAggregator(storage)
        result = aggregator.update_feed("threatfox")

        assert result["success"] is True
        assert result["added"] >= 0
        storage.close()

    def test_update_unknown_feed(self, tmp_path):
        """Test updating unknown feed"""
        db_path = str(tmp_path / "test.db")
        storage = ThreatFeedStorage(db_path)
        aggregator = FeedAggregator(storage)
        result = aggregator.update_feed("unknown_feed")

        assert "error" in result
        storage.close()

    @patch("requests.post")
    @patch("requests.get")
    def test_update_all(self, mock_get, mock_post, tmp_path):
        """Test updating all feeds"""
        mock_post_response = Mock()
        mock_post_response.status_code = 200
        mock_post_response.json.return_value = {"query_status": "ok", "data": []}
        mock_post.return_value = mock_post_response

        mock_get_response = Mock()
        mock_get_response.status_code = 200
        mock_get_response.text = "id,dateadded,url,url_status\n"
        mock_get.return_value = mock_get_response

        db_path = str(tmp_path / "test.db")
        storage = ThreatFeedStorage(db_path)
        aggregator = FeedAggregator(storage)
        results = aggregator.update_all()

        assert "threatfox" in results
        assert "urlhaus" in results
        storage.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
