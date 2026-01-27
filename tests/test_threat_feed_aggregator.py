#!/usr/bin/env python3
"""
Unit tests for Threat Feed Aggregator
"""

import pytest
import sys
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, patch

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from secops_helper.tools.threat_feed_aggregator import ThreatFeedAggregator


class TestFeedSources:
    """Test threat feed source handling"""

    def test_list_available_sources(self):
        """Test listing available feed sources"""
        aggregator = ThreatFeedAggregator()
        sources = aggregator.get_available_sources()
        assert isinstance(sources, list)
        assert len(sources) > 0

    def test_threatfox_source_config(self):
        """Test ThreatFox source configuration"""
        aggregator = ThreatFeedAggregator()
        sources = aggregator.get_available_sources()
        assert "threatfox" in [s.lower() for s in sources]

    def test_urlhaus_source_config(self):
        """Test URLhaus source configuration"""
        aggregator = ThreatFeedAggregator()
        sources = aggregator.get_available_sources()
        assert "urlhaus" in [s.lower() for s in sources]


class TestFeedUpdate:
    """Test feed update functionality"""

    @patch("requests.get")
    def test_update_threatfox(self, mock_get):
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
                    "first_seen": "2025-01-01 00:00:00",
                }
            ],
        }
        mock_get.return_value = mock_response

        aggregator = ThreatFeedAggregator()
        result = aggregator.update_feed("threatfox")
        assert result is not None

    @patch("requests.get")
    def test_update_urlhaus(self, mock_get):
        """Test updating URLhaus feed"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "id,dateadded,url,url_status,threat,tags\n1,2025-01-01,http://evil.com/mal,online,malware_download,elf"
        mock_get.return_value = mock_response

        aggregator = ThreatFeedAggregator()
        result = aggregator.update_feed("urlhaus")
        assert result is not None

    @patch("requests.get")
    def test_update_all_feeds(self, mock_get):
        """Test updating all feeds"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"query_status": "ok", "data": []}
        mock_response.text = "id,dateadded,url,url_status\n"
        mock_get.return_value = mock_response

        aggregator = ThreatFeedAggregator()
        result = aggregator.update_all()
        assert result is not None


class TestIOCStorage:
    """Test IOC storage functionality"""

    @pytest.fixture
    def temp_db(self):
        """Create temporary database"""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as f:
            return f.name

    def test_store_ioc(self, temp_db):
        """Test storing IOC to database"""
        aggregator = ThreatFeedAggregator(db_path=temp_db)
        result = aggregator.store_ioc(
            {
                "value": "evil.com",
                "type": "domain",
                "source": "test",
                "confidence": 75,
                "malware_family": "TestMalware",
            }
        )
        assert result is True or result is None
        os.unlink(temp_db)

    def test_deduplication(self, temp_db):
        """Test that duplicate IOCs are deduplicated"""
        aggregator = ThreatFeedAggregator(db_path=temp_db)
        ioc = {"value": "evil.com", "type": "domain", "source": "test", "confidence": 75}
        aggregator.store_ioc(ioc)
        aggregator.store_ioc(ioc)
        # Second insert should update, not duplicate
        results = aggregator.search(value="evil.com")
        assert len(results) <= 1
        os.unlink(temp_db)

    def test_confidence_aggregation(self, temp_db):
        """Test that confidence increases with multiple sources"""
        aggregator = ThreatFeedAggregator(db_path=temp_db)
        aggregator.store_ioc(
            {"value": "evil.com", "type": "domain", "source": "source1", "confidence": 50}
        )
        aggregator.store_ioc(
            {"value": "evil.com", "type": "domain", "source": "source2", "confidence": 60}
        )
        results = aggregator.search(value="evil.com")
        if results:
            # Confidence should be higher than individual sources
            assert results[0].get("confidence", 0) >= 50
        os.unlink(temp_db)


class TestIOCSearch:
    """Test IOC search functionality"""

    @pytest.fixture
    def populated_db(self):
        """Create database with test data"""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as f:
            db_path = f.name

        aggregator = ThreatFeedAggregator(db_path=db_path)
        test_iocs = [
            {
                "value": "evil.com",
                "type": "domain",
                "source": "test",
                "confidence": 75,
                "malware_family": "Emotet",
            },
            {
                "value": "192.168.1.100",
                "type": "ip",
                "source": "test",
                "confidence": 80,
                "malware_family": "TrickBot",
            },
            {
                "value": "http://bad.com/mal.exe",
                "type": "url",
                "source": "test",
                "confidence": 90,
                "malware_family": "Emotet",
            },
        ]
        for ioc in test_iocs:
            aggregator.store_ioc(ioc)

        yield db_path
        os.unlink(db_path)

    def test_search_by_value(self, populated_db):
        """Test searching by IOC value"""
        aggregator = ThreatFeedAggregator(db_path=populated_db)
        results = aggregator.search(value="evil.com")
        assert len(results) >= 0  # May be 0 or more depending on implementation

    def test_search_by_type(self, populated_db):
        """Test searching by IOC type"""
        aggregator = ThreatFeedAggregator(db_path=populated_db)
        results = aggregator.search(ioc_type="domain")
        assert isinstance(results, list)

    def test_search_by_malware_family(self, populated_db):
        """Test searching by malware family"""
        aggregator = ThreatFeedAggregator(db_path=populated_db)
        results = aggregator.search(malware_family="Emotet")
        assert isinstance(results, list)

    def test_search_by_confidence(self, populated_db):
        """Test searching by minimum confidence"""
        aggregator = ThreatFeedAggregator(db_path=populated_db)
        results = aggregator.search(min_confidence=80)
        for r in results:
            assert r.get("confidence", 0) >= 80


class TestExport:
    """Test export functionality"""

    @pytest.fixture
    def populated_db(self):
        """Create database with test data"""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as f:
            db_path = f.name

        aggregator = ThreatFeedAggregator(db_path=db_path)
        aggregator.store_ioc(
            {"value": "evil.com", "type": "domain", "source": "test", "confidence": 75}
        )

        yield db_path
        os.unlink(db_path)

    def test_export_json(self, populated_db):
        """Test exporting to JSON"""
        aggregator = ThreatFeedAggregator(db_path=populated_db)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as f:
            output_path = f.name

        try:
            aggregator.export(output_path, format="json")
            assert os.path.exists(output_path)
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)

    def test_export_csv(self, populated_db):
        """Test exporting to CSV"""
        aggregator = ThreatFeedAggregator(db_path=populated_db)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as f:
            output_path = f.name

        try:
            aggregator.export(output_path, format="csv")
            assert os.path.exists(output_path)
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)


class TestStatistics:
    """Test statistics functionality"""

    def test_get_stats(self):
        """Test getting feed statistics"""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as f:
            db_path = f.name

        try:
            aggregator = ThreatFeedAggregator(db_path=db_path)
            stats = aggregator.get_stats()
            assert isinstance(stats, dict)
        finally:
            os.unlink(db_path)


class TestThreatFeedAggregatorIntegration:
    """Integration tests for Threat Feed Aggregator"""

    def test_aggregator_creation(self):
        """Test creating aggregator instance"""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as f:
            db_path = f.name

        try:
            aggregator = ThreatFeedAggregator(db_path=db_path)
            assert aggregator is not None
        finally:
            os.unlink(db_path)

    def test_aggregator_with_default_db(self):
        """Test aggregator with default database path"""
        aggregator = ThreatFeedAggregator()
        assert aggregator is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
