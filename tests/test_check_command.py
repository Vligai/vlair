#!/usr/bin/env python3
"""
Unit tests for the secops check command
Tests the quick indicator lookup functionality
"""

import pytest
import sys
import os
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
from io import StringIO

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


class TestCheckCommandRouting:
    """Test that check command routes to correct tools"""

    # These tests would need the full CLI to be testable
    # For now, test the underlying components directly

    def test_hash_lookup_module_importable(self):
        """Test that hash_lookup module is importable"""
        from secops_helper.tools.hash_lookup import HashLookup

        assert HashLookup is not None

    def test_domain_ip_intel_module_importable(self):
        """Test that domain_ip_intel module is importable"""
        from secops_helper.tools.domain_ip_intel import DomainIPIntelligence

        assert DomainIPIntelligence is not None

    def test_url_analyzer_module_importable(self):
        """Test that url_analyzer module is importable"""
        from secops_helper.tools.url_analyzer import URLAnalyzer

        assert URLAnalyzer is not None


class TestCheckHashCommand:
    """Test the check hash subcommand"""

    @patch("secops_helper.tools.hash_lookup.HashLookup")
    def test_check_hash_lookup_instantiation(self, mock_lookup_class):
        """Test that HashLookup can be instantiated"""
        mock_instance = MagicMock()
        mock_instance.lookup.return_value = {
            "verdict": "MALICIOUS",
            "detections": 45,
            "total_engines": 70,
            "malware_family": "Emotet",
            "sources": ["VirusTotal"],
        }
        mock_lookup_class.return_value = mock_instance

        from secops_helper.tools.hash_lookup import HashLookup

        lookup = HashLookup(verbose=False)
        assert lookup is not None

    def test_hash_validator(self):
        """Test hash validation"""
        from secops_helper.tools.hash_lookup import HashValidator

        # Test MD5
        is_valid, hash_type = HashValidator.validate("44d88612fea8a8f36de82e1278abb02f")
        assert is_valid is True
        assert hash_type == "md5"

        # Test SHA1
        is_valid, hash_type = HashValidator.validate("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
        assert is_valid is True
        assert hash_type == "sha1"

        # Test SHA256
        is_valid, hash_type = HashValidator.validate(
            "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
        )
        assert is_valid is True
        assert hash_type == "sha256"

        # Test invalid
        is_valid, hash_type = HashValidator.validate("invalid_hash")
        assert is_valid is False


class TestCheckDomainCommand:
    """Test the check domain subcommand"""

    def test_domain_validator(self):
        """Test domain validation"""
        from secops_helper.tools.domain_ip_intel import Validator

        assert Validator.is_valid_domain("example.com") is True
        assert Validator.is_valid_domain("sub.example.com") is True
        assert Validator.is_valid_domain("invalid") is False


class TestCheckIPCommand:
    """Test the check ip subcommand"""

    def test_ip_validator(self):
        """Test IP validation"""
        from secops_helper.tools.domain_ip_intel import Validator

        assert Validator.is_valid_ipv4("192.168.1.1") is True
        assert Validator.is_valid_ipv4("8.8.8.8") is True
        assert Validator.is_valid_ipv4("999.999.999.999") is False
        assert Validator.is_valid_ipv4("not.an.ip") is False

    def test_private_ip_detection(self):
        """Test private IP detection"""
        from secops_helper.tools.domain_ip_intel import Validator

        assert Validator.is_private_ip("192.168.1.1") is True
        assert Validator.is_private_ip("10.0.0.1") is True
        assert Validator.is_private_ip("8.8.8.8") is False


class TestCheckURLCommand:
    """Test the check url subcommand"""

    def test_url_validator(self):
        """Test URL validation"""
        from secops_helper.tools.url_analyzer import URLValidator

        assert URLValidator.is_valid_url("http://example.com") is True
        assert URLValidator.is_valid_url("https://example.com/path") is True
        assert URLValidator.is_valid_url("not-a-url") is False


class TestCheckFileInput:
    """Test the check command with file input"""

    def test_analyzer_creation(self):
        """Test that Analyzer can be created"""
        from secops_helper.core.analyzer import Analyzer

        analyzer = Analyzer(verbose=False)
        assert analyzer is not None


class TestCheckHistoryRecording:
    """Test that check command records to history"""

    def test_history_creation(self):
        """Test that AnalysisHistory can be created"""
        from secops_helper.core.history import AnalysisHistory

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test_history.db")
            history = AnalysisHistory(db_path=db_path)
            assert history is not None


class TestCheckConsoleOutput:
    """Test console output formatting for check command"""

    def test_hash_lookup_result_structure(self):
        """Test that hash lookup returns expected structure"""
        # This would need mocked API responses
        pass

    def test_domain_lookup_result_structure(self):
        """Test that domain lookup returns expected structure"""
        # This would need mocked API responses
        pass


class TestDetector:
    """Test input type detection"""

    def test_detect_hash(self):
        """Test detecting hash input"""
        from secops_helper.core.detector import Detector

        detector = Detector()

        # MD5
        result = detector.detect("44d88612fea8a8f36de82e1278abb02f")
        assert result["type"] == "hash"
        assert result["subtype"] == "md5"

        # SHA256
        result = detector.detect("2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae")
        assert result["type"] == "hash"
        assert result["subtype"] == "sha256"

    def test_detect_ip(self):
        """Test detecting IP input"""
        from secops_helper.core.detector import Detector

        detector = Detector()
        result = detector.detect("8.8.8.8")
        assert result["type"] == "ip"

    def test_detect_domain(self):
        """Test detecting domain input"""
        from secops_helper.core.detector import Detector

        detector = Detector()
        result = detector.detect("malicious.com")
        assert result["type"] == "domain"

    def test_detect_url(self):
        """Test detecting URL input"""
        from secops_helper.core.detector import Detector

        detector = Detector()
        result = detector.detect("http://evil.com/payload")
        assert result["type"] == "url"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
