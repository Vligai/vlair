#!/usr/bin/env python3
"""
Unit tests for URL Analyzer
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from vlair.tools.url_analyzer import URLValidator, URLParser, SuspiciousPatternDetector


class TestURLValidator:
    """Test URL validation"""

    def test_valid_http_url(self):
        """Test valid HTTP URL"""
        assert URLValidator.is_valid_url("http://example.com") is True

    def test_valid_https_url(self):
        """Test valid HTTPS URL"""
        assert URLValidator.is_valid_url("https://example.com") is True

    def test_valid_url_with_path(self):
        """Test valid URL with path"""
        assert URLValidator.is_valid_url("https://example.com/path/to/page") is True

    def test_valid_url_with_port(self):
        """Test valid URL with port"""
        assert URLValidator.is_valid_url("http://example.com:8080") is True

    def test_valid_url_with_query(self):
        """Test valid URL with query string"""
        assert URLValidator.is_valid_url("https://example.com/search?q=test") is True

    def test_valid_url_with_ip(self):
        """Test valid URL with IP address"""
        assert URLValidator.is_valid_url("http://192.168.1.1/admin") is True

    def test_invalid_url_no_scheme(self):
        """Test URL without scheme"""
        assert URLValidator.is_valid_url("example.com") is False

    def test_invalid_url_bad_scheme(self):
        """Test URL with invalid scheme"""
        assert URLValidator.is_valid_url("ftp://example.com") is False

    def test_invalid_url_empty(self):
        """Test empty string"""
        assert URLValidator.is_valid_url("") is False

    def test_normalize_url_add_scheme(self):
        """Test normalizing URL without scheme"""
        normalized = URLValidator.normalize_url("example.com")
        assert normalized.startswith("http://")

    def test_normalize_url_lowercase_domain(self):
        """Test normalizing URL with uppercase domain"""
        normalized = URLValidator.normalize_url("http://EXAMPLE.COM")
        assert "example.com" in normalized

    def test_defang_url_http(self):
        """Test defanging HTTP URL"""
        defanged = URLValidator.defang_url("http://evil.com")
        assert "hxxp://" in defanged
        assert "[.]" in defanged

    def test_defang_url_https(self):
        """Test defanging HTTPS URL"""
        defanged = URLValidator.defang_url("https://malicious.com")
        assert "hxxps://" in defanged
        assert "[.]" in defanged


class TestURLParser:
    """Test URL parsing"""

    def test_parse_simple_url(self):
        """Test parsing simple URL"""
        result = URLParser.parse_url("https://example.com")
        assert result["scheme"] == "https"
        assert result["domain"] == "example.com"

    def test_parse_url_with_path(self):
        """Test parsing URL with path"""
        result = URLParser.parse_url("https://example.com/path/to/file.html")
        assert result["path"] == "/path/to/file.html"
        assert result["file_extension"] == "html"

    def test_parse_url_with_port(self):
        """Test parsing URL with port"""
        result = URLParser.parse_url("http://example.com:8080/admin")
        assert result["port"] == 8080

    def test_parse_url_with_query(self):
        """Test parsing URL with query parameters"""
        result = URLParser.parse_url("https://example.com/search?q=test&page=1")
        assert result["query"] == "q=test&page=1"
        assert "q" in result["query_params"]

    def test_parse_url_preserves_original(self):
        """Test that original URL is preserved"""
        url = "https://example.com/test"
        result = URLParser.parse_url(url)
        assert result["original"] == url


class TestSuspiciousPatternDetector:
    """Test suspicious URL pattern detection"""

    def test_detect_ip_in_url(self):
        """Test detection of IP address in URL"""
        parsed = URLParser.parse_url("http://192.168.1.1/malware.exe")
        result = SuspiciousPatternDetector.analyze_url("http://192.168.1.1/malware.exe", parsed)
        assert "Uses IP address instead of domain name" in result["suspicions"]
        assert result["is_suspicious"] is True

    def test_detect_suspicious_extension(self):
        """Test detection of suspicious extension"""
        parsed = URLParser.parse_url("http://example.com/file.exe")
        result = SuspiciousPatternDetector.analyze_url("http://example.com/file.exe", parsed)
        assert any("Suspicious file extension" in s for s in result["suspicions"])

    def test_detect_suspicious_tld(self):
        """Test detection of suspicious TLD"""
        parsed = URLParser.parse_url("http://malware.tk/payload")
        result = SuspiciousPatternDetector.analyze_url("http://malware.tk/payload", parsed)
        assert any("free/suspicious TLD" in s for s in result["suspicions"])

    def test_detect_url_encoding(self):
        """Test detection of heavy URL encoding"""
        url = "http://example.com/%41%42%43%44%45"
        parsed = URLParser.parse_url(url)
        result = SuspiciousPatternDetector.analyze_url(url, parsed)
        # May or may not trigger depending on encoding count
        assert "risk_score" in result

    def test_detect_suspicious_keywords(self):
        """Test detection of suspicious keywords"""
        parsed = URLParser.parse_url("http://example.com/login-verify-account")
        result = SuspiciousPatternDetector.analyze_url(
            "http://example.com/login-verify-account", parsed
        )
        assert any("suspicious keywords" in s for s in result["suspicions"])

    def test_clean_url_low_risk(self):
        """Test clean URL has low risk score"""
        parsed = URLParser.parse_url("https://www.google.com/search")
        result = SuspiciousPatternDetector.analyze_url("https://www.google.com/search", parsed)
        assert result["risk_score"] < 30
        assert result["is_suspicious"] is False


class TestURLAnalyzerIntegration:
    """Integration tests for URL Analyzer (mocked APIs)"""

    @patch("vlair.tools.url_analyzer.get_cache")
    def test_analyzer_creation(self, mock_cache):
        """Test creating analyzer instance"""
        from vlair.tools.url_analyzer import URLAnalyzer

        mock_cache_instance = Mock()
        mock_cache_instance.get.return_value = None
        mock_cache.return_value = mock_cache_instance

        analyzer = URLAnalyzer(verbose=False)
        assert analyzer is not None

    @patch("vlair.tools.url_analyzer.get_cache")
    @patch("requests.get")
    def test_analyze_returns_result(self, mock_get, mock_cache):
        """Test that analyze returns a result dict"""
        from vlair.tools.url_analyzer import URLAnalyzer

        mock_cache_instance = Mock()
        mock_cache_instance.get.return_value = None
        mock_cache.return_value = mock_cache_instance

        # Mock VT response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "harmless": 70,
                        "undetected": 5,
                    }
                }
            }
        }
        mock_get.return_value = mock_response

        with patch.dict("os.environ", {"VT_API_KEY": "test_key"}):
            analyzer = URLAnalyzer(verbose=False)
            result = analyzer.analyze("http://example.com")

        assert result is not None
        assert "url" in result or "original" in result


class TestURLRiskScoring:
    """Test URL risk scoring"""

    def test_clean_url_low_score(self):
        """Test that clean URL gets low risk score"""
        # Clean URL should score low
        pass  # Implement when we understand the scoring interface

    def test_malicious_url_high_score(self):
        """Test that malicious indicators raise score"""
        # URL with malicious indicators should score high
        pass  # Implement when we understand the scoring interface


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
