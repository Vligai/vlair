#!/usr/bin/env python3
"""
Unit tests for EML Parser
"""

import pytest
import sys
import json
from pathlib import Path
from unittest.mock import Mock, patch, mock_open
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from emlAnalysis.emlParser import (
    parse_eml,
    extract_basic_headers,
    extract_ips_and_servers,
    extract_auth_results,
    extract_attachments,
    extract_body,
    vt_lookup_sha256,
    build_summary,
    json_serial,
)


class TestHelperFunctions:
    """Test helper functions"""

    def test_json_serial_datetime(self):
        """Test datetime serialization"""
        dt = datetime(2025, 11, 18, 10, 0, 0)
        result = json_serial(dt)
        assert isinstance(result, str)
        assert "2025-11-18" in result

    def test_json_serial_unsupported(self):
        """Test unsupported type serialization"""
        with pytest.raises(TypeError):
            json_serial(set([1, 2, 3]))


class TestParseEml:
    """Test EML file parsing"""

    def test_parse_eml_basic(self):
        """Test basic EML parsing"""
        test_file = Path(__file__).parent / "test_data" / "email_samples" / "phishing_sample.eml"

        # Skip if file doesn't exist
        if not test_file.exists():
            pytest.skip("Test EML file not found")

        result = parse_eml(str(test_file))

        # Should return a parsed email dictionary
        assert isinstance(result, dict)
        assert "header" in result

    def test_parse_eml_nonexistent(self):
        """Test parsing nonexistent file"""
        with pytest.raises(FileNotFoundError):
            parse_eml("/nonexistent/file.eml")


class TestExtractBasicHeaders:
    """Test header extraction"""

    def test_extract_basic_headers_complete(self):
        """Test extraction with complete headers"""
        parsed = {
            "header": {
                "from": "attacker@malicious.com",
                "to": ["victim@company.com"],
                "subject": "Urgent: Verify Your Account",
                "date": "2025-11-18T10:00:00Z",
                "header": {
                    "reply-to": ["phishing@badactor.net"],
                    "return-path": ["<bounce@malicious.com>"],
                    "x-mailer": ["EvilMailer 1.0"],
                    "x-priority": ["1"],
                    "x-originating-ip": ["[203.0.113.100]"],
                    "message-id": ["<abc123@malicious.com>"],
                },
            }
        }

        result = extract_basic_headers(parsed)

        assert result["From"] == "attacker@malicious.com"
        assert "victim@company.com" in result["To"]
        assert result["Subject"] == "Urgent: Verify Your Account"
        assert result["X-Mailer"] == ["EvilMailer 1.0"]
        assert result["X-Priority"] == ["1"]

    def test_extract_basic_headers_missing(self):
        """Test extraction with missing headers"""
        parsed = {"header": {}}

        result = extract_basic_headers(parsed)

        assert result["From"] == "N/A"
        assert result["To"] == ["N/A"]
        assert result["Subject"] == "N/A"


class TestExtractIpsAndServers:
    """Test IP and server extraction"""

    def test_extract_ips_with_received_headers(self):
        """Test IP extraction from received headers"""
        parsed = {
            "header": {
                "received": [{"src": "from mail.attacker.com [203.0.113.100]"}, {"src": "from relay.isp.com [198.51.100.1]"}],
                "received_ip": ["203.0.113.100", "198.51.100.1", "192.0.2.1"],
                "header": {"x-originating-ip": ["[203.0.113.100]"], "x-sender-ip": [""]},
            }
        }

        result = extract_ips_and_servers(parsed)

        assert result["source_ip"] == "203.0.113.100"
        assert "203.0.113.100" in result["all_ips"]
        assert len(result["all_ips"]) == 3

    def test_extract_ips_minimal(self):
        """Test IP extraction with minimal data"""
        parsed = {"header": {"received": [], "received_ip": [], "header": {"x-originating-ip": [""], "x-sender-ip": [""]}}}

        result = extract_ips_and_servers(parsed)

        assert result["source_ip"] == "Unknown"
        assert result["last_relay_ip"] == "Unknown"
        assert result["last_relay_server"] == "Unknown"


class TestExtractAuthResults:
    """Test authentication results extraction"""

    def test_extract_auth_results_present(self):
        """Test extraction of SPF/DKIM/DMARC results"""
        parsed = {
            "header": {
                "header": {
                    "received-spf": ["fail (domain does not designate sender)"],
                    "authentication-results": ["dkim=fail; spf=fail; dmarc=fail"],
                }
            }
        }

        result = extract_auth_results(parsed)

        assert "fail" in result["SPF"].lower()
        assert "fail" in result["DKIM"].lower()
        assert "fail" in result["DMARC"].lower()

    def test_extract_auth_results_missing(self):
        """Test extraction with missing auth results"""
        parsed = {"header": {"header": {}}}

        result = extract_auth_results(parsed)

        assert result["SPF"] == "N/A"
        assert result["DKIM"] == "N/A"
        assert result["DMARC"] == "N/A"


class TestExtractAttachments:
    """Test attachment extraction"""

    def test_extract_attachments_with_hashes(self):
        """Test attachment extraction with file hashes"""
        parsed = {
            "attachment": [
                {
                    "filename": "invoice.pdf",
                    "size": 12345,
                    "extension": "pdf",
                    "content_header": {"content-type": ["application/pdf"]},
                    "hash": {
                        "md5": "5d41402abc4b2a76b9719d911017c592",
                        "sha1": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
                        "sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
                        "sha512": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    },
                }
            ]
        }

        result = extract_attachments(parsed, vt_enabled=False)

        assert len(result) == 1
        assert result[0]["filename"] == "invoice.pdf"
        assert result[0]["size"] == 12345
        assert result[0]["extension"] == "pdf"
        assert result[0]["hashes"]["md5"] == "5d41402abc4b2a76b9719d911017c592"
        assert result[0]["hashes"]["sha256"] == "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"

    def test_extract_attachments_no_attachments(self):
        """Test extraction with no attachments"""
        parsed = {"attachment": []}

        result = extract_attachments(parsed)

        assert result == []

    @patch("emlAnalysis.emlParser.vt_lookup_sha256")
    def test_extract_attachments_with_vt(self, mock_vt):
        """Test attachment extraction with VT lookup"""
        mock_vt.return_value = {"VT_Malicious": 5, "VT_Suspicious": 2, "VT_Link": "https://www.virustotal.com/gui/file/abc123"}

        parsed = {
            "attachment": [
                {
                    "filename": "malware.exe",
                    "size": 54321,
                    "extension": "exe",
                    "content_header": {"content-type": ["application/x-msdownload"]},
                    "hash": {
                        "md5": "5d41402abc4b2a76b9719d911017c592",
                        "sha1": "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
                        "sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
                        "sha512": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    },
                }
            ]
        }

        result = extract_attachments(parsed, vt_enabled=True)

        assert len(result) == 1
        assert result[0]["VirusTotal"]["VT_Malicious"] == 5
        mock_vt.assert_called_once()


class TestExtractBody:
    """Test body content extraction"""

    def test_extract_body_text(self):
        """Test body text extraction"""
        parsed = {
            "body": [
                {
                    "content_type": "text/plain",
                    "hash": "abc123",
                    "uri_hash": ["uri_hash_1"],
                    "email_hash": ["email_hash_1"],
                    "domain_hash": ["domain_hash_1"],
                    "content": "This is the email body content with a URL: http://example.com",
                }
            ]
        }

        result = extract_body(parsed)

        assert len(result) == 1
        assert result[0]["content_type"] == "text/plain"
        assert "email body content" in result[0]["body_text"]
        assert len(result[0]["uri_hashes"]) > 0

    def test_extract_body_html(self):
        """Test HTML body extraction"""
        parsed = {
            "body": [
                {
                    "content_type": "text/html",
                    "hash": "def456",
                    "uri_hash": [],
                    "email_hash": [],
                    "domain_hash": [],
                    "content": "<html><body>HTML email content</body></html>",
                }
            ]
        }

        result = extract_body(parsed)

        assert len(result) == 1
        assert result[0]["content_type"] == "text/html"
        assert "HTML email content" in result[0]["body_text"]

    def test_extract_body_bytes(self):
        """Test body extraction with bytes content"""
        parsed = {
            "body": [
                {
                    "content_type": "text/plain",
                    "hash": "ghi789",
                    "uri_hash": [],
                    "email_hash": [],
                    "domain_hash": [],
                    "content": b"Byte content",
                }
            ]
        }

        result = extract_body(parsed)

        assert len(result) == 1
        assert "Byte content" in result[0]["body_text"]

    def test_extract_body_empty(self):
        """Test extraction with no body"""
        parsed = {"body": []}

        result = extract_body(parsed)

        assert result == []


class TestVirusTotalLookup:
    """Test VirusTotal API integration"""

    @patch("requests.get")
    def test_vt_lookup_success(self, mock_get):
        """Test successful VT lookup"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {"attributes": {"last_analysis_stats": {"malicious": 10, "suspicious": 2, "undetected": 60}}}
        }
        mock_get.return_value = mock_response

        # Mock environment variable
        with patch("emlAnalysis.emlParser.VT_API_KEY", "test_key"):
            result = vt_lookup_sha256("abc123def456")

        assert result["VT_Malicious"] == 10
        assert result["VT_Suspicious"] == 2
        assert "VT_Link" in result

    @patch("requests.get")
    def test_vt_lookup_not_found(self, mock_get):
        """Test VT lookup for file not found"""
        mock_response = Mock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        with patch("emlAnalysis.emlParser.VT_API_KEY", "test_key"):
            result = vt_lookup_sha256("nonexistent_hash")

        assert "VT_Error" in result
        assert "404" in result["VT_Error"]

    @patch("requests.get")
    def test_vt_lookup_network_error(self, mock_get):
        """Test VT lookup with network error"""
        mock_get.side_effect = Exception("Network error")

        with patch("emlAnalysis.emlParser.VT_API_KEY", "test_key"):
            result = vt_lookup_sha256("abc123")

        assert "VT_Error" in result
        assert "Network error" in result["VT_Error"]

    def test_vt_lookup_no_api_key(self):
        """Test VT lookup without API key"""
        with patch("emlAnalysis.emlParser.VT_API_KEY", None):
            result = vt_lookup_sha256("abc123")

        assert result == {}

    def test_vt_lookup_invalid_hash(self):
        """Test VT lookup with invalid hash"""
        with patch("emlAnalysis.emlParser.VT_API_KEY", "test_key"):
            result = vt_lookup_sha256("N/A")

        assert result == {}


class TestBuildSummary:
    """Test complete summary building"""

    def test_build_summary_complete(self):
        """Test building complete summary"""
        parsed = {
            "header": {
                "from": "attacker@malicious.com",
                "to": ["victim@company.com"],
                "subject": "Phishing Email",
                "date": "2025-11-18T10:00:00Z",
                "received": [],
                "received_ip": ["203.0.113.100"],
                "header": {
                    "reply-to": ["phishing@badactor.net"],
                    "return-path": ["<bounce@malicious.com>"],
                    "x-mailer": ["EvilMailer 1.0"],
                    "x-priority": ["1"],
                    "x-originating-ip": ["[203.0.113.100]"],
                    "message-id": ["<abc123@malicious.com>"],
                    "received-spf": ["fail"],
                    "authentication-results": ["dkim=fail; spf=fail"],
                },
            },
            "attachment": [],
            "body": [
                {
                    "content_type": "text/plain",
                    "hash": "abc123",
                    "uri_hash": [],
                    "email_hash": [],
                    "domain_hash": [],
                    "content": "Email body",
                }
            ],
        }

        result = build_summary(parsed, "test.eml", vt_enabled=False)

        assert result["File"] == "test.eml"
        assert result["Headers"]["From"] == "attacker@malicious.com"
        assert result["Source IP (likely attacker)"] == "203.0.113.100"
        assert "SPF/DKIM/DMARC Results" in result
        assert "Attachments" in result
        assert "Body Content" in result

    def test_build_summary_minimal(self):
        """Test building summary with minimal data"""
        parsed = {"header": {}, "attachment": [], "body": []}

        result = build_summary(parsed, "test.eml")

        assert result["File"] == "test.eml"
        assert "Headers" in result
        assert "Attachments" in result
        assert result["Attachments"] == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
