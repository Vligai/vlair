#!/usr/bin/env python3
"""
Unit tests for Input Type Detector
Tests auto-detection of hashes, IPs, domains, URLs, and file types
"""

import pytest
import sys
import os
import tempfile
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from secops_helper.core.detector import InputDetector, InputType


class TestHashDetection:
    """Test hash format detection"""

    def setup_method(self):
        self.detector = InputDetector()

    def test_detect_md5(self):
        """Test MD5 hash detection"""
        result = self.detector.detect("44d88612fea8a8f36de82e1278abb02f")
        assert result["type"] == InputType.HASH_MD5
        assert result["confidence"] == "high"
        assert result["metadata"]["length"] == 32

    def test_detect_md5_uppercase(self):
        """Test MD5 hash detection with uppercase"""
        result = self.detector.detect("44D88612FEA8A8F36DE82E1278ABB02F")
        assert result["type"] == InputType.HASH_MD5

    def test_detect_sha1(self):
        """Test SHA1 hash detection"""
        result = self.detector.detect("3395856ce81f2b7382dee72602f798b642f14140")
        assert result["type"] == InputType.HASH_SHA1
        assert result["confidence"] == "high"
        assert result["metadata"]["length"] == 40

    def test_detect_sha256(self):
        """Test SHA256 hash detection"""
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result = self.detector.detect(sha256)
        assert result["type"] == InputType.HASH_SHA256
        assert result["confidence"] == "high"
        assert result["metadata"]["length"] == 64

    def test_invalid_hash_wrong_length(self):
        """Test that wrong-length hex strings aren't detected as hashes"""
        result = self.detector.detect("44d88612fea8a8f36de82e1278")  # 26 chars
        assert result["type"] == InputType.UNKNOWN

    def test_invalid_hash_non_hex(self):
        """Test that non-hex strings aren't detected as hashes"""
        result = self.detector.detect("44d88612fea8a8f36de82e1278abb02g")  # 'g' is not hex
        assert result["type"] == InputType.UNKNOWN


class TestIPDetection:
    """Test IP address detection"""

    def setup_method(self):
        self.detector = InputDetector()

    def test_detect_ipv4_basic(self):
        """Test basic IPv4 detection"""
        result = self.detector.detect("192.168.1.1")
        assert result["type"] == InputType.IP
        assert result["confidence"] == "high"
        assert result["metadata"]["version"] == 4

    def test_detect_ipv4_public(self):
        """Test public IPv4 detection"""
        result = self.detector.detect("8.8.8.8")
        assert result["type"] == InputType.IP

    def test_detect_ipv4_edge_values(self):
        """Test IPv4 with edge values (0 and 255)"""
        result = self.detector.detect("0.0.0.0")
        assert result["type"] == InputType.IP

        result = self.detector.detect("255.255.255.255")
        assert result["type"] == InputType.IP

    def test_invalid_ipv4_out_of_range(self):
        """Test that out-of-range octets aren't detected"""
        result = self.detector.detect("192.168.1.256")
        assert result["type"] != InputType.IP

    def test_invalid_ipv4_too_few_octets(self):
        """Test that incomplete IPs aren't detected"""
        result = self.detector.detect("192.168.1")
        assert result["type"] != InputType.IP


class TestDomainDetection:
    """Test domain detection"""

    def setup_method(self):
        self.detector = InputDetector()

    def test_detect_simple_domain(self):
        """Test simple domain detection"""
        result = self.detector.detect("example.com")
        assert result["type"] == InputType.DOMAIN
        assert result["confidence"] == "medium"

    def test_detect_subdomain(self):
        """Test subdomain detection"""
        result = self.detector.detect("mail.example.com")
        assert result["type"] == InputType.DOMAIN

    def test_detect_multi_level_subdomain(self):
        """Test multi-level subdomain detection"""
        result = self.detector.detect("api.v2.example.com")
        assert result["type"] == InputType.DOMAIN

    def test_detect_various_tlds(self):
        """Test various TLDs"""
        domains = ["example.net", "example.org", "example.co.uk", "example.io"]
        for domain in domains:
            result = self.detector.detect(domain)
            assert result["type"] == InputType.DOMAIN, f"Failed for {domain}"

    def test_invalid_domain_no_tld(self):
        """Test that domains without valid TLD aren't detected"""
        result = self.detector.detect("example")
        assert result["type"] != InputType.DOMAIN

    def test_invalid_domain_numeric(self):
        """Test that fully numeric strings aren't detected as domains"""
        result = self.detector.detect("12345.67890")
        # Should not be detected as domain (all numeric)
        assert result["type"] != InputType.DOMAIN


class TestURLDetection:
    """Test URL detection"""

    def setup_method(self):
        self.detector = InputDetector()

    def test_detect_http_url(self):
        """Test HTTP URL detection"""
        result = self.detector.detect("http://example.com")
        assert result["type"] == InputType.URL
        assert result["confidence"] == "high"
        assert result["metadata"]["scheme"] == "http"

    def test_detect_https_url(self):
        """Test HTTPS URL detection"""
        result = self.detector.detect("https://example.com")
        assert result["type"] == InputType.URL
        assert result["metadata"]["scheme"] == "https"

    def test_detect_url_with_path(self):
        """Test URL with path detection"""
        result = self.detector.detect("https://example.com/path/to/resource")
        assert result["type"] == InputType.URL

    def test_detect_url_with_query(self):
        """Test URL with query string detection"""
        result = self.detector.detect("https://example.com/search?q=test")
        assert result["type"] == InputType.URL

    def test_detect_url_with_port(self):
        """Test URL with port detection"""
        result = self.detector.detect("http://example.com:8080/api")
        assert result["type"] == InputType.URL

    def test_url_detected_before_domain(self):
        """Test that URLs are detected before domains"""
        # URL should take precedence over domain
        result = self.detector.detect("https://example.com")
        assert result["type"] == InputType.URL


class TestFileTypeDetection:
    """Test file type detection"""

    def setup_method(self):
        self.detector = InputDetector()

    def test_detect_eml_file(self):
        """Test .eml file detection"""
        with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as f:
            f.write(b"From: test@example.com\nTo: recipient@example.com\n")
            temp_path = f.name

        try:
            result = self.detector.detect(temp_path)
            assert result["type"] == InputType.EMAIL
            assert result["confidence"] == "high"
        finally:
            os.unlink(temp_path)

    def test_detect_pcap_file(self):
        """Test .pcap file detection"""
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            f.write(b"\xd4\xc3\xb2\xa1")  # PCAP magic bytes
            temp_path = f.name

        try:
            result = self.detector.detect(temp_path)
            assert result["type"] == InputType.PCAP
            assert result["confidence"] == "high"
        finally:
            os.unlink(temp_path)

    def test_detect_log_file(self):
        """Test .log file detection"""
        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as f:
            f.write(b'192.168.1.1 - - [01/Jan/2025:00:00:00] "GET / HTTP/1.1"')
            temp_path = f.name

        try:
            result = self.detector.detect(temp_path)
            assert result["type"] == InputType.LOG
        finally:
            os.unlink(temp_path)

    def test_detect_javascript_file(self):
        """Test .js file detection"""
        with tempfile.NamedTemporaryFile(suffix=".js", delete=False) as f:
            f.write(b"var x = 1;")
            temp_path = f.name

        try:
            result = self.detector.detect(temp_path)
            assert result["type"] == InputType.SCRIPT
            assert result["metadata"]["language"] == "javascript"
        finally:
            os.unlink(temp_path)

    def test_detect_powershell_file(self):
        """Test .ps1 file detection"""
        with tempfile.NamedTemporaryFile(suffix=".ps1", delete=False) as f:
            f.write(b'Write-Host "Hello"')
            temp_path = f.name

        try:
            result = self.detector.detect(temp_path)
            assert result["type"] == InputType.SCRIPT
            assert result["metadata"]["language"] == "powershell"
        finally:
            os.unlink(temp_path)


class TestContentBasedDetection:
    """Test content-based file type detection"""

    def setup_method(self):
        self.detector = InputDetector()

    def test_detect_log_by_content(self):
        """Test log file detection by content (Apache format)"""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b'192.168.1.1 - - [01/Jan/2025:00:00:00 +0000] "GET / HTTP/1.1" 200 1234\n')
            temp_path = f.name

        try:
            result = self.detector.detect(temp_path)
            assert result["type"] == InputType.LOG
            assert result["metadata"]["detected_by"] == "content"
        finally:
            os.unlink(temp_path)

    def test_detect_email_by_content(self):
        """Test email detection by content (headers)"""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"From: sender@example.com\nTo: recipient@example.com\nSubject: Test\n")
            temp_path = f.name

        try:
            result = self.detector.detect(temp_path)
            assert result["type"] == InputType.EMAIL
        finally:
            os.unlink(temp_path)


class TestIOCListDetection:
    """Test IOC list file detection"""

    def setup_method(self):
        self.detector = InputDetector()

    def test_detect_ioc_list_hashes(self):
        """Test detection of file containing list of hashes"""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"44d88612fea8a8f36de82e1278abb02f\n")
            f.write(b"3395856ce81f2b7382dee72602f798b642f14140\n")
            f.write(b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n")
            temp_path = f.name

        try:
            result = self.detector.detect(temp_path)
            assert result["type"] == InputType.IOC_LIST
        finally:
            os.unlink(temp_path)

    def test_detect_ioc_list_mixed(self):
        """Test detection of file containing mixed IOCs"""
        with tempfile.NamedTemporaryFile(suffix=".ioc", delete=False) as f:
            f.write(b"192.168.1.1\n")
            f.write(b"malicious.com\n")
            f.write(b"44d88612fea8a8f36de82e1278abb02f\n")
            temp_path = f.name

        try:
            result = self.detector.detect(temp_path)
            assert result["type"] == InputType.IOC_LIST
        finally:
            os.unlink(temp_path)


class TestRecommendedTools:
    """Test tool recommendation based on input type"""

    def setup_method(self):
        self.detector = InputDetector()

    def test_hash_recommends_hash_lookup(self):
        """Test that hash input recommends hash lookup tool"""
        detection = self.detector.detect("44d88612fea8a8f36de82e1278abb02f")
        tools = self.detector.get_recommended_tools(detection)
        assert "hash" in tools

    def test_email_recommends_multiple_tools(self):
        """Test that email input recommends eml parser and ioc extractor"""
        with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as f:
            f.write(b"From: test@example.com\n")
            temp_path = f.name

        try:
            detection = self.detector.detect(temp_path)
            tools = self.detector.get_recommended_tools(detection)
            assert "eml" in tools
            assert "ioc" in tools
        finally:
            os.unlink(temp_path)

    def test_domain_recommends_intel(self):
        """Test that domain input recommends intel tool"""
        detection = self.detector.detect("malicious.com")
        tools = self.detector.get_recommended_tools(detection)
        assert "intel" in tools

    def test_url_recommends_url_analyzer(self):
        """Test that URL input recommends url analyzer"""
        detection = self.detector.detect("https://malicious.com/payload")
        tools = self.detector.get_recommended_tools(detection)
        assert "url" in tools


class TestEdgeCases:
    """Test edge cases and boundary conditions"""

    def setup_method(self):
        self.detector = InputDetector()

    def test_empty_string(self):
        """Test empty string handling"""
        result = self.detector.detect("")
        assert result["type"] == InputType.UNKNOWN

    def test_whitespace_only(self):
        """Test whitespace-only input"""
        result = self.detector.detect("   ")
        assert result["type"] == InputType.UNKNOWN

    def test_nonexistent_file(self):
        """Test nonexistent file path"""
        result = self.detector.detect("/nonexistent/path/to/file.exe")
        assert result["type"] == InputType.UNKNOWN

    def test_special_characters(self):
        """Test input with special characters"""
        result = self.detector.detect("!@#$%^&*()")
        assert result["type"] == InputType.UNKNOWN

    def test_input_with_whitespace(self):
        """Test that whitespace is trimmed"""
        result = self.detector.detect("  44d88612fea8a8f36de82e1278abb02f  ")
        assert result["type"] == InputType.HASH_MD5
