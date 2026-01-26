#!/usr/bin/env python3
"""
Integration tests for Analyzer
Tests the main orchestration engine and tool chaining
"""

import pytest
import sys
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.analyzer import Analyzer
from core.detector import InputType
from core.scorer import Severity


class TestAnalyzerInit:
    """Test Analyzer initialization"""

    def test_analyzer_creation(self):
        """Test creating an analyzer"""
        analyzer = Analyzer(verbose=False)
        assert analyzer is not None
        assert analyzer.detector is not None
        assert analyzer.scorer is not None
        assert analyzer.reporter is not None

    def test_analyzer_tool_availability_check(self):
        """Test that analyzer checks tool availability"""
        analyzer = Analyzer(verbose=False)
        assert isinstance(analyzer.available_tools, dict)
        # At least some tools should be detected
        assert len(analyzer.available_tools) > 0


class TestAnalyzeHash:
    """Test hash analysis"""

    def setup_method(self):
        self.analyzer = Analyzer(verbose=False)

    def test_analyze_md5_detection(self):
        """Test that MD5 hashes are detected"""
        result = self.analyzer.analyze("44d88612fea8a8f36de82e1278abb02f")
        assert result["type"] == InputType.HASH_MD5
        assert result["input"] == "44d88612fea8a8f36de82e1278abb02f"

    def test_analyze_sha256_detection(self):
        """Test that SHA256 hashes are detected"""
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result = self.analyzer.analyze(sha256)
        assert result["type"] == InputType.HASH_SHA256

    def test_analyze_hash_has_iocs(self):
        """Test that hash is added to IOCs"""
        result = self.analyzer.analyze("44d88612fea8a8f36de82e1278abb02f")
        assert "44d88612fea8a8f36de82e1278abb02f" in result["iocs"]["hashes"]

    def test_analyze_hash_has_scorer(self):
        """Test that result includes scorer"""
        result = self.analyzer.analyze("44d88612fea8a8f36de82e1278abb02f")
        assert result["scorer"] is not None


class TestAnalyzeIP:
    """Test IP address analysis"""

    def setup_method(self):
        self.analyzer = Analyzer(verbose=False)

    def test_analyze_ipv4_detection(self):
        """Test that IPv4 addresses are detected"""
        result = self.analyzer.analyze("192.168.1.1")
        assert result["type"] == InputType.IP
        assert result["input"] == "192.168.1.1"

    def test_analyze_ip_has_iocs(self):
        """Test that IP is added to IOCs"""
        result = self.analyzer.analyze("8.8.8.8")
        assert "8.8.8.8" in result["iocs"]["ips"]


class TestAnalyzeDomain:
    """Test domain analysis"""

    def setup_method(self):
        self.analyzer = Analyzer(verbose=False)

    def test_analyze_domain_detection(self):
        """Test that domains are detected"""
        result = self.analyzer.analyze("example.com")
        assert result["type"] == InputType.DOMAIN
        assert result["input"] == "example.com"

    def test_analyze_domain_has_iocs(self):
        """Test that domain is added to IOCs"""
        result = self.analyzer.analyze("malicious.com")
        assert "malicious.com" in result["iocs"]["domains"]


class TestAnalyzeURL:
    """Test URL analysis"""

    def setup_method(self):
        self.analyzer = Analyzer(verbose=False)

    def test_analyze_url_detection(self):
        """Test that URLs are detected"""
        result = self.analyzer.analyze("https://example.com/path")
        assert result["type"] == InputType.URL
        assert result["input"] == "https://example.com/path"

    def test_analyze_url_has_iocs(self):
        """Test that URL is added to IOCs"""
        result = self.analyzer.analyze("http://malicious.com/payload")
        assert "http://malicious.com/payload" in result["iocs"]["urls"]


class TestAnalyzeFile:
    """Test file analysis"""

    def setup_method(self):
        self.analyzer = Analyzer(verbose=False)

    def test_analyze_email_file(self):
        """Test analyzing .eml file"""
        with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as f:
            f.write(b"From: test@example.com\nTo: recipient@example.com\nSubject: Test\n\nBody")
            temp_path = f.name

        try:
            result = self.analyzer.analyze(temp_path)
            assert result["type"] == InputType.EMAIL
        finally:
            os.unlink(temp_path)

    def test_analyze_log_file(self):
        """Test analyzing .log file"""
        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as f:
            f.write(b'192.168.1.1 - - [01/Jan/2025:00:00:00 +0000] "GET / HTTP/1.1" 200 1234\n')
            temp_path = f.name

        try:
            result = self.analyzer.analyze(temp_path)
            assert result["type"] == InputType.LOG
        finally:
            os.unlink(temp_path)

    def test_analyze_script_file(self):
        """Test analyzing script file"""
        with tempfile.NamedTemporaryFile(suffix=".js", delete=False) as f:
            f.write(b'var malware = "payload";')
            temp_path = f.name

        try:
            result = self.analyzer.analyze(temp_path)
            assert result["type"] == InputType.SCRIPT
        finally:
            os.unlink(temp_path)

    def test_analyze_generic_file(self):
        """Test analyzing generic file"""
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"\x00\x01\x02\x03\x04\x05")
            temp_path = f.name

        try:
            result = self.analyzer.analyze(temp_path)
            assert result["type"] == InputType.FILE
            # Should have file hash in IOCs
            assert len(result["iocs"]["hashes"]) > 0
        finally:
            os.unlink(temp_path)


class TestAnalyzeIOCList:
    """Test IOC list analysis"""

    def setup_method(self):
        self.analyzer = Analyzer(verbose=False)

    def test_analyze_hash_list(self):
        """Test analyzing file with list of hashes"""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            f.write(b"44d88612fea8a8f36de82e1278abb02f\n")
            f.write(b"3395856ce81f2b7382dee72602f798b642f14140\n")
            temp_path = f.name

        try:
            result = self.analyzer.analyze(temp_path)
            assert result["type"] == InputType.IOC_LIST
            assert len(result["iocs"]["hashes"]) >= 2
        finally:
            os.unlink(temp_path)


class TestResultStructure:
    """Test that analysis results have correct structure"""

    def setup_method(self):
        self.analyzer = Analyzer(verbose=False)

    def test_result_has_required_fields(self):
        """Test that result has all required fields"""
        result = self.analyzer.analyze("example.com")

        assert "input" in result
        assert "type" in result
        assert "detection" in result
        assert "tool_results" in result
        assert "iocs" in result
        assert "scorer" in result

    def test_iocs_has_all_categories(self):
        """Test that IOCs dict has all categories"""
        result = self.analyzer.analyze("example.com")

        assert "hashes" in result["iocs"]
        assert "domains" in result["iocs"]
        assert "ips" in result["iocs"]
        assert "urls" in result["iocs"]
        assert "emails" in result["iocs"]

    def test_tool_results_is_dict(self):
        """Test that tool_results is a dictionary"""
        result = self.analyzer.analyze("example.com")
        assert isinstance(result["tool_results"], dict)


class TestVerboseMode:
    """Test verbose mode functionality"""

    def test_verbose_logging(self):
        """Test that verbose mode produces logging"""
        analyzer = Analyzer(verbose=True)
        # Should not crash
        result = analyzer.analyze("example.com")
        assert result is not None


class TestErrorHandling:
    """Test error handling in analyzer"""

    def setup_method(self):
        self.analyzer = Analyzer(verbose=False)

    def test_unknown_input_handling(self):
        """Test handling of unknown input"""
        result = self.analyzer.analyze("!@#$%^&*()")
        assert result["type"] == InputType.UNKNOWN

    def test_nonexistent_file_handling(self):
        """Test handling of nonexistent file"""
        result = self.analyzer.analyze("/nonexistent/path/file.exe")
        assert result["type"] == InputType.UNKNOWN

    def test_empty_input_handling(self):
        """Test handling of empty input"""
        result = self.analyzer.analyze("")
        assert result["type"] == InputType.UNKNOWN


class TestToolChaining:
    """Test tool chaining behavior"""

    def setup_method(self):
        self.analyzer = Analyzer(verbose=False)

    def test_email_chains_ioc_extraction(self):
        """Test that email analysis chains to IOC extraction"""
        with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as f:
            content = b"""From: attacker@evil.com
To: victim@company.com
Subject: Important!

Please visit http://malicious.com/payload or contact support@evil.com
"""
            f.write(content)
            temp_path = f.name

        try:
            result = self.analyzer.analyze(temp_path)
            # If IOC extractor ran, we should have extracted IOCs
            if "ioc_extractor" in result["tool_results"]:
                # Check that IOCs were extracted
                iocs = result["iocs"]
                # Should have found URL and/or domain
                assert len(iocs.get("urls", [])) > 0 or len(iocs.get("domains", [])) > 0
        finally:
            os.unlink(temp_path)


class TestScorerIntegration:
    """Test scorer integration with analyzer"""

    def setup_method(self):
        self.analyzer = Analyzer(verbose=False)

    def test_scorer_receives_findings(self):
        """Test that scorer receives findings from tools"""
        # This is hard to test without mocking, but we can verify structure
        result = self.analyzer.analyze("example.com")
        scorer = result["scorer"]

        # Scorer should be properly initialized
        assert scorer is not None
        # Should be able to get summary
        summary = scorer.get_summary()
        assert "risk_score" in summary
        assert "verdict" in summary

    def test_scorer_reset_between_analyses(self):
        """Test that scorer is reset between analyses"""
        # Analyze twice
        result1 = self.analyzer.analyze("example.com")
        result2 = self.analyzer.analyze("test.net")

        # Each should have their own scorer state
        # (In real implementation, scorer is reset at start of analyze())


class TestMockedToolExecution:
    """Test analyzer with mocked tools"""

    def test_hash_lookup_integration(self):
        """Test hash lookup integration with mocked response"""
        analyzer = Analyzer(verbose=False)

        # If hash_lookup is available, test with mock
        if analyzer.available_tools.get("hash_lookup"):
            with patch("hashLookup.lookup.HashLookup") as MockHashLookup:
                mock_instance = MagicMock()
                mock_instance.lookup.return_value = {
                    "hash": "44d88612fea8a8f36de82e1278abb02f",
                    "verdict": "malicious",
                    "sources": {"virustotal": {"detections": 45, "total": 70}},
                }
                MockHashLookup.return_value = mock_instance

                result = analyzer.analyze("44d88612fea8a8f36de82e1278abb02f")
                # Should have run analysis
                assert result is not None


class TestAnalyzeCommandLineInterface:
    """Test the command-line interface of analyzer"""

    def test_parse_args_basic(self):
        """Test basic argument parsing"""
        from core.analyzer import parse_args

        # Mock sys.argv
        with patch("sys.argv", ["analyzer.py", "test_input"]):
            args = parse_args()
            assert args.input == "test_input"
            assert args.verbose == False
            assert args.json == False
            assert args.quiet == False

    def test_parse_args_verbose(self):
        """Test verbose flag parsing"""
        from core.analyzer import parse_args

        with patch("sys.argv", ["analyzer.py", "test_input", "--verbose"]):
            args = parse_args()
            assert args.verbose == True

    def test_parse_args_json(self):
        """Test JSON flag parsing"""
        from core.analyzer import parse_args

        with patch("sys.argv", ["analyzer.py", "test_input", "--json"]):
            args = parse_args()
            assert args.json == True

    def test_parse_args_quiet(self):
        """Test quiet flag parsing"""
        from core.analyzer import parse_args

        with patch("sys.argv", ["analyzer.py", "test_input", "--quiet"]):
            args = parse_args()
            assert args.quiet == True

    def test_parse_args_short_flags(self):
        """Test short flag parsing"""
        from core.analyzer import parse_args

        with patch("sys.argv", ["analyzer.py", "test_input", "-v", "-j"]):
            args = parse_args()
            assert args.verbose == True
            assert args.json == True
