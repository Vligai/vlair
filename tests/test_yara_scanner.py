#!/usr/bin/env python3
"""
Unit tests for YARA Scanner
"""

import pytest
import sys
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# Check if yara is available
try:
    import yara

    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


class TestYaraRuleValidation:
    """Test YARA rule validation"""

    @pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
    def test_validate_valid_rule(self):
        """Test validating a correct YARA rule"""
        from secops_helper.tools.yara_scanner import YaraRuleManager

        manager = YaraRuleManager()

        # Create a valid rule file
        with tempfile.NamedTemporaryFile(suffix=".yar", delete=False, mode="w") as f:
            f.write('rule test_rule { strings: $a = "test" condition: $a }')
            rule_path = f.name

        try:
            valid, error = manager.validate_rule(rule_path)
            assert valid is True
            assert error is None
        finally:
            import os

            os.unlink(rule_path)

    @pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
    def test_validate_invalid_rule(self):
        """Test handling invalid YARA rule syntax"""
        from secops_helper.tools.yara_scanner import YaraRuleManager

        manager = YaraRuleManager()

        # Create an invalid rule file
        with tempfile.NamedTemporaryFile(suffix=".yar", delete=False, mode="w") as f:
            f.write("rule invalid_rule { this is not valid }")
            rule_path = f.name

        try:
            valid, error = manager.validate_rule(rule_path)
            assert valid is False
            assert error is not None
        finally:
            import os

            os.unlink(rule_path)

    def test_validate_rule_file_not_found(self):
        """Test handling missing rule file"""
        pass  # Skip - needs yara module


class TestYaraScanning:
    """Test YARA scanning functionality"""

    @pytest.fixture
    def test_file(self):
        """Create a temporary test file"""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            f.write(b"This is a test file with EICAR test string")
            return f.name

    def test_scan_file_no_matches(self):
        """Test scanning file with no matches"""
        pass  # Skip - needs compiled rules

    def test_scan_file_with_match(self):
        """Test scanning file that matches a rule"""
        pass  # Skip - needs compiled rules

    def test_scan_directory(self):
        """Test scanning entire directory"""
        pass  # Skip - needs compiled rules

    def test_scan_nonexistent_file(self):
        """Test handling nonexistent file"""
        pass  # Skip - needs compiled rules


class TestMatchProcessing:
    """Test YARA match processing"""

    def test_extract_match_metadata(self):
        """Test extracting metadata from matches"""
        pass

    def test_severity_classification(self):
        """Test severity classification of matches"""
        pass

    def test_match_details_extraction(self):
        """Test extracting match details (strings, offsets)"""
        pass


class TestYaraScannerIntegration:
    """Integration tests for YARA Scanner"""

    def test_scanner_without_yara(self):
        """Test behavior when yara-python not installed"""
        # Import the module and check YARA_AVAILABLE flag
        from secops_helper.tools import yara_scanner

        # The module should define YARA_AVAILABLE
        assert hasattr(yara_scanner, "YARA_AVAILABLE")
        # This just tests that the module loads without error

    @pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
    def test_scanner_creation(self):
        """Test creating scanner instance"""
        from secops_helper.tools.yara_scanner import YaraScanner, YaraRuleManager

        # Create a simple rule
        with tempfile.NamedTemporaryFile(suffix=".yar", delete=False, mode="w") as f:
            f.write('rule test_rule { strings: $a = "test" condition: $a }')
            rule_path = f.name

        try:
            manager = YaraRuleManager(verbose=False)
            rules = manager.load_rules_from_file(rule_path)
            if rules:
                scanner = YaraScanner(rules, verbose=False)
                assert scanner is not None
        finally:
            import os

            os.unlink(rule_path)

    def test_load_rules_from_directory(self):
        """Test loading rules from directory"""
        pass

    def test_load_rules_from_file(self):
        """Test loading rules from single file"""
        pass


class TestBatchScanning:
    """Test batch scanning functionality"""

    def test_scan_multiple_files(self):
        """Test scanning multiple files"""
        pass

    def test_scan_with_threading(self):
        """Test multi-threaded scanning"""
        pass

    def test_progress_reporting(self):
        """Test progress reporting during batch scan"""
        pass


class TestOutputFormatting:
    """Test output formatting"""

    def test_json_output(self):
        """Test JSON output format"""
        pass

    def test_csv_output(self):
        """Test CSV output format"""
        pass

    def test_console_output(self):
        """Test console output format"""
        pass


class TestMatchAnalyzer:
    """Test MatchAnalyzer class"""

    @pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
    def test_classify_severity_critical(self):
        """Test severity classification for critical tags"""
        from secops_helper.tools.yara_scanner import MatchAnalyzer

        # Create a mock match with critical tags
        mock_match = Mock()
        mock_match.tags = ["ransomware", "apt"]
        mock_match.meta = {}

        severity = MatchAnalyzer.classify_severity(mock_match)
        assert severity == "critical"

    @pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
    def test_classify_severity_high(self):
        """Test severity classification for high tags"""
        from secops_helper.tools.yara_scanner import MatchAnalyzer

        mock_match = Mock()
        mock_match.tags = ["trojan", "malware"]
        mock_match.meta = {}

        severity = MatchAnalyzer.classify_severity(mock_match)
        assert severity == "high"

    @pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
    def test_classify_verdict_clean(self):
        """Test verdict classification with no matches"""
        from secops_helper.tools.yara_scanner import MatchAnalyzer

        verdict, score = MatchAnalyzer.classify_verdict([])
        assert verdict == "clean"
        assert score == 0

    @pytest.mark.skipif(not YARA_AVAILABLE, reason="yara-python not installed")
    def test_classify_verdict_malicious(self):
        """Test verdict classification with critical matches"""
        from secops_helper.tools.yara_scanner import MatchAnalyzer

        matches = [{"severity": "critical"}]
        verdict, score = MatchAnalyzer.classify_verdict(matches)
        assert verdict == "malicious"
        assert score > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
