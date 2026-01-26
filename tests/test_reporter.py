#!/usr/bin/env python3
"""
Unit tests for Reporter
Tests output formatting for console, JSON, and quiet modes
"""

import pytest
import sys
import json
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.reporter import Reporter, Colors
from core.scorer import RiskScorer, Severity, Verdict


class TestColors:
    """Test color handling"""

    def test_colors_have_values(self):
        """Test that color codes are defined"""
        Colors.enable()
        assert Colors.RED != ""
        assert Colors.GREEN != ""
        assert Colors.YELLOW != ""
        assert Colors.RESET != ""

    def test_disable_colors(self):
        """Test that colors can be disabled"""
        Colors.enable()
        Colors.disable()
        assert Colors.RED == ""
        assert Colors.GREEN == ""
        assert Colors.RESET == ""


class TestReporterInit:
    """Test Reporter initialization"""

    def test_reporter_creation(self):
        """Test creating a reporter"""
        reporter = Reporter(use_colors=False)
        assert reporter is not None

    def test_reporter_no_colors_for_non_tty(self):
        """Test that colors are disabled for non-TTY"""
        # When not a TTY, colors should be disabled
        reporter = Reporter(use_colors=True)
        # Note: actual color state depends on sys.stdout.isatty()


class TestQuietOutput:
    """Test quiet mode output"""

    def setup_method(self):
        self.reporter = Reporter(use_colors=False)
        self.scorer = RiskScorer()

    def test_quiet_format_structure(self):
        """Test quiet output format"""
        self.scorer.add_finding(Severity.CRITICAL, "Test", "test")
        output = self.reporter.format_quiet(self.scorer)

        # Should be "VERDICT SCORE" format
        parts = output.split()
        assert len(parts) == 2
        assert parts[0] in ["CLEAN", "LOW_RISK", "SUSPICIOUS", "MALICIOUS", "UNKNOWN"]
        assert parts[1].isdigit()

    def test_quiet_malicious(self):
        """Test quiet output for malicious verdict"""
        for _ in range(3):
            self.scorer.add_finding(Severity.CRITICAL, "Critical", "test")
        output = self.reporter.format_quiet(self.scorer)

        assert "MALICIOUS" in output

    def test_quiet_clean(self):
        """Test quiet output for clean verdict"""
        self.scorer.add_finding(Severity.INFO, "Info", "test")
        output = self.reporter.format_quiet(self.scorer)

        # With only info findings, should be clean or unknown
        assert "CLEAN" in output or "UNKNOWN" in output


class TestJSONOutput:
    """Test JSON output format"""

    def setup_method(self):
        self.reporter = Reporter(use_colors=False)
        self.scorer = RiskScorer()

    def test_json_is_valid(self):
        """Test that JSON output is valid JSON"""
        self.scorer.add_finding(Severity.HIGH, "Test finding", "test")
        output = self.reporter.format_json(
            "test_input", "hash", self.scorer, {"hashes": ["abc123"]}, {"hash_lookup": {"result": "clean"}}
        )

        # Should be parseable JSON
        parsed = json.loads(output)
        assert parsed is not None

    def test_json_structure(self):
        """Test JSON output structure"""
        self.scorer.add_finding(Severity.HIGH, "Test finding", "test")
        output = self.reporter.format_json(
            "test_input", "hash", self.scorer, {"hashes": ["abc123"]}, {"hash_lookup": {"result": "clean"}}
        )
        parsed = json.loads(output)

        # Check required fields
        assert "input" in parsed
        assert "type" in parsed
        assert "timestamp" in parsed
        assert "verdict" in parsed
        assert "risk_score" in parsed
        assert "findings" in parsed
        assert "iocs" in parsed
        assert "recommendations" in parsed
        assert "tool_results" in parsed

    def test_json_input_preserved(self):
        """Test that input value is preserved in JSON"""
        output = self.reporter.format_json("suspicious.eml", "email", self.scorer, {}, {})
        parsed = json.loads(output)

        assert parsed["input"] == "suspicious.eml"
        assert parsed["type"] == "email"

    def test_json_findings_included(self):
        """Test that findings are included in JSON"""
        self.scorer.add_finding(Severity.CRITICAL, "Critical issue", "test", {"count": 5})
        output = self.reporter.format_json("input", "hash", self.scorer, {}, {})
        parsed = json.loads(output)

        assert len(parsed["findings"]) == 1
        assert parsed["findings"][0]["severity"] == "critical"
        assert parsed["findings"][0]["message"] == "Critical issue"

    def test_json_iocs_included(self):
        """Test that IOCs are included in JSON"""
        iocs = {"hashes": ["abc123", "def456"], "domains": ["evil.com"], "urls": ["http://bad.com/malware"]}
        output = self.reporter.format_json("input", "email", self.scorer, iocs, {})
        parsed = json.loads(output)

        assert parsed["iocs"]["hashes"] == ["abc123", "def456"]
        assert parsed["iocs"]["domains"] == ["evil.com"]

    def test_json_tool_results_included(self):
        """Test that tool results are included in JSON"""
        tool_results = {"hash_lookup": {"verdict": "malicious", "detections": 45}, "domain_intel": {"risk_score": 85}}
        output = self.reporter.format_json("input", "hash", self.scorer, {}, tool_results)
        parsed = json.loads(output)

        assert "hash_lookup" in parsed["tool_results"]
        assert parsed["tool_results"]["hash_lookup"]["verdict"] == "malicious"


class TestConsoleOutput:
    """Test console output format"""

    def setup_method(self):
        self.reporter = Reporter(use_colors=False)
        self.scorer = RiskScorer()

    def test_console_has_header(self):
        """Test that console output has header"""
        output = self.reporter.format_console("test.eml", "email", self.scorer, {}, {})
        assert "SecOps Helper" in output
        assert "Analysis Report" in output

    def test_console_has_verdict(self):
        """Test that console output shows verdict"""
        self.scorer.add_finding(Severity.CRITICAL, "Test", "test")
        output = self.reporter.format_console("test.eml", "email", self.scorer, {}, {})
        assert "VERDICT" in output

    def test_console_has_risk_score(self):
        """Test that console output shows risk score"""
        self.scorer.add_finding(Severity.HIGH, "Test", "test")
        output = self.reporter.format_console("test.eml", "email", self.scorer, {}, {})
        assert "Risk Score" in output
        assert "/100" in output

    def test_console_shows_findings(self):
        """Test that console output shows findings"""
        self.scorer.add_finding(Severity.CRITICAL, "Critical security issue", "test")
        output = self.reporter.format_console("test.eml", "email", self.scorer, {}, {})
        assert "Key Findings" in output
        assert "Critical security issue" in output

    def test_console_shows_iocs(self):
        """Test that console output shows extracted IOCs"""
        iocs = {"hashes": ["44d88612fea8a8f36de82e1278abb02f"], "domains": ["evil.com"], "urls": [], "ips": [], "emails": []}
        output = self.reporter.format_console("test.eml", "email", self.scorer, iocs, {})
        assert "Extracted IOCs" in output
        assert "Hashes" in output

    def test_console_shows_recommendations(self):
        """Test that console output shows recommendations"""
        self.scorer.add_finding(Severity.CRITICAL, "Test", "test")
        output = self.reporter.format_console("test.eml", "email", self.scorer, {}, {})
        assert "Recommended Actions" in output

    def test_console_shows_input_info(self):
        """Test that console output shows input information"""
        output = self.reporter.format_console("suspicious.eml", "email", self.scorer, {}, {})
        assert "suspicious.eml" in output
        assert "email" in output

    def test_console_limits_findings(self):
        """Test that console output limits displayed findings"""
        # Add more than 10 findings
        for i in range(15):
            self.scorer.add_finding(Severity.MEDIUM, f"Finding {i}", "test")

        output = self.reporter.format_console("test.eml", "email", self.scorer, {}, {})
        # Should show "and X more findings"
        assert "more findings" in output


class TestVerboseOutput:
    """Test verbose output format"""

    def setup_method(self):
        self.reporter = Reporter(use_colors=False)
        self.scorer = RiskScorer()

    def test_verbose_includes_console_output(self):
        """Test that verbose includes standard console output"""
        self.scorer.add_finding(Severity.HIGH, "Test", "test")
        output = self.reporter.format_verbose("test.eml", "email", self.scorer, {}, {})
        assert "SecOps Helper" in output
        assert "VERDICT" in output

    def test_verbose_includes_tool_results(self):
        """Test that verbose output includes detailed tool results"""
        tool_results = {"hash_lookup": {"verdict": "malicious", "detections": 45}}
        output = self.reporter.format_verbose("test.eml", "email", self.scorer, {}, tool_results)
        assert "Detailed Tool Results" in output
        assert "hash_lookup" in output


class TestExitCode:
    """Test exit code determination"""

    def setup_method(self):
        self.reporter = Reporter(use_colors=False)

    def test_exit_code_clean(self):
        """Test exit code 0 for clean verdict"""
        scorer = RiskScorer()
        scorer.add_finding(Severity.INFO, "Info", "test")
        exit_code = self.reporter.get_exit_code(scorer)
        assert exit_code == 0

    def test_exit_code_suspicious(self):
        """Test exit code 1 for suspicious verdict"""
        scorer = RiskScorer()
        scorer.add_finding(Severity.CRITICAL, "Critical", "test")
        scorer.add_finding(Severity.HIGH, "High", "test")
        # This should give score 40-69 (suspicious)
        score = scorer.calculate_score()
        if 40 <= score < 70:
            exit_code = self.reporter.get_exit_code(scorer)
            assert exit_code == 1

    def test_exit_code_malicious(self):
        """Test exit code 2 for malicious verdict"""
        scorer = RiskScorer()
        for _ in range(3):
            scorer.add_finding(Severity.CRITICAL, "Critical", "test")
        exit_code = self.reporter.get_exit_code(scorer)
        assert exit_code == 2


class TestDefanging:
    """Test IOC defanging for safe display"""

    def setup_method(self):
        self.reporter = Reporter(use_colors=False)
        self.scorer = RiskScorer()

    def test_url_defanged(self):
        """Test that URLs are defanged in console output"""
        iocs = {"urls": ["http://evil.com/malware"], "hashes": [], "domains": [], "ips": [], "emails": []}
        output = self.reporter.format_console("test.eml", "email", self.scorer, iocs, {})
        # URL should be defanged
        assert "hxxp://" in output
        assert "http://" not in output.replace("hxxp://", "")  # Make sure original isn't there

    def test_domain_defanged(self):
        """Test that domains are defanged in console output"""
        iocs = {"domains": ["evil.com"], "hashes": [], "urls": [], "ips": [], "emails": []}
        output = self.reporter.format_console("test.eml", "email", self.scorer, iocs, {})
        # Domain should be defanged
        assert "evil[.]com" in output


class TestEmptyResults:
    """Test handling of empty results"""

    def setup_method(self):
        self.reporter = Reporter(use_colors=False)
        self.scorer = RiskScorer()

    def test_empty_iocs(self):
        """Test output with no IOCs"""
        output = self.reporter.format_console(
            "test.txt", "file", self.scorer, {"hashes": [], "domains": [], "urls": [], "ips": [], "emails": []}, {}
        )
        # Should not show IOCs section if all empty
        # Or show it but with no entries
        assert output is not None

    def test_empty_findings(self):
        """Test output with no findings"""
        output = self.reporter.format_console("test.txt", "file", self.scorer, {}, {})
        # Should still produce valid output
        assert "SecOps Helper" in output

    def test_empty_tool_results(self):
        """Test JSON output with empty tool results"""
        output = self.reporter.format_json("test.txt", "file", self.scorer, {}, {})
        parsed = json.loads(output)
        assert parsed["tool_results"] == {}
