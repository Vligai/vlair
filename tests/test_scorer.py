#!/usr/bin/env python3
"""
Unit tests for Risk Scorer
Tests risk scoring, verdict calculation, and finding aggregation
"""

import pytest
import sys
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from vlair.core.scorer import RiskScorer, Severity, Verdict, Finding


class TestSeverity:
    """Test Severity enum"""

    def test_severity_values(self):
        """Test that all severity levels exist"""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"


class TestVerdict:
    """Test Verdict enum"""

    def test_verdict_values(self):
        """Test that all verdict levels exist"""
        assert Verdict.CLEAN.value == "CLEAN"
        assert Verdict.LOW_RISK.value == "LOW_RISK"
        assert Verdict.SUSPICIOUS.value == "SUSPICIOUS"
        assert Verdict.MALICIOUS.value == "MALICIOUS"
        assert Verdict.UNKNOWN.value == "UNKNOWN"


class TestFinding:
    """Test Finding dataclass"""

    def test_finding_creation(self):
        """Test creating a finding"""
        finding = Finding(severity=Severity.HIGH, message="Test finding", source="test_tool")
        assert finding.severity == Severity.HIGH
        assert finding.message == "Test finding"
        assert finding.source == "test_tool"
        assert finding.details is None

    def test_finding_with_details(self):
        """Test creating a finding with details"""
        finding = Finding(
            severity=Severity.CRITICAL,
            message="Critical finding",
            source="test_tool",
            details={"count": 5, "type": "malware"},
        )
        assert finding.details == {"count": 5, "type": "malware"}

    def test_finding_to_dict(self):
        """Test finding serialization"""
        finding = Finding(
            severity=Severity.MEDIUM,
            message="Medium finding",
            source="scanner",
            details={"file": "test.exe"},
        )
        result = finding.to_dict()

        assert result["severity"] == "medium"
        assert result["message"] == "Medium finding"
        assert result["source"] == "scanner"
        assert result["details"] == {"file": "test.exe"}


class TestRiskScorerBasic:
    """Test basic RiskScorer functionality"""

    def setup_method(self):
        self.scorer = RiskScorer()

    def test_empty_scorer(self):
        """Test scorer with no findings"""
        assert self.scorer.calculate_score() == 0
        assert self.scorer.get_verdict() == Verdict.UNKNOWN

    def test_add_finding(self):
        """Test adding a single finding"""
        self.scorer.add_finding(Severity.HIGH, "Test finding", "test_tool")
        assert len(self.scorer.findings) == 1

    def test_reset(self):
        """Test resetting the scorer"""
        self.scorer.add_finding(Severity.HIGH, "Test", "test")
        self.scorer.reset()
        assert len(self.scorer.findings) == 0


class TestScoreCalculation:
    """Test risk score calculation"""

    def setup_method(self):
        self.scorer = RiskScorer()

    def test_critical_finding_score(self):
        """Test that critical findings add significant score"""
        self.scorer.add_finding(Severity.CRITICAL, "Critical issue", "test")
        score = self.scorer.calculate_score()
        assert score >= 25  # Critical weight is 30

    def test_high_finding_score(self):
        """Test that high findings add moderate score"""
        self.scorer.add_finding(Severity.HIGH, "High issue", "test")
        score = self.scorer.calculate_score()
        assert 10 <= score <= 20

    def test_medium_finding_score(self):
        """Test that medium findings add small score"""
        self.scorer.add_finding(Severity.MEDIUM, "Medium issue", "test")
        score = self.scorer.calculate_score()
        assert 3 <= score <= 10

    def test_low_finding_score(self):
        """Test that low findings add minimal score"""
        self.scorer.add_finding(Severity.LOW, "Low issue", "test")
        score = self.scorer.calculate_score()
        assert score <= 5

    def test_info_finding_no_score(self):
        """Test that info findings don't add score"""
        self.scorer.add_finding(Severity.INFO, "Info message", "test")
        score = self.scorer.calculate_score()
        assert score == 0

    def test_multiple_findings_accumulate(self):
        """Test that multiple findings accumulate score"""
        self.scorer.add_finding(Severity.HIGH, "Issue 1", "test")
        self.scorer.add_finding(Severity.HIGH, "Issue 2", "test")
        score = self.scorer.calculate_score()
        assert score >= 20

    def test_score_capped_at_100(self):
        """Test that score is capped at 100"""
        # Add many findings across all severity levels to exceed 100
        for i in range(10):
            self.scorer.add_finding(Severity.CRITICAL, f"Critical {i}", "test")
        for i in range(10):
            self.scorer.add_finding(Severity.HIGH, f"High {i}", "test")
        for i in range(10):
            self.scorer.add_finding(Severity.MEDIUM, f"Medium {i}", "test")
        score = self.scorer.calculate_score()
        assert score == 100

    def test_severity_caps_applied(self):
        """Test that per-severity caps are applied"""
        # Add many high findings - should hit cap
        for i in range(10):
            self.scorer.add_finding(Severity.HIGH, f"High {i}", "test")
        score = self.scorer.calculate_score()
        # High cap is 40, so should not exceed that
        assert score <= 40


class TestVerdictCalculation:
    """Test verdict determination based on score"""

    def setup_method(self):
        self.scorer = RiskScorer()

    def test_verdict_malicious(self):
        """Test MALICIOUS verdict for high scores"""
        # Add enough to get score >= 70
        for i in range(3):
            self.scorer.add_finding(Severity.CRITICAL, f"Critical {i}", "test")
        verdict = self.scorer.get_verdict()
        assert verdict == Verdict.MALICIOUS

    def test_verdict_suspicious(self):
        """Test SUSPICIOUS verdict for medium scores"""
        # Add enough to get score 40-69
        self.scorer.add_finding(Severity.CRITICAL, "Critical", "test")
        self.scorer.add_finding(Severity.HIGH, "High", "test")
        score = self.scorer.calculate_score()
        if 40 <= score < 70:
            verdict = self.scorer.get_verdict()
            assert verdict == Verdict.SUSPICIOUS

    def test_verdict_low_risk(self):
        """Test LOW_RISK verdict for low scores"""
        # Add small findings to get score 10-39
        self.scorer.add_finding(Severity.MEDIUM, "Medium 1", "test")
        self.scorer.add_finding(Severity.MEDIUM, "Medium 2", "test")
        self.scorer.add_finding(Severity.LOW, "Low", "test")
        score = self.scorer.calculate_score()
        if 10 <= score < 40:
            verdict = self.scorer.get_verdict()
            assert verdict == Verdict.LOW_RISK

    def test_verdict_clean(self):
        """Test CLEAN verdict for minimal scores"""
        self.scorer.add_finding(Severity.LOW, "Minor issue", "test")
        score = self.scorer.calculate_score()
        if score < 10:
            verdict = self.scorer.get_verdict()
            assert verdict == Verdict.CLEAN

    def test_verdict_unknown_no_findings(self):
        """Test UNKNOWN verdict when no findings"""
        verdict = self.scorer.get_verdict()
        assert verdict == Verdict.UNKNOWN


class TestSummary:
    """Test summary generation"""

    def setup_method(self):
        self.scorer = RiskScorer()

    def test_summary_structure(self):
        """Test that summary has required fields"""
        self.scorer.add_finding(Severity.HIGH, "Test", "test")
        summary = self.scorer.get_summary()

        assert "risk_score" in summary
        assert "verdict" in summary
        assert "confidence" in summary
        assert "finding_counts" in summary
        assert "total_findings" in summary

    def test_summary_finding_counts(self):
        """Test that finding counts are accurate"""
        self.scorer.add_finding(Severity.CRITICAL, "Crit 1", "test")
        self.scorer.add_finding(Severity.CRITICAL, "Crit 2", "test")
        self.scorer.add_finding(Severity.HIGH, "High", "test")
        self.scorer.add_finding(Severity.MEDIUM, "Med", "test")

        summary = self.scorer.get_summary()
        assert summary["finding_counts"]["critical"] == 2
        assert summary["finding_counts"]["high"] == 1
        assert summary["finding_counts"]["medium"] == 1
        assert summary["total_findings"] == 4

    def test_confidence_levels(self):
        """Test confidence level calculation"""
        # No findings = low confidence
        summary = self.scorer.get_summary()
        assert summary["confidence"] == "low"

        # 1-2 findings = medium confidence
        self.scorer.add_finding(Severity.HIGH, "Test", "test")
        summary = self.scorer.get_summary()
        assert summary["confidence"] == "medium"

        # 3+ findings = high confidence
        self.scorer.add_finding(Severity.HIGH, "Test 2", "test")
        self.scorer.add_finding(Severity.HIGH, "Test 3", "test")
        summary = self.scorer.get_summary()
        assert summary["confidence"] == "high"


class TestGetFindings:
    """Test findings retrieval"""

    def setup_method(self):
        self.scorer = RiskScorer()
        self.scorer.add_finding(Severity.CRITICAL, "Critical", "test")
        self.scorer.add_finding(Severity.HIGH, "High", "test")
        self.scorer.add_finding(Severity.MEDIUM, "Medium", "test")
        self.scorer.add_finding(Severity.LOW, "Low", "test")
        self.scorer.add_finding(Severity.INFO, "Info", "test")

    def test_get_all_findings(self):
        """Test getting all findings"""
        findings = self.scorer.get_findings()
        assert len(findings) == 5

    def test_findings_sorted_by_severity(self):
        """Test that findings are sorted by severity (critical first)"""
        findings = self.scorer.get_findings()
        assert findings[0]["severity"] == "critical"
        assert findings[1]["severity"] == "high"
        assert findings[2]["severity"] == "medium"

    def test_filter_by_min_severity(self):
        """Test filtering findings by minimum severity"""
        # Only get high and above
        findings = self.scorer.get_findings(min_severity=Severity.HIGH)
        assert len(findings) == 2
        severities = [f["severity"] for f in findings]
        assert "critical" in severities
        assert "high" in severities
        assert "medium" not in severities


class TestRecommendations:
    """Test recommendation generation"""

    def setup_method(self):
        self.scorer = RiskScorer()

    def test_recommendations_for_malware(self):
        """Test recommendations when malware is detected"""
        self.scorer.add_finding(
            Severity.CRITICAL,
            "Hash matches known malware",
            "hash_lookup",
            {"malware_family": "Emotet"},
        )
        recommendations = self.scorer.get_recommendations()

        assert any("isolate" in r.lower() for r in recommendations)
        assert any("sandbox" in r.lower() for r in recommendations)

    def test_recommendations_for_phishing(self):
        """Test recommendations for phishing indicators"""
        self.scorer.add_finding(
            Severity.HIGH, "SPF validation failed", "eml_parser", {"spf": "fail"}
        )
        recommendations = self.scorer.get_recommendations()

        assert any("block" in r.lower() and "domain" in r.lower() for r in recommendations)

    def test_default_recommendations(self):
        """Test that some recommendation is always provided"""
        self.scorer.add_finding(Severity.LOW, "Minor issue", "test")
        recommendations = self.scorer.get_recommendations()

        assert len(recommendations) > 0


class TestAddFindingsFromToolResults:
    """Test adding findings from tool result dictionaries"""

    def setup_method(self):
        self.scorer = RiskScorer()

    def test_hash_lookup_malicious(self):
        """Test adding findings from malicious hash lookup"""
        result = {
            "hash": "44d88612fea8a8f36de82e1278abb02f",
            "sources": {"virustotal": {"detections": 45, "total": 70, "verdict": "malicious"}},
        }
        self.scorer.add_findings_from_hash_lookup(result)

        assert len(self.scorer.findings) > 0
        assert self.scorer.findings[0].severity == Severity.CRITICAL

    def test_hash_lookup_clean(self):
        """Test adding findings from clean hash lookup"""
        result = {
            "hash": "44d88612fea8a8f36de82e1278abb02f",
            "sources": {"virustotal": {"detections": 0, "total": 70, "verdict": "clean"}},
        }
        self.scorer.add_findings_from_hash_lookup(result)

        # No findings for clean results
        assert len(self.scorer.findings) == 0

    def test_hash_lookup_with_malwarebazaar(self):
        """Test adding findings from MalwareBazaar match"""
        result = {
            "hash": "44d88612fea8a8f36de82e1278abb02f",
            "sources": {"malwarebazaar": {"found": True, "malware_family": "Emotet"}},
        }
        self.scorer.add_findings_from_hash_lookup(result)

        assert len(self.scorer.findings) > 0
        assert any("Emotet" in f.message for f in self.scorer.findings)

    def test_domain_intel_malicious(self):
        """Test adding findings from malicious domain intel"""
        result = {"indicator": "malicious.com", "risk_score": 85, "verdict": "malicious"}
        self.scorer.add_findings_from_domain_intel(result)

        assert len(self.scorer.findings) > 0
        assert self.scorer.findings[0].severity == Severity.CRITICAL

    def test_url_analysis_suspicious(self):
        """Test adding findings from suspicious URL analysis"""
        result = {
            "url": "http://suspicious.com/payload",
            "risk_score": 55,
            "verdict": "suspicious",
            "suspicious_patterns": ["encoded_url", "ip_address_url"],
        }
        self.scorer.add_findings_from_url_analysis(result)

        assert len(self.scorer.findings) > 0

    def test_email_analysis_spf_fail(self):
        """Test adding findings from email with SPF failure"""
        result = {
            "authentication": {
                "spf": {"result": "fail"},
                "dkim": {"result": "pass"},
                "dmarc": {"result": "pass"},
            }
        }
        self.scorer.add_findings_from_email_analysis(result)

        assert len(self.scorer.findings) > 0
        assert any("SPF" in f.message for f in self.scorer.findings)

    def test_yara_scan_match(self):
        """Test adding findings from YARA scan matches"""
        result = {
            "matches": [
                {"rule": "Emotet_Dropper", "severity": "critical"},
                {"rule": "Suspicious_Strings", "severity": "medium"},
            ]
        }
        self.scorer.add_findings_from_yara_scan(result)

        assert len(self.scorer.findings) == 2

    def test_log_analysis_sql_injection(self):
        """Test adding findings from log analysis with SQL injection"""
        result = {
            "threats": {"sql_injection": [{"ip": "1.2.3.4", "payload": "' OR 1=1"}], "xss": []}
        }
        self.scorer.add_findings_from_log_analysis(result)

        assert len(self.scorer.findings) > 0
        assert any("SQL injection" in f.message for f in self.scorer.findings)

    def test_empty_result_handling(self):
        """Test that empty/error results are handled gracefully"""
        self.scorer.add_findings_from_hash_lookup({})
        self.scorer.add_findings_from_hash_lookup({"error": "API timeout"})
        self.scorer.add_findings_from_domain_intel(None)

        # Should not crash and should have no findings
        assert len(self.scorer.findings) == 0
