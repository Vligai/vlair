#!/usr/bin/env python3
"""
Unit tests for Report Generator
Tests HTML and Markdown report generation
"""

import pytest
import sys
import os
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.report_generator import ReportGenerator, ReportData
from core.scorer import RiskScorer, Severity, Verdict


class TestReportGeneratorInit:
    """Test ReportGenerator initialization"""

    def test_creation(self):
        gen = ReportGenerator()
        assert gen is not None

    def test_supported_formats(self):
        gen = ReportGenerator()
        assert "html" in gen.SUPPORTED_FORMATS
        assert "markdown" in gen.SUPPORTED_FORMATS
        assert "md" in gen.SUPPORTED_FORMATS


class TestBuildReportData:
    """Test report data construction from result dicts"""

    def setup_method(self):
        self.gen = ReportGenerator()
        self.scorer = RiskScorer()

    def test_build_from_analyze_result(self):
        self.scorer.add_finding(Severity.CRITICAL, "Test finding", "test")
        result = {
            "input": "test.eml",
            "type": "email",
            "scorer": self.scorer,
            "iocs": {"hashes": ["abc123"], "domains": [], "ips": [], "urls": []},
            "tool_results": {"eml_parser": {"result": "parsed"}},
        }
        data = self.gen._build_report_data(result)
        assert data.input_value == "test.eml"
        assert data.input_type == "email"
        assert data.risk_score > 0
        assert len(data.findings) == 1
        assert "eml_parser" in data.tools_executed

    def test_build_from_workflow_result(self):
        self.scorer.add_finding(Severity.HIGH, "Workflow finding", "workflow")
        result = {
            "input": "suspicious.eml",
            "type": "email",
            "workflow": "phishing-email",
            "scorer": self.scorer,
            "iocs": {"hashes": [], "domains": ["evil.com"]},
            "tool_results": {"eml_parser": {}, "ioc_extractor": {}},
            "steps_completed": 5,
            "steps_total": 7,
            "step_results": [
                {"name": "parse_email", "success": True, "duration_ms": 100, "error": None},
                {"name": "extract_iocs", "success": True, "duration_ms": 50, "error": None},
            ],
            "duration_seconds": 2.5,
        }
        data = self.gen._build_report_data(result)
        assert data.workflow_name == "phishing-email"
        assert data.steps_completed == 5
        assert data.steps_total == 7
        assert len(data.step_results) == 2
        assert data.duration_seconds == 2.5

    def test_build_with_empty_scorer(self):
        result = {"input": "clean.txt", "type": "file", "scorer": self.scorer, "iocs": {}, "tool_results": {}}
        data = self.gen._build_report_data(result)
        assert data.risk_score == 0
        assert data.verdict == "UNKNOWN"
        assert data.findings == []

    def test_build_without_scorer_object(self):
        """Test building from pre-serialized result (no RiskScorer instance)"""
        result = {
            "input": "test_hash",
            "type": "hash",
            "summary": {
                "risk_score": 50,
                "verdict": "SUSPICIOUS",
                "confidence": "medium",
                "finding_counts": {"critical": 0, "high": 1},
            },
            "findings": [{"severity": "high", "message": "Flagged", "source": "hash_lookup"}],
            "recommendations": ["Block it"],
            "iocs": {"hashes": ["abc"]},
            "tool_results": {"hash_lookup": {}},
        }
        data = self.gen._build_report_data(result)
        assert data.risk_score == 50
        assert data.verdict == "SUSPICIOUS"
        assert len(data.findings) == 1

    def test_build_preserves_all_ioc_types(self):
        self.scorer.add_finding(Severity.LOW, "Minor", "test")
        result = {
            "input": "test",
            "type": "file",
            "scorer": self.scorer,
            "iocs": {
                "hashes": ["aaa"],
                "domains": ["evil.com"],
                "ips": ["1.2.3.4"],
                "urls": ["http://bad.com"],
                "emails": ["bad@evil.com"],
            },
            "tool_results": {},
        }
        data = self.gen._build_report_data(result)
        assert data.iocs["hashes"] == ["aaa"]
        assert data.iocs["domains"] == ["evil.com"]
        assert data.iocs["ips"] == ["1.2.3.4"]
        assert data.iocs["urls"] == ["http://bad.com"]
        assert data.iocs["emails"] == ["bad@evil.com"]


class TestHTMLGeneration:
    """Test HTML report generation"""

    def setup_method(self):
        self.gen = ReportGenerator()
        self.scorer = RiskScorer()

    def _make_result(self, severity=Severity.HIGH, iocs=None):
        self.scorer.add_finding(severity, "Test finding", "test_tool")
        return {
            "input": "test_input",
            "type": "hash",
            "scorer": self.scorer,
            "iocs": iocs or {"hashes": ["abc123"], "domains": [], "ips": [], "urls": []},
            "tool_results": {"hash_lookup": {"verdict": "suspicious"}},
        }

    def test_html_is_valid_structure(self):
        result = self._make_result()
        data = self.gen._build_report_data(result)
        html = self.gen.format_html(data)
        assert "<!DOCTYPE html>" in html
        assert "<html" in html
        assert "</html>" in html
        assert "<head>" in html
        assert "<body>" in html

    def test_html_contains_inline_css(self):
        result = self._make_result()
        data = self.gen._build_report_data(result)
        html = self.gen.format_html(data)
        assert "<style>" in html

    def test_html_no_external_stylesheets(self):
        result = self._make_result()
        data = self.gen._build_report_data(result)
        html = self.gen.format_html(data)
        assert '<link rel="stylesheet"' not in html

    def test_html_contains_verdict(self):
        result = self._make_result(Severity.CRITICAL)
        data = self.gen._build_report_data(result)
        html = self.gen.format_html(data)
        assert data.verdict in html

    def test_html_contains_risk_score(self):
        result = self._make_result()
        data = self.gen._build_report_data(result)
        html = self.gen.format_html(data)
        assert str(data.risk_score) in html
        assert "/100" in html

    def test_html_contains_findings(self):
        result = self._make_result()
        data = self.gen._build_report_data(result)
        html = self.gen.format_html(data)
        assert "Test finding" in html

    def test_html_defangs_domains(self):
        iocs = {"domains": ["evil.com"], "hashes": [], "ips": [], "urls": []}
        result = self._make_result(iocs=iocs)
        data = self.gen._build_report_data(result)
        html = self.gen.format_html(data)
        assert "evil[.]com" in html

    def test_html_defangs_urls(self):
        iocs = {"urls": ["http://evil.com/malware"], "hashes": [], "domains": [], "ips": []}
        result = self._make_result(iocs=iocs)
        data = self.gen._build_report_data(result)
        html = self.gen.format_html(data)
        assert "hxxp://" in html

    def test_html_contains_recommendations(self):
        result = self._make_result(Severity.CRITICAL)
        data = self.gen._build_report_data(result)
        html = self.gen.format_html(data)
        assert "Recommended Actions" in html

    def test_html_contains_metadata(self):
        result = self._make_result()
        data = self.gen._build_report_data(result)
        html = self.gen.format_html(data)
        assert "test_input" in html
        assert "hash" in html

    def test_html_no_external_scripts(self):
        result = self._make_result()
        data = self.gen._build_report_data(result)
        html = self.gen.format_html(data)
        assert "<script src=" not in html

    def test_html_responsive_meta(self):
        result = self._make_result()
        data = self.gen._build_report_data(result)
        html = self.gen.format_html(data)
        assert "viewport" in html

    def test_html_escapes_special_chars(self):
        """Test that special HTML characters are escaped"""
        self.scorer.add_finding(Severity.HIGH, '<script>alert("xss")</script>', "test")
        result = {"input": "<b>bad</b>", "type": "hash", "scorer": self.scorer, "iocs": {}, "tool_results": {}}
        data = self.gen._build_report_data(result)
        html = self.gen.format_html(data)
        assert "<script>alert" not in html
        assert "&lt;script&gt;" in html

    def test_html_empty_findings(self):
        result = {"input": "clean", "type": "hash", "scorer": self.scorer, "iocs": {}, "tool_results": {}}
        data = self.gen._build_report_data(result)
        html = self.gen.format_html(data)
        assert "No findings to report" in html

    def test_html_empty_iocs(self):
        result = {"input": "clean", "type": "hash", "scorer": self.scorer, "iocs": {}, "tool_results": {}}
        data = self.gen._build_report_data(result)
        html = self.gen.format_html(data)
        assert "No indicators of compromise" in html


class TestMarkdownGeneration:
    """Test Markdown report generation"""

    def setup_method(self):
        self.gen = ReportGenerator()
        self.scorer = RiskScorer()

    def _make_result(self, severity=Severity.HIGH, iocs=None, workflow=False):
        self.scorer.add_finding(severity, "Test finding", "test_tool")
        result = {
            "input": "test_input",
            "type": "hash",
            "scorer": self.scorer,
            "iocs": iocs or {"hashes": ["abc123"], "domains": [], "ips": [], "urls": []},
            "tool_results": {"hash_lookup": {"verdict": "suspicious"}},
        }
        if workflow:
            result["workflow"] = "test-workflow"
            result["steps_completed"] = 3
            result["steps_total"] = 5
            result["step_results"] = [
                {"name": "step1", "success": True, "duration_ms": 100, "error": None},
                {"name": "step2", "success": False, "duration_ms": 200, "error": "timeout"},
            ]
            result["duration_seconds"] = 1.5
        return result

    def test_markdown_has_title(self):
        result = self._make_result()
        data = self.gen._build_report_data(result)
        md = self.gen.format_markdown(data)
        assert "# SecOps Helper" in md

    def test_markdown_has_verdict(self):
        result = self._make_result()
        data = self.gen._build_report_data(result)
        md = self.gen.format_markdown(data)
        assert data.verdict in md

    def test_markdown_has_risk_score(self):
        result = self._make_result()
        data = self.gen._build_report_data(result)
        md = self.gen.format_markdown(data)
        assert str(data.risk_score) in md

    def test_markdown_has_findings_section(self):
        result = self._make_result()
        data = self.gen._build_report_data(result)
        md = self.gen.format_markdown(data)
        assert "## Findings" in md
        assert "Test finding" in md

    def test_markdown_has_ioc_table(self):
        iocs = {"hashes": ["abc123"], "domains": ["evil.com"]}
        result = self._make_result(iocs=iocs)
        data = self.gen._build_report_data(result)
        md = self.gen.format_markdown(data)
        assert "## Indicators of Compromise" in md
        assert "evil[.]com" in md

    def test_markdown_has_recommendations(self):
        result = self._make_result(Severity.CRITICAL)
        data = self.gen._build_report_data(result)
        md = self.gen.format_markdown(data)
        assert "## Recommended Actions" in md

    def test_markdown_has_timeline_for_workflow(self):
        result = self._make_result(workflow=True)
        data = self.gen._build_report_data(result)
        md = self.gen.format_markdown(data)
        assert "## Analysis Timeline" in md
        assert "step1" in md
        assert "step2" in md

    def test_markdown_timeline_shows_failure(self):
        result = self._make_result(workflow=True)
        data = self.gen._build_report_data(result)
        md = self.gen.format_markdown(data)
        assert "Failed" in md

    def test_markdown_defangs_urls(self):
        iocs = {"urls": ["http://evil.com/payload"], "hashes": [], "domains": [], "ips": []}
        result = self._make_result(iocs=iocs)
        data = self.gen._build_report_data(result)
        md = self.gen.format_markdown(data)
        assert "hxxp://" in md

    def test_markdown_has_metadata(self):
        result = self._make_result()
        data = self.gen._build_report_data(result)
        md = self.gen.format_markdown(data)
        assert "## Metadata" in md
        assert "test_input" in md

    def test_markdown_empty_findings(self):
        result = {"input": "clean", "type": "hash", "scorer": self.scorer, "iocs": {}, "tool_results": {}}
        data = self.gen._build_report_data(result)
        md = self.gen.format_markdown(data)
        assert "No findings to report" in md

    def test_markdown_tools_timeline_when_no_steps(self):
        """Test that tools are shown as timeline when no step_results"""
        result = self._make_result()
        data = self.gen._build_report_data(result)
        md = self.gen.format_markdown(data)
        assert "hash_lookup" in md
        assert "Executed" in md


class TestFileGeneration:
    """Test file writing and naming"""

    def setup_method(self):
        self.gen = ReportGenerator()
        self.scorer = RiskScorer()
        self.scorer.add_finding(Severity.HIGH, "Test", "test")

    def _make_result(self):
        return {"input": "test.eml", "type": "email", "scorer": self.scorer, "iocs": {}, "tool_results": {}}

    def test_generate_html_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "report.html")
            result = self._make_result()
            path = self.gen.generate(result, "html", output)
            assert Path(path).exists()
            content = Path(path).read_text(encoding="utf-8")
            assert "<!DOCTYPE html>" in content

    def test_generate_markdown_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "report.md")
            result = self._make_result()
            path = self.gen.generate(result, "markdown", output)
            assert Path(path).exists()
            content = Path(path).read_text(encoding="utf-8")
            assert "# SecOps Helper" in content

    def test_auto_generated_filename_html(self):
        result = self._make_result()
        data = self.gen._build_report_data(result)
        name = self.gen._generate_filename(data, ".html")
        assert name.startswith("secops_report_")
        assert name.endswith(".html")
        assert "email" in name

    def test_auto_generated_filename_md(self):
        result = self._make_result()
        data = self.gen._build_report_data(result)
        name = self.gen._generate_filename(data, ".md")
        assert name.endswith(".md")

    def test_invalid_format_raises(self):
        result = self._make_result()
        with pytest.raises(ValueError):
            self.gen.generate(result, "pdf")

    def test_md_alias_for_markdown(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "report.md")
            result = self._make_result()
            path = self.gen.generate(result, "md", output)
            assert Path(path).exists()
            content = Path(path).read_text(encoding="utf-8")
            assert "# SecOps Helper" in content

    def test_generate_returns_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output = os.path.join(tmpdir, "out.html")
            result = self._make_result()
            path = self.gen.generate(result, "html", output)
            assert path == output


class TestDefanging:
    """Test IOC defanging in reports"""

    def setup_method(self):
        self.gen = ReportGenerator()

    def test_defang_http(self):
        assert self.gen._defang("http://evil.com") == "hxxp://evil[.]com"

    def test_defang_https(self):
        assert self.gen._defang("https://evil.com") == "hxxps://evil[.]com"

    def test_defang_domain(self):
        assert self.gen._defang("evil.com") == "evil[.]com"

    def test_defang_ip(self):
        assert self.gen._defang("192.168.1.1") == "192[.]168[.]1[.]1"

    def test_defang_preserves_hash(self):
        h = "44d88612fea8a8f36de82e1278abb02f"
        assert self.gen._defang(h) == h

    def test_defang_url_with_path(self):
        assert self.gen._defang("http://evil.com/malware.exe") == "hxxp://evil[.]com/malware[.]exe"


class TestExecSummary:
    """Test executive summary generation"""

    def setup_method(self):
        self.gen = ReportGenerator()

    def _make_data(self, verdict="SUSPICIOUS", score=50, findings=None, iocs=None, finding_counts=None):
        return ReportData(
            input_value="test.eml",
            input_type="email",
            timestamp="2025-01-20 10:00:00 UTC",
            risk_score=score,
            verdict=verdict,
            confidence="medium",
            findings=findings or [],
            finding_counts=finding_counts or {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            iocs=iocs or {},
            recommendations=[],
            tool_results={},
            tools_executed=["eml_parser"],
        )

    def test_summary_mentions_verdict(self):
        data = self._make_data(verdict="MALICIOUS", score=85)
        summary = self.gen._generate_executive_summary(data)
        assert "MALICIOUS" in summary

    def test_summary_mentions_input_type(self):
        data = self._make_data()
        summary = self.gen._generate_executive_summary(data)
        assert "email" in summary

    def test_summary_mentions_score(self):
        data = self._make_data(score=75)
        summary = self.gen._generate_executive_summary(data)
        assert "75" in summary

    def test_summary_mentions_critical_findings(self):
        data = self._make_data(
            findings=[{"severity": "critical", "message": "Hash malicious", "source": "test"}],
            finding_counts={"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0},
        )
        # Override the counts properly
        data.finding_counts = {"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0}
        summary = self.gen._generate_executive_summary(data)
        assert "critical" in summary.lower()

    def test_summary_mentions_ioc_count(self):
        data = self._make_data(iocs={"hashes": ["a", "b", "c"], "domains": ["evil.com"]})
        summary = self.gen._generate_executive_summary(data)
        assert "4" in summary  # 3 hashes + 1 domain

    def test_summary_mentions_workflow(self):
        data = self._make_data()
        data.workflow_name = "phishing-email"
        summary = self.gen._generate_executive_summary(data)
        assert "phishing-email" in summary

    def test_summary_no_findings(self):
        data = self._make_data(verdict="UNKNOWN", score=0, findings=[])
        summary = self.gen._generate_executive_summary(data)
        assert "No significant findings" in summary


class TestVerdictDescription:
    """Test verdict description generation"""

    def setup_method(self):
        self.gen = ReportGenerator()

    def test_malicious(self):
        desc = self.gen._verdict_description("MALICIOUS")
        assert "malicious" in desc.lower()

    def test_suspicious(self):
        desc = self.gen._verdict_description("SUSPICIOUS")
        assert "suspicious" in desc.lower()

    def test_clean(self):
        desc = self.gen._verdict_description("CLEAN")
        assert "No malicious" in desc

    def test_unknown(self):
        desc = self.gen._verdict_description("UNKNOWN")
        assert "Insufficient" in desc

    def test_invalid_verdict(self):
        desc = self.gen._verdict_description("INVALID")
        assert "could not be determined" in desc
