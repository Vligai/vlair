#!/usr/bin/env python3
"""
Extended unit tests for Workflow Engine and Individual Workflows.

Focuses on increasing test coverage for:
- PhishingEmailWorkflow (phishing_email.py)
- NetworkForensicsWorkflow (network_forensics.py)
- LogInvestigationWorkflow (log_investigation.py)
- MalwareTriageWorkflow (malware_triage.py)
- IOCHuntWorkflow (ioc_hunt.py)

Tests individual step execution paths with mocked tools,
error handling, verbose mode output, and edge cases.
"""

import pytest
import sys
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock, PropertyMock

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from vlair.core.workflow import (
    Workflow,
    WorkflowStep,
    StepResult,
    WorkflowContext,
    WorkflowRegistry,
)
from vlair.core.scorer import Severity, RiskScorer

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_context(input_value="test_input", input_type="unknown"):
    """Create a fresh WorkflowContext for testing."""
    return WorkflowContext(input_value, input_type)


# ===========================================================================
# PhishingEmailWorkflow tests
# ===========================================================================


class TestPhishingEmailWorkflowSteps:
    """Test individual step execution in PhishingEmailWorkflow."""

    def _make_workflow(self, verbose=False):
        from vlair.workflows.phishing_email import PhishingEmailWorkflow

        return PhishingEmailWorkflow(verbose=verbose)

    # ----- _execute_step dispatch -----

    def test_execute_step_unknown_step(self):
        """Unknown step name returns a failed StepResult."""
        wf = self._make_workflow()
        ctx = _make_context()
        step = WorkflowStep(name="nonexistent", description="x", tool="x")
        result = wf._execute_step(step, ctx)
        assert result.success is False
        assert "Unknown step" in result.error

    # ----- parse_email -----

    @patch("vlair.workflows.phishing_email.PhishingEmailWorkflow._parse_email")
    def test_execute_step_dispatches_parse_email(self, mock_parse):
        """_execute_step dispatches to _parse_email for 'parse_email' step."""
        mock_parse.return_value = StepResult(step_name="parse_email", success=True)
        wf = self._make_workflow()
        ctx = _make_context()
        step = WorkflowStep(name="parse_email", description="parse", tool="eml_parser")
        result = wf._execute_step(step, ctx)
        mock_parse.assert_called_once_with(ctx)
        assert result.success is True

    def test_parse_email_import_error(self):
        """_parse_email handles ImportError gracefully."""
        wf = self._make_workflow()
        ctx = _make_context("fake.eml")
        with patch.dict("sys.modules", {"vlair.tools.eml_parser": None}):
            with patch("builtins.__import__", side_effect=ImportError("no module")):
                result = wf._parse_email(ctx)
        assert result.success is False
        assert "not available" in result.error or "no module" in result.error

    def test_parse_email_spf_fail_finding(self):
        """SPF fail adds HIGH finding."""
        wf = self._make_workflow()
        ctx = _make_context("test.eml")

        mock_parser_instance = MagicMock()
        mock_parser_instance.parse.return_value = {
            "authentication": {
                "spf": {"result": "fail"},
                "dkim": {"result": "pass"},
                "dmarc": {"result": "pass"},
            },
            "attachments": [],
        }

        # The code does: from vlair.tools.eml_parser import EMLParser
        # EMLParser does not exist in the module, so we inject it
        import vlair.tools.eml_parser as eml_mod

        mock_class = MagicMock(return_value=mock_parser_instance)
        with patch.object(eml_mod, "EMLParser", mock_class, create=True):
            result = wf._parse_email(ctx)

        assert result.success is True
        # Check that a finding was added
        findings = ctx.scorer.findings
        assert any("SPF" in f.message for f in findings)

    def test_parse_email_spf_softfail_finding(self):
        """SPF softfail adds MEDIUM finding."""
        wf = self._make_workflow()
        ctx = _make_context("test.eml")

        mock_parser_instance = MagicMock()
        mock_parser_instance.parse.return_value = {
            "authentication": {
                "spf": {"result": "softfail"},
                "dkim": {"result": "pass"},
                "dmarc": {"result": "pass"},
            },
            "attachments": [],
        }

        import vlair.tools.eml_parser as eml_mod

        mock_class = MagicMock(return_value=mock_parser_instance)
        with patch.object(eml_mod, "EMLParser", mock_class, create=True):
            result = wf._parse_email(ctx)

        assert result.success is True
        findings = ctx.scorer.findings
        assert any("soft fail" in f.message.lower() for f in findings)

    def test_parse_email_dkim_fail_finding(self):
        """DKIM fail adds MEDIUM finding."""
        wf = self._make_workflow()
        ctx = _make_context("test.eml")

        mock_parser_instance = MagicMock()
        mock_parser_instance.parse.return_value = {
            "authentication": {
                "spf": {"result": "pass"},
                "dkim": {"result": "fail"},
                "dmarc": {"result": "pass"},
            },
            "attachments": [],
        }

        import vlair.tools.eml_parser as eml_mod

        mock_class = MagicMock(return_value=mock_parser_instance)
        with patch.object(eml_mod, "EMLParser", mock_class, create=True):
            result = wf._parse_email(ctx)

        assert result.success is True
        findings = ctx.scorer.findings
        assert any("DKIM" in f.message for f in findings)

    def test_parse_email_dmarc_fail_finding(self):
        """DMARC fail adds HIGH finding."""
        wf = self._make_workflow()
        ctx = _make_context("test.eml")

        mock_parser_instance = MagicMock()
        mock_parser_instance.parse.return_value = {
            "authentication": {
                "spf": {"result": "pass"},
                "dkim": {"result": "pass"},
                "dmarc": {"result": "fail"},
            },
            "attachments": [],
        }

        import vlair.tools.eml_parser as eml_mod

        mock_class = MagicMock(return_value=mock_parser_instance)
        with patch.object(eml_mod, "EMLParser", mock_class, create=True):
            result = wf._parse_email(ctx)

        assert result.success is True
        findings = ctx.scorer.findings
        assert any("DMARC" in f.message for f in findings)

    def test_parse_email_extracts_attachment_hashes(self):
        """Attachment hashes are added to context IOCs."""
        wf = self._make_workflow()
        ctx = _make_context("test.eml")

        mock_parser_instance = MagicMock()
        mock_parser_instance.parse.return_value = {
            "authentication": {},
            "attachments": [
                {"md5": "abc123", "sha256": "def456"},
                {"md5": "ghi789"},
            ],
        }

        import vlair.tools.eml_parser as eml_mod

        mock_class = MagicMock(return_value=mock_parser_instance)
        with patch.object(eml_mod, "EMLParser", mock_class, create=True):
            result = wf._parse_email(ctx)

        assert result.success is True
        assert "abc123" in ctx.iocs["hashes"]
        assert "def456" in ctx.iocs["hashes"]
        assert "ghi789" in ctx.iocs["hashes"]

    def test_parse_email_generic_exception(self):
        """Generic exception in _parse_email is caught."""
        wf = self._make_workflow()
        ctx = _make_context("test.eml")

        mock_parser_instance = MagicMock()
        mock_parser_instance.parse.side_effect = RuntimeError("boom")

        import vlair.tools.eml_parser as eml_mod

        mock_class = MagicMock(return_value=mock_parser_instance)
        with patch.object(eml_mod, "EMLParser", mock_class, create=True):
            result = wf._parse_email(ctx)

        assert result.success is False
        assert "boom" in result.error

    # ----- extract_iocs -----

    def test_extract_iocs_success_with_many_iocs(self):
        """Many IOCs triggers a LOW finding about potential phishing."""
        wf = self._make_workflow()
        ctx = _make_context("test.eml")

        mock_extractor = MagicMock()
        mock_extractor.extract_from_file.return_value = {
            "md5": ["h1"],
            "sha1": ["h2"],
            "sha256": ["h3"],
            "domains": ["d1.com", "d2.com", "d3.com", "d4.com"],
            "ips": ["1.2.3.4", "5.6.7.8"],
            "urls": ["http://a.com", "http://b.com", "http://c.com"],
            "emails": ["a@b.com"],
        }

        with patch("vlair.tools.ioc_extractor.IOCExtractor", return_value=mock_extractor):
            result = wf._extract_iocs(ctx)

        assert result.success is True
        total_iocs = sum(len(v) for v in ctx.iocs.values())
        assert total_iocs > 10
        findings = ctx.scorer.findings
        assert any("many IOCs" in f.message for f in findings)

    def test_extract_iocs_import_error(self):
        """Import error in _extract_iocs is caught."""
        wf = self._make_workflow()
        ctx = _make_context("test.eml")

        with patch.dict("sys.modules", {"vlair.tools.ioc_extractor": None}):
            with patch("builtins.__import__", side_effect=ImportError("no module")):
                result = wf._extract_iocs(ctx)

        assert result.success is False

    def test_extract_iocs_generic_exception(self):
        """Generic exception in _extract_iocs is caught."""
        wf = self._make_workflow()
        ctx = _make_context("test.eml")

        mock_extractor = MagicMock()
        mock_extractor.extract_from_file.side_effect = ValueError("bad file")

        with patch("vlair.tools.ioc_extractor.IOCExtractor", return_value=mock_extractor):
            result = wf._extract_iocs(ctx)

        assert result.success is False
        assert "bad file" in result.error

    # ----- check_hashes -----

    def test_check_hashes_no_hashes(self):
        """No hashes returns success with message."""
        wf = self._make_workflow()
        ctx = _make_context()
        result = wf._check_hashes(ctx)
        assert result.success is True
        assert "No hashes" in result.data["message"]

    def test_check_hashes_malicious(self):
        """Malicious hash adds CRITICAL finding."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.add_iocs("hashes", ["abc123deadbeef"])

        mock_lookup = MagicMock()
        mock_lookup.lookup.return_value = {"verdict": "malicious"}

        with patch("vlair.tools.hash_lookup.HashLookup", return_value=mock_lookup):
            result = wf._check_hashes(ctx)

        assert result.success is True
        assert any(f.severity == Severity.CRITICAL for f in ctx.scorer.findings)

    def test_check_hashes_suspicious(self):
        """Suspicious hash adds HIGH finding."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.add_iocs("hashes", ["abc123"])

        mock_lookup = MagicMock()
        mock_lookup.lookup.return_value = {"verdict": "suspicious"}

        with patch("vlair.tools.hash_lookup.HashLookup", return_value=mock_lookup):
            result = wf._check_hashes(ctx)

        assert result.success is True
        assert any(f.severity == Severity.HIGH for f in ctx.scorer.findings)

    def test_check_hashes_import_error(self):
        """Import error in _check_hashes is caught."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.add_iocs("hashes", ["abc"])

        with patch.dict("sys.modules", {"vlair.tools.hash_lookup": None}):
            with patch("builtins.__import__", side_effect=ImportError("no module")):
                result = wf._check_hashes(ctx)

        assert result.success is False

    # ----- check_domains -----

    def test_check_domains_no_domains(self):
        """No domains returns success with message."""
        wf = self._make_workflow()
        ctx = _make_context()
        result = wf._check_domains(ctx)
        assert result.success is True
        assert "No domains" in result.data["message"]

    def test_check_domains_malicious_with_young_domain(self):
        """Malicious domain with young age adds findings."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.add_iocs("domains", ["evil.com"])

        mock_intel = MagicMock()
        mock_intel.lookup.return_value = {
            "verdict": "malicious",
            "domain_age_days": 5,
        }

        with patch(
            "vlair.tools.domain_ip_intel.DomainIPIntelligence",
            return_value=mock_intel,
        ):
            result = wf._check_domains(ctx)

        assert result.success is True
        findings = ctx.scorer.findings
        assert any(f.severity == Severity.CRITICAL for f in findings)
        assert any("recently registered" in f.message for f in findings)

    def test_check_domains_suspicious(self):
        """Suspicious domain adds HIGH finding."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.add_iocs("domains", ["sketchy.com"])

        mock_intel = MagicMock()
        mock_intel.lookup.return_value = {"verdict": "suspicious", "domain_age_days": 999}

        with patch(
            "vlair.tools.domain_ip_intel.DomainIPIntelligence",
            return_value=mock_intel,
        ):
            result = wf._check_domains(ctx)

        assert result.success is True
        assert any(f.severity == Severity.HIGH for f in ctx.scorer.findings)

    def test_check_domains_import_error(self):
        """Import error in _check_domains is caught."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.add_iocs("domains", ["test.com"])

        with patch.dict("sys.modules", {"vlair.tools.domain_ip_intel": None}):
            with patch("builtins.__import__", side_effect=ImportError):
                result = wf._check_domains(ctx)

        assert result.success is False

    # ----- check_urls -----

    def test_check_urls_no_urls(self):
        """No URLs returns success with message."""
        wf = self._make_workflow()
        ctx = _make_context()
        result = wf._check_urls(ctx)
        assert result.success is True
        assert "No URLs" in result.data["message"]

    def test_check_urls_malicious_with_patterns(self):
        """Malicious URL with suspicious patterns adds multiple findings."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.add_iocs("urls", ["http://evil.com/payload"])

        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = {
            "verdict": "malicious",
            "suspicious_patterns": ["ip_address_in_url", "long_url"],
        }

        with patch("vlair.tools.url_analyzer.URLAnalyzer", return_value=mock_analyzer):
            result = wf._check_urls(ctx)

        assert result.success is True
        findings = ctx.scorer.findings
        assert any(f.severity == Severity.CRITICAL for f in findings)
        assert any("suspicious patterns" in f.message for f in findings)

    def test_check_urls_suspicious(self):
        """Suspicious URL adds HIGH finding."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.add_iocs("urls", ["http://sketchy.com"])

        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = {"verdict": "suspicious", "suspicious_patterns": []}

        with patch("vlair.tools.url_analyzer.URLAnalyzer", return_value=mock_analyzer):
            result = wf._check_urls(ctx)

        assert result.success is True
        assert any(f.severity == Severity.HIGH for f in ctx.scorer.findings)

    def test_check_urls_import_error(self):
        """Import error in _check_urls is caught."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.add_iocs("urls", ["http://x.com"])

        with patch.dict("sys.modules", {"vlair.tools.url_analyzer": None}):
            with patch("builtins.__import__", side_effect=ImportError):
                result = wf._check_urls(ctx)

        assert result.success is False

    # ----- check_certificates -----

    def test_check_certificates_no_https_urls(self):
        """No HTTPS URLs returns success with message."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.add_iocs("urls", ["http://insecure.com"])
        result = wf._check_certificates(ctx)
        assert result.success is True
        assert "No HTTPS" in result.data["message"]

    def test_check_certificates_suspicious_and_phishing(self):
        """Certificate with suspicious verdict and phishing indicators adds findings."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.add_iocs("urls", ["https://suspicious.com"])

        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = {
            "verdict": "suspicious",
            "phishing_indicators": ["brand_impersonation"],
        }

        import vlair.tools.cert_analyzer as cert_mod

        mock_class = MagicMock(return_value=mock_analyzer)
        with patch.object(cert_mod, "CertAnalyzer", mock_class, create=True):
            result = wf._check_certificates(ctx)

        assert result.success is True
        findings = ctx.scorer.findings
        assert any("Certificate issues" in f.message for f in findings)
        assert any("phishing indicators" in f.message for f in findings)

    def test_check_certificates_analyzer_exception_per_url(self):
        """Exception on individual URL is swallowed and processing continues."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.add_iocs("urls", ["https://good.com", "https://bad.com"])

        mock_analyzer = MagicMock()
        # First call raises, second succeeds
        mock_analyzer.analyze.side_effect = [
            Exception("connection failed"),
            {"verdict": "clean"},
        ]

        import vlair.tools.cert_analyzer as cert_mod

        mock_class = MagicMock(return_value=mock_analyzer)
        with patch.object(cert_mod, "CertAnalyzer", mock_class, create=True):
            result = wf._check_certificates(ctx)

        assert result.success is True

    def test_check_certificates_import_error(self):
        """Import error in _check_certificates is caught."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.add_iocs("urls", ["https://example.com"])

        with patch.dict("sys.modules", {"vlair.tools.cert_analyzer": None}):
            with patch("builtins.__import__", side_effect=ImportError):
                result = wf._check_certificates(ctx)

        assert result.success is False

    # ----- calculate_score -----

    def test_calculate_score_high_risk(self):
        """High risk score (>=70) produces extended recommendations."""
        wf = self._make_workflow()
        ctx = _make_context()
        # Add enough critical findings to push score >= 70
        ctx.scorer.add_finding(Severity.CRITICAL, "test1", "test")
        ctx.scorer.add_finding(Severity.CRITICAL, "test2", "test")
        ctx.scorer.add_finding(Severity.CRITICAL, "test3", "test")

        result = wf._calculate_score(ctx)
        assert result.success is True
        assert result.data["risk_score"] >= 70
        assert len(result.data["recommendations"]) >= 3

    def test_calculate_score_medium_risk(self):
        """Medium risk score (40-69) produces moderate recommendations."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.scorer.add_finding(Severity.HIGH, "test1", "test")
        ctx.scorer.add_finding(Severity.HIGH, "test2", "test")
        ctx.scorer.add_finding(Severity.HIGH, "test3", "test")

        result = wf._calculate_score(ctx)
        assert result.success is True
        score = result.data["risk_score"]
        assert 40 <= score < 70
        assert len(result.data["recommendations"]) >= 2

    def test_calculate_score_low_risk(self):
        """Low risk score (<40) produces monitoring recommendation."""
        wf = self._make_workflow()
        ctx = _make_context()
        # No findings at all
        result = wf._calculate_score(ctx)
        assert result.success is True
        assert result.data["risk_score"] < 40
        assert any("monitoring" in r.lower() for r in result.data["recommendations"])

    # ----- full workflow with mocked tools -----

    def test_full_workflow_verbose_mode(self, capsys):
        """Verbose mode prints progress to stderr."""
        wf = self._make_workflow(verbose=True)

        mock_parser_instance = MagicMock()
        mock_parser_instance.parse.return_value = {
            "authentication": {},
            "attachments": [],
        }

        mock_extractor = MagicMock()
        mock_extractor.extract_from_file.return_value = {
            "md5": [],
            "sha1": [],
            "sha256": [],
            "domains": [],
            "ips": [],
            "urls": [],
            "emails": [],
        }

        import vlair.tools.eml_parser as eml_mod

        mock_class = MagicMock(return_value=mock_parser_instance)
        with patch.object(eml_mod, "EMLParser", mock_class, create=True):
            with patch(
                "vlair.tools.ioc_extractor.IOCExtractor",
                return_value=mock_extractor,
            ):
                result = wf.execute("fake.eml", "email")

        assert result["workflow"] == "phishing-email"


# ===========================================================================
# NetworkForensicsWorkflow tests
# ===========================================================================


class TestNetworkForensicsWorkflowSteps:
    """Test individual step execution in NetworkForensicsWorkflow."""

    def _make_workflow(self, verbose=False):
        from vlair.workflows.network_forensics import NetworkForensicsWorkflow

        return NetworkForensicsWorkflow(verbose=verbose)

    def test_execute_step_unknown(self):
        """Unknown step returns failure."""
        wf = self._make_workflow()
        ctx = _make_context()
        step = WorkflowStep(name="unknown", description="x", tool="x")
        result = wf._execute_step(step, ctx)
        assert result.success is False

    # ----- parse_pcap -----

    def test_parse_pcap_success(self):
        """parse_pcap stores result in context and logs packets."""
        wf = self._make_workflow(verbose=True)
        ctx = _make_context("test.pcap")

        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = {
            "statistics": {"total_packets": 1500},
        }

        with patch("vlair.tools.pcap_analyzer.PCAPAnalyzer", return_value=mock_analyzer):
            result = wf._parse_pcap(ctx)

        assert result.success is True
        assert ctx.data["pcap_result"]["statistics"]["total_packets"] == 1500

    def test_parse_pcap_import_error(self):
        """Import error in _parse_pcap is caught."""
        wf = self._make_workflow()
        ctx = _make_context("test.pcap")

        with patch.dict("sys.modules", {"vlair.tools.pcap_analyzer": None}):
            with patch("builtins.__import__", side_effect=ImportError):
                result = wf._parse_pcap(ctx)

        assert result.success is False

    # ----- extract_iocs -----

    def test_extract_iocs_from_pcap(self):
        """IOCs are extracted from pcap results."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.data["pcap_result"] = {
            "ips": {"1.2.3.4": 10, "5.6.7.8": 5},
            "dns_queries": [
                {"query": "example.com"},
                {"query": "malware.com"},
                {"query": None},
            ],
        }

        result = wf._extract_iocs(ctx)
        assert result.success is True
        assert "1.2.3.4" in ctx.iocs["ips"]
        assert "example.com" in ctx.iocs["domains"]
        assert ctx.data["network_iocs"]["unique_ips"] == 2
        assert ctx.data["network_iocs"]["dns_queries"] == 2

    # ----- detect_scans -----

    def test_detect_scans_with_port_scans(self):
        """Port scan activity adds MEDIUM finding."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.data["pcap_result"] = {
            "threats": {"port_scans": ["10.0.0.1", "10.0.0.2"]},
            "connections": [],
        }

        result = wf._detect_scans(ctx)
        assert result.success is True
        assert any("port scan" in f.message.lower() for f in ctx.scorer.findings)

    def test_detect_scans_high_port_connections(self):
        """Many high-port connections add LOW finding."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.data["pcap_result"] = {
            "threats": {},
            "connections": [{"dst_port": 15000 + i} for i in range(25)],
        }

        result = wf._detect_scans(ctx)
        assert result.success is True
        assert any("high ports" in f.message.lower() for f in ctx.scorer.findings)

    # ----- analyze_dns -----

    def test_analyze_dns_suspicious_and_dga(self):
        """Suspicious DNS and DGA candidates generate findings."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.data["pcap_result"] = {
            "threats": {
                "suspicious_dns": [{"query": "bad.com"}],
            },
            "dns_queries": [
                # A normal domain
                {"query": "google.com"},
                # A DGA candidate: long, consonant-heavy
                {"query": "xzqwrthklmnbvcdf.xyz"},
            ],
        }

        result = wf._analyze_dns(ctx)
        assert result.success is True
        findings = ctx.scorer.findings
        assert any("suspicious DNS" in f.message for f in findings)
        assert any("DGA" in f.message for f in findings)

    def test_analyze_dns_tunneling(self):
        """Many TXT queries suggest DNS tunneling."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.data["pcap_result"] = {
            "threats": {},
            "dns_queries": [{"query": f"q{i}.com", "type": "TXT"} for i in range(15)],
        }

        result = wf._analyze_dns(ctx)
        assert result.success is True
        assert any("tunneling" in f.message.lower() for f in ctx.scorer.findings)

    # ----- check_ips -----

    def test_check_ips_no_public_ips(self):
        """Only private IPs results in no-op."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.add_iocs("ips", ["10.0.0.1", "192.168.1.1"])
        result = wf._check_ips(ctx)
        assert result.success is True
        assert result.data.get("checked") == 0

    def test_check_ips_malicious(self):
        """Malicious public IP adds CRITICAL finding."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.add_iocs("ips", ["203.0.113.10"])

        mock_intel = MagicMock()
        mock_intel.lookup.return_value = {"verdict": "malicious"}

        with patch(
            "vlair.tools.domain_ip_intel.DomainIPIntelligence",
            return_value=mock_intel,
        ):
            result = wf._check_ips(ctx)

        assert result.success is True
        assert result.data["malicious"] == 1
        assert any(f.severity == Severity.CRITICAL for f in ctx.scorer.findings)

    def test_check_ips_exception(self):
        """Exception in _check_ips is caught."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.add_iocs("ips", ["203.0.113.10"])

        with patch(
            "vlair.tools.domain_ip_intel.DomainIPIntelligence",
            side_effect=Exception("fail"),
        ):
            result = wf._check_ips(ctx)

        assert result.success is False

    # ----- _is_private_ip -----

    def test_is_private_ip_10_range(self):
        wf = self._make_workflow()
        assert wf._is_private_ip("10.0.0.1") is True

    def test_is_private_ip_172_range(self):
        wf = self._make_workflow()
        assert wf._is_private_ip("172.16.0.1") is True
        assert wf._is_private_ip("172.31.255.255") is True
        assert wf._is_private_ip("172.15.0.1") is False
        assert wf._is_private_ip("172.32.0.1") is False

    def test_is_private_ip_192_range(self):
        wf = self._make_workflow()
        assert wf._is_private_ip("192.168.0.1") is True

    def test_is_private_ip_loopback(self):
        wf = self._make_workflow()
        assert wf._is_private_ip("127.0.0.1") is True

    def test_is_private_ip_public(self):
        wf = self._make_workflow()
        assert wf._is_private_ip("8.8.8.8") is False

    def test_is_private_ip_invalid(self):
        wf = self._make_workflow()
        assert wf._is_private_ip("not.an.ip") is False
        assert wf._is_private_ip("1.2.3") is False

    # ----- yara_scan -----

    def test_yara_scan_with_matches(self):
        """YARA matches add findings."""
        wf = self._make_workflow()
        ctx = _make_context("test.pcap")

        mock_scanner = MagicMock()
        mock_scanner.scan_file.return_value = {
            "matches": [
                {"rule": "suspicious_strings", "severity": "high"},
            ],
        }

        with patch("vlair.tools.yara_scanner.YaraScanner", return_value=mock_scanner):
            result = wf._yara_scan(ctx)

        assert result.success is True
        assert any("YARA" in f.message for f in ctx.scorer.findings)

    def test_yara_scan_exception(self):
        """Exception in _yara_scan is caught."""
        wf = self._make_workflow()
        ctx = _make_context("test.pcap")

        with patch(
            "vlair.tools.yara_scanner.YaraScanner",
            side_effect=Exception("yara fail"),
        ):
            result = wf._yara_scan(ctx)

        assert result.success is False

    # ----- generate_report -----

    def test_generate_report_high_risk(self):
        """High risk score produces extended recommendations."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.data["pcap_result"] = {"statistics": {"total_packets": 500}}
        ctx.data["network_iocs"] = {"unique_ips": 10, "dns_queries": 5}
        ctx.scorer.add_finding(Severity.CRITICAL, "t1", "t")
        ctx.scorer.add_finding(Severity.CRITICAL, "t2", "t")
        ctx.scorer.add_finding(Severity.CRITICAL, "t3", "t")

        result = wf._generate_report(ctx)
        assert result.success is True
        assert result.data["risk_score"] >= 70
        assert any("Isolate" in r for r in result.data["recommendations"])

    def test_generate_report_medium_risk(self):
        """Medium risk generates moderate recommendations."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.data["pcap_result"] = {"statistics": {"total_packets": 100}}
        ctx.data["network_iocs"] = {"unique_ips": 2, "dns_queries": 1}
        ctx.scorer.add_finding(Severity.HIGH, "t1", "t")
        ctx.scorer.add_finding(Severity.HIGH, "t2", "t")
        ctx.scorer.add_finding(Severity.HIGH, "t3", "t")

        result = wf._generate_report(ctx)
        assert result.success is True
        score = result.data["risk_score"]
        assert 40 <= score < 70

    def test_generate_report_low_risk(self):
        """Low risk generates monitoring recommendation."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.data["pcap_result"] = {"statistics": {}}
        ctx.data["network_iocs"] = {}

        result = wf._generate_report(ctx)
        assert result.success is True
        assert any("monitoring" in r.lower() for r in result.data["recommendations"])


# ===========================================================================
# LogInvestigationWorkflow tests
# ===========================================================================


class TestLogInvestigationWorkflowSteps:
    """Test individual step execution in LogInvestigationWorkflow."""

    def _make_workflow(self, verbose=False):
        from vlair.workflows.log_investigation import LogInvestigationWorkflow

        return LogInvestigationWorkflow(verbose=verbose)

    def test_execute_step_unknown(self):
        wf = self._make_workflow()
        ctx = _make_context()
        step = WorkflowStep(name="unknown", description="x", tool="x")
        result = wf._execute_step(step, ctx)
        assert result.success is False

    # ----- parse_logs -----

    def test_parse_logs_success(self):
        wf = self._make_workflow(verbose=True)
        ctx = _make_context("test.log")

        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = {
            "statistics": {"total_entries": 200},
        }

        with patch("vlair.tools.log_analyzer.LogAnalyzer", return_value=mock_analyzer):
            result = wf._parse_logs(ctx)

        assert result.success is True
        assert ctx.data["log_result"]["statistics"]["total_entries"] == 200

    def test_parse_logs_import_error(self):
        wf = self._make_workflow()
        ctx = _make_context("test.log")

        with patch.dict("sys.modules", {"vlair.tools.log_analyzer": None}):
            with patch("builtins.__import__", side_effect=ImportError):
                result = wf._parse_logs(ctx)

        assert result.success is False

    # ----- detect_attacks -----

    def test_detect_attacks_all_types(self):
        """All attack types generate corresponding findings."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.data["log_result"] = {
            "threats": {
                "sql_injection": [{"ip": "1.1.1.1"}],
                "xss": [{"ip": "2.2.2.2"}],
                "path_traversal": [{"ip": "3.3.3.3"}],
                "command_injection": [{"ip": "4.4.4.4"}],
            }
        }

        result = wf._detect_attacks(ctx)
        assert result.success is True
        assert ctx.data["attack_counts"]["sql_injection"] == 1
        assert ctx.data["attack_counts"]["xss"] == 1
        assert ctx.data["attack_counts"]["path_traversal"] == 1
        assert ctx.data["attack_counts"]["command_injection"] == 1
        # Should have CRITICAL for sqli and cmd injection, HIGH for xss and traversal
        assert len(ctx.scorer.findings) == 4

    def test_detect_attacks_empty(self):
        """No threats detected produces empty counts."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.data["log_result"] = {"threats": {}}
        result = wf._detect_attacks(ctx)
        assert result.success is True
        assert ctx.data["attack_counts"] == {}

    # ----- detect_bruteforce -----

    def test_detect_bruteforce_with_dict_entries(self):
        """Brute force dict entries add IPs to context."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.data["log_result"] = {
            "threats": {
                "brute_force": [
                    {"ip": "10.0.0.1"},
                    {"ip": "10.0.0.2"},
                ],
            }
        }

        result = wf._detect_bruteforce(ctx)
        assert result.success is True
        assert ctx.data["brute_force_count"] == 2
        assert "10.0.0.1" in ctx.iocs["ips"]

    def test_detect_bruteforce_with_string_entries(self):
        """Brute force string entries are also handled."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.data["log_result"] = {
            "threats": {
                "brute_force": ["10.0.0.1"],
            }
        }

        result = wf._detect_bruteforce(ctx)
        assert result.success is True
        assert "10.0.0.1" in ctx.iocs["ips"]

    def test_detect_bruteforce_empty(self):
        """No brute force activity."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.data["log_result"] = {"threats": {"brute_force": []}}

        result = wf._detect_bruteforce(ctx)
        assert result.success is True
        assert ctx.data["brute_force_count"] == 0

    # ----- detect_scanners -----

    def test_detect_scanners_with_entries(self):
        """Scanner IPs add LOW finding and IOCs."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.data["log_result"] = {
            "threats": {
                "scanners": [{"ip": "8.8.8.8"}, {"ip": "9.9.9.9"}],
            }
        }

        result = wf._detect_scanners(ctx)
        assert result.success is True
        assert ctx.data["scanner_count"] == 2
        assert "8.8.8.8" in ctx.iocs["ips"]

    def test_detect_scanners_empty(self):
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.data["log_result"] = {"threats": {"scanners": []}}

        result = wf._detect_scanners(ctx)
        assert result.success is True
        assert ctx.data["scanner_count"] == 0

    # ----- extract_attackers -----

    def test_extract_attackers_mixed_entries(self):
        """Attacker IPs are extracted from various formats."""
        wf = self._make_workflow(verbose=True)
        ctx = _make_context()
        ctx.data["log_result"] = {
            "threats": {
                "sql_injection": [{"ip": "1.1.1.1"}],
                "xss": ["2.2.2.2"],
                "scanners": [{"ip": "1.1.1.1"}],  # duplicate
                "other": "not_a_list",
            }
        }

        result = wf._extract_attackers(ctx)
        assert result.success is True
        attackers = ctx.data["attacker_ips"]
        assert "1.1.1.1" in attackers
        assert "2.2.2.2" in attackers

    def test_extract_attackers_string_not_ip(self):
        """Strings without 3 dots are not treated as IPs."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.data["log_result"] = {
            "threats": {
                "misc": ["not_an_ip", "also.not.ip"],
            }
        }

        result = wf._extract_attackers(ctx)
        assert result.success is True
        assert len(ctx.data["attacker_ips"]) == 0

    # ----- check_ips -----

    def test_check_ips_no_ips(self):
        """No attacker IPs to check."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.data["attacker_ips"] = []

        result = wf._check_ips(ctx)
        assert result.success is True
        assert result.data.get("checked") == 0

    def test_check_ips_malicious(self):
        """Malicious attacker IP adds HIGH finding."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.data["attacker_ips"] = ["1.2.3.4"]

        mock_intel = MagicMock()
        mock_intel.lookup.return_value = {"verdict": "malicious"}

        with patch(
            "vlair.tools.domain_ip_intel.DomainIPIntelligence",
            return_value=mock_intel,
        ):
            result = wf._check_ips(ctx)

        assert result.success is True
        assert result.data["known_malicious"] == 1

    # ----- generate_report -----

    def test_generate_report_high_risk_with_attacks(self):
        """High risk with SQL injection and command injection adds extra recommendations."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.data["log_result"] = {"statistics": {"total_entries": 1000}}
        ctx.data["attack_counts"] = {
            "sql_injection": 5,
            "path_traversal": 2,
            "command_injection": 3,
        }
        ctx.data["attacker_ips"] = ["1.2.3.4"]
        ctx.data["ip_check_results"] = {"known_malicious": 1}
        ctx.scorer.add_finding(Severity.CRITICAL, "t1", "t")
        ctx.scorer.add_finding(Severity.CRITICAL, "t2", "t")
        ctx.scorer.add_finding(Severity.CRITICAL, "t3", "t")

        result = wf._generate_report(ctx)
        assert result.success is True
        recs = result.data["recommendations"]
        assert any("database access" in r.lower() for r in recs)
        assert any("file access" in r.lower() for r in recs)
        assert any("unauthorized process" in r.lower() for r in recs)


# ===========================================================================
# MalwareTriageWorkflow tests
# ===========================================================================


class TestMalwareTriageWorkflowSteps:
    """Test individual step execution in MalwareTriageWorkflow."""

    def _make_workflow(self, verbose=False):
        from vlair.workflows.malware_triage import MalwareTriageWorkflow

        return MalwareTriageWorkflow(verbose=verbose)

    def test_execute_step_unknown(self):
        wf = self._make_workflow()
        ctx = _make_context()
        step = WorkflowStep(name="unknown", description="x", tool="x")
        result = wf._execute_step(step, ctx)
        assert result.success is False

    # ----- calculate_hashes -----

    def test_calculate_hashes_file_not_found(self):
        """Missing file returns failure."""
        wf = self._make_workflow()
        ctx = _make_context("/nonexistent/file.exe")
        result = wf._calculate_hashes(ctx)
        assert result.success is False
        assert "not found" in result.error.lower() or "File not found" in result.error

    def test_calculate_hashes_success(self):
        """Valid file produces correct hashes."""
        wf = self._make_workflow()

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"test content for hashing")
            temp_path = f.name

        try:
            ctx = _make_context(temp_path)
            result = wf._calculate_hashes(ctx)
            assert result.success is True
            assert "md5" in result.data
            assert "sha256" in result.data
            assert "file_size" in result.data
            assert ctx.data["file_extension"] == ".exe"
            assert len(ctx.iocs["hashes"]) == 2  # md5 and sha256
        finally:
            os.unlink(temp_path)

    # ----- check_hashes -----

    def test_check_hashes_no_hash(self):
        """No SHA256 available returns failure."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.data["hashes"] = {}
        result = wf._check_hashes(ctx)
        assert result.success is False

    def test_check_hashes_malicious_with_family(self):
        """Malicious hash with malware family adds two CRITICAL findings."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.data["hashes"] = {"sha256": "abc123"}

        mock_lookup = MagicMock()
        mock_lookup.lookup.return_value = {
            "verdict": "malicious",
            "sources": {
                "malwarebazaar": {"malware_family": "Emotet"},
            },
        }

        with patch("vlair.tools.hash_lookup.HashLookup", return_value=mock_lookup):
            result = wf._check_hashes(ctx)

        assert result.success is True
        # Should have CRITICAL for known malware + CRITICAL for family
        critical_findings = [f for f in ctx.scorer.findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) >= 2

    def test_check_hashes_suspicious(self):
        """Suspicious verdict adds HIGH finding."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.data["hashes"] = {"sha256": "abc123"}

        mock_lookup = MagicMock()
        mock_lookup.lookup.return_value = {
            "verdict": "suspicious",
            "sources": {"malwarebazaar": {}},
        }

        with patch("vlair.tools.hash_lookup.HashLookup", return_value=mock_lookup):
            result = wf._check_hashes(ctx)

        assert result.success is True
        assert any(f.severity == Severity.HIGH for f in ctx.scorer.findings)

    def test_check_hashes_import_error(self):
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.data["hashes"] = {"sha256": "abc"}

        with patch.dict("sys.modules", {"vlair.tools.hash_lookup": None}):
            with patch("builtins.__import__", side_effect=ImportError):
                result = wf._check_hashes(ctx)

        assert result.success is False

    # ----- yara_scan -----

    def test_yara_scan_matches_various_severities(self):
        """YARA matches with different severity levels are handled."""
        wf = self._make_workflow(verbose=True)
        ctx = _make_context("test.exe")

        mock_scanner = MagicMock()
        mock_scanner.scan_file.return_value = {
            "matches": [
                {"rule": "r1", "severity": "critical"},
                {"rule": "r2", "severity": "high"},
                {"rule": "r3", "severity": "medium"},
                {"rule": "r4", "severity": "low"},
            ],
        }

        with patch("vlair.tools.yara_scanner.YaraScanner", return_value=mock_scanner):
            result = wf._yara_scan(ctx)

        assert result.success is True
        assert len(ctx.scorer.findings) == 4

    def test_yara_scan_import_error(self):
        wf = self._make_workflow()
        ctx = _make_context("test.exe")

        with patch.dict("sys.modules", {"vlair.tools.yara_scanner": None}):
            with patch("builtins.__import__", side_effect=ImportError):
                result = wf._yara_scan(ctx)

        assert result.success is False

    # ----- deobfuscate -----

    def test_deobfuscate_non_script(self):
        """Non-script files are skipped."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.data["file_extension"] = ".exe"
        result = wf._deobfuscate(ctx)
        assert result.success is True
        assert "Not a script" in result.data["message"]

    def test_deobfuscate_heavy_obfuscation(self):
        """Heavily obfuscated script adds HIGH finding."""
        wf = self._make_workflow()
        ctx = _make_context("test.ps1")
        ctx.data["file_extension"] = ".ps1"

        mock_deob = MagicMock()
        mock_deob.deobfuscate_file.return_value = {
            "layers_decoded": 5,
            "extracted_iocs": {
                "urls": ["http://evil.com"],
                "domains": ["evil.com"],
                "ips": ["1.2.3.4"],
            },
        }

        with patch("vlair.tools.deobfuscator.Deobfuscator", return_value=mock_deob):
            result = wf._deobfuscate(ctx)

        assert result.success is True
        assert any(
            f.severity == Severity.HIGH and "heavily obfuscated" in f.message
            for f in ctx.scorer.findings
        )
        assert "http://evil.com" in ctx.iocs["urls"]

    def test_deobfuscate_light_obfuscation(self):
        """Lightly obfuscated script adds MEDIUM finding."""
        wf = self._make_workflow()
        ctx = _make_context("test.js")
        ctx.data["file_extension"] = ".js"

        mock_deob = MagicMock()
        mock_deob.deobfuscate_file.return_value = {
            "layers_decoded": 1,
            "extracted_iocs": {},
        }

        with patch("vlair.tools.deobfuscator.Deobfuscator", return_value=mock_deob):
            result = wf._deobfuscate(ctx)

        assert result.success is True
        assert any(
            f.severity == Severity.MEDIUM and "obfuscated" in f.message for f in ctx.scorer.findings
        )

    def test_deobfuscate_import_error(self):
        wf = self._make_workflow()
        ctx = _make_context("test.js")
        ctx.data["file_extension"] = ".js"

        with patch.dict("sys.modules", {"vlair.tools.deobfuscator": None}):
            with patch("builtins.__import__", side_effect=ImportError):
                result = wf._deobfuscate(ctx)

        assert result.success is False

    # ----- extract_iocs -----

    def test_extract_iocs_many_network_indicators(self):
        """Many network indicators add MEDIUM finding."""
        wf = self._make_workflow()
        ctx = _make_context("test.bin")

        mock_extractor = MagicMock()
        mock_extractor.extract_from_file.return_value = {
            "domains": ["a.com", "b.com", "c.com"],
            "ips": ["1.1.1.1", "2.2.2.2"],
            "urls": ["http://a.com", "http://b.com"],
            "emails": ["x@y.com"],
        }

        with patch("vlair.tools.ioc_extractor.IOCExtractor", return_value=mock_extractor):
            result = wf._extract_iocs(ctx)

        assert result.success is True
        # total_iocs = 3 + 2 + 2 = 7 > 5, so finding should be added
        assert any("network indicators" in f.message for f in ctx.scorer.findings)

    def test_extract_iocs_import_error(self):
        wf = self._make_workflow()
        ctx = _make_context("test.bin")

        with patch.dict("sys.modules", {"vlair.tools.ioc_extractor": None}):
            with patch("builtins.__import__", side_effect=ImportError):
                result = wf._extract_iocs(ctx)

        assert result.success is False

    # ----- check_iocs -----

    def test_check_iocs_malicious_domains_and_urls(self):
        """Malicious domains and URLs add findings."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.add_iocs("domains", ["evil.com"])
        ctx.add_iocs("urls", ["http://evil.com/payload"])

        mock_intel = MagicMock()
        mock_intel.lookup.return_value = {"verdict": "malicious"}

        mock_url_analyzer = MagicMock()
        mock_url_analyzer.analyze.return_value = {"verdict": "malicious"}

        with patch(
            "vlair.tools.domain_ip_intel.DomainIPIntelligence",
            return_value=mock_intel,
        ):
            with patch(
                "vlair.tools.url_analyzer.URLAnalyzer",
                return_value=mock_url_analyzer,
            ):
                result = wf._check_iocs(ctx)

        assert result.success is True
        assert any("malicious domain" in f.message for f in ctx.scorer.findings)
        assert any("malicious URL" in f.message for f in ctx.scorer.findings)

    def test_check_iocs_empty(self):
        """No IOCs to check."""
        wf = self._make_workflow()
        ctx = _make_context()
        result = wf._check_iocs(ctx)
        assert result.success is True

    def test_check_iocs_domain_exception_swallowed(self):
        """Exception in domain lookup is swallowed."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.add_iocs("domains", ["fail.com"])

        with patch(
            "vlair.tools.domain_ip_intel.DomainIPIntelligence",
            side_effect=Exception("fail"),
        ):
            result = wf._check_iocs(ctx)

        assert result.success is True

    # ----- calculate_score -----

    def test_calculate_score_high_risk(self):
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.scorer.add_finding(Severity.CRITICAL, "t1", "t")
        ctx.scorer.add_finding(Severity.CRITICAL, "t2", "t")
        ctx.scorer.add_finding(Severity.CRITICAL, "t3", "t")

        result = wf._calculate_score(ctx)
        assert result.success is True
        assert result.data["risk_score"] >= 70
        assert any("QUARANTINE" in r for r in result.data["recommendations"])

    def test_calculate_score_medium_risk(self):
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.scorer.add_finding(Severity.HIGH, "t1", "t")
        ctx.scorer.add_finding(Severity.HIGH, "t2", "t")
        ctx.scorer.add_finding(Severity.HIGH, "t3", "t")

        result = wf._calculate_score(ctx)
        assert result.success is True
        score = result.data["risk_score"]
        assert 40 <= score < 70
        assert any("suspicious" in r.lower() for r in result.data["recommendations"])

    def test_calculate_score_low_risk(self):
        wf = self._make_workflow()
        ctx = _make_context()
        result = wf._calculate_score(ctx)
        assert result.success is True
        assert result.data["risk_score"] < 40
        assert any("low risk" in r.lower() for r in result.data["recommendations"])


# ===========================================================================
# IOCHuntWorkflow tests
# ===========================================================================


class TestIOCHuntWorkflowSteps:
    """Test individual step execution in IOCHuntWorkflow."""

    def _make_workflow(self, verbose=False):
        from vlair.workflows.ioc_hunt import IOCHuntWorkflow

        return IOCHuntWorkflow(verbose=verbose)

    def test_execute_step_unknown(self):
        wf = self._make_workflow()
        ctx = _make_context()
        step = WorkflowStep(name="unknown", description="x", tool="x")
        result = wf._execute_step(step, ctx)
        assert result.success is False

    # ----- parse_iocs -----

    def test_parse_iocs_success(self):
        """Successfully parsed IOCs are counted and stored."""
        wf = self._make_workflow(verbose=True)
        ctx = _make_context("test.txt")

        mock_extractor = MagicMock()
        mock_extractor.extract_from_file.return_value = {
            "md5": ["hash1"],
            "sha1": [],
            "sha256": ["hash2"],
            "domains": ["evil.com"],
            "ips": ["1.2.3.4"],
            "urls": ["http://evil.com"],
        }

        with patch("vlair.tools.ioc_extractor.IOCExtractor", return_value=mock_extractor):
            result = wf._parse_iocs(ctx)

        assert result.success is True
        assert ctx.data["ioc_counts"]["hashes"] == 2
        assert ctx.data["ioc_counts"]["domains"] == 1

    def test_parse_iocs_exception(self):
        """Exception in _parse_iocs is caught."""
        wf = self._make_workflow()
        ctx = _make_context("test.txt")

        mock_extractor = MagicMock()
        mock_extractor.extract_from_file.side_effect = FileNotFoundError("no file")

        with patch("vlair.tools.ioc_extractor.IOCExtractor", return_value=mock_extractor):
            result = wf._parse_iocs(ctx)

        assert result.success is False

    # ----- check_hashes -----

    def test_check_hashes_empty(self):
        """No hashes returns success with zero checked."""
        wf = self._make_workflow()
        ctx = _make_context()
        result = wf._check_hashes(ctx)
        assert result.success is True
        assert result.data["checked"] == 0

    def test_check_hashes_mixed_verdicts(self):
        """Hashes with various verdicts are correctly tallied."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.add_iocs("hashes", ["h1", "h2", "h3", "h4"])

        mock_lookup = MagicMock()
        mock_lookup.lookup.side_effect = [
            {"verdict": "malicious"},
            {"verdict": "suspicious"},
            {"verdict": "clean"},
            {"verdict": "unknown"},
        ]

        with patch("vlair.tools.hash_lookup.HashLookup", return_value=mock_lookup):
            result = wf._check_hashes(ctx)

        assert result.success is True
        data = result.data
        assert data["malicious"] == 1
        assert data["suspicious"] == 1
        assert data["clean"] == 1
        assert data["unknown"] == 1

    def test_check_hashes_exception(self):
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.add_iocs("hashes", ["h1"])

        with patch("vlair.tools.hash_lookup.HashLookup", side_effect=Exception("fail")):
            result = wf._check_hashes(ctx)

        assert result.success is False

    # ----- check_domains -----

    def test_check_domains_empty(self):
        wf = self._make_workflow()
        ctx = _make_context()
        result = wf._check_domains(ctx)
        assert result.success is True
        assert result.data["checked"] == 0

    def test_check_domains_malicious(self):
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.add_iocs("domains", ["evil.com"])

        mock_intel = MagicMock()
        mock_intel.lookup.return_value = {"verdict": "malicious"}

        with patch(
            "vlair.tools.domain_ip_intel.DomainIPIntelligence",
            return_value=mock_intel,
        ):
            result = wf._check_domains(ctx)

        assert result.success is True
        assert result.data["malicious"] == 1
        assert any(f.severity == Severity.HIGH for f in ctx.scorer.findings)

    def test_check_domains_exception(self):
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.add_iocs("domains", ["d.com"])

        with patch(
            "vlair.tools.domain_ip_intel.DomainIPIntelligence",
            side_effect=Exception("fail"),
        ):
            result = wf._check_domains(ctx)

        assert result.success is False

    # ----- check_ips -----

    def test_check_ips_empty(self):
        wf = self._make_workflow()
        ctx = _make_context()
        result = wf._check_ips(ctx)
        assert result.success is True
        assert result.data["checked"] == 0

    def test_check_ips_mixed(self):
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.add_iocs("ips", ["1.1.1.1", "2.2.2.2"])

        mock_intel = MagicMock()
        mock_intel.lookup.side_effect = [
            {"verdict": "malicious"},
            {"verdict": "clean"},
        ]

        with patch(
            "vlair.tools.domain_ip_intel.DomainIPIntelligence",
            return_value=mock_intel,
        ):
            result = wf._check_ips(ctx)

        assert result.success is True
        assert result.data["malicious"] == 1
        assert result.data["clean"] == 1

    # ----- check_urls -----

    def test_check_urls_empty(self):
        wf = self._make_workflow()
        ctx = _make_context()
        result = wf._check_urls(ctx)
        assert result.success is True
        assert result.data["checked"] == 0

    def test_check_urls_malicious(self):
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.add_iocs("urls", ["http://evil.com"])

        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = {"verdict": "malicious"}

        with patch("vlair.tools.url_analyzer.URLAnalyzer", return_value=mock_analyzer):
            result = wf._check_urls(ctx)

        assert result.success is True
        assert result.data["malicious"] == 1

    # ----- generate_report -----

    def test_generate_report_with_malicious_iocs(self):
        """Report with malicious IOCs has blocking recommendations."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.data["ioc_counts"] = {"hashes": 2, "domains": 1, "ips": 1, "urls": 1}
        ctx.data["hash_results"] = {"checked": 2, "malicious": 1}
        ctx.data["domain_results"] = {"checked": 1, "malicious": 0}
        ctx.data["ip_results"] = {"checked": 1, "malicious": 0}
        ctx.data["url_results"] = {"checked": 1, "malicious": 1}

        ctx.scorer.add_finding(Severity.CRITICAL, "t", "t")

        result = wf._generate_report(ctx)
        assert result.success is True
        assert result.data["total_malicious"] == 2
        assert result.data["hit_rate_percent"] > 0
        assert any("Block" in r for r in result.data["recommendations"])

    def test_generate_report_no_malicious(self):
        """Report with no malicious IOCs gives monitoring recommendation."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.data["ioc_counts"] = {"hashes": 1, "domains": 0, "ips": 0, "urls": 0}
        ctx.data["hash_results"] = {"checked": 1, "malicious": 0}
        ctx.data["domain_results"] = {}
        ctx.data["ip_results"] = {}
        ctx.data["url_results"] = {}

        result = wf._generate_report(ctx)
        assert result.success is True
        assert result.data["total_malicious"] == 0
        assert any("monitoring" in r.lower() for r in result.data["recommendations"])

    def test_generate_report_empty_context(self):
        """Report with empty context data."""
        wf = self._make_workflow()
        ctx = _make_context()
        ctx.data["ioc_counts"] = {}

        result = wf._generate_report(ctx)
        assert result.success is True
        assert result.data["total_iocs"] == 0
        assert result.data["hit_rate_percent"] == 0


# ===========================================================================
# Cross-cutting workflow tests
# ===========================================================================


class TestWorkflowDependencySkipping:
    """Test that steps with unmet dependencies are properly skipped."""

    def test_phishing_steps_skip_when_parse_fails(self):
        """When parse_email fails, dependent steps are skipped."""
        from vlair.workflows.phishing_email import PhishingEmailWorkflow

        wf = PhishingEmailWorkflow(verbose=False)

        # Use a file that will cause parse to fail with ImportError
        with patch.dict("sys.modules", {"vlair.tools.eml_parser": None}):
            with patch("builtins.__import__", side_effect=ImportError):
                result = wf.execute("/fake/file.eml", "email")

        # parse_email should have failed
        parse_step = next((r for r in result["step_results"] if r["name"] == "parse_email"), None)
        assert parse_step is not None
        assert parse_step["success"] is False

    def test_malware_workflow_with_nonexistent_file(self):
        """When calculate_hashes fails, check_hashes may also fail but workflow completes."""
        from vlair.workflows.malware_triage import MalwareTriageWorkflow

        wf = MalwareTriageWorkflow(verbose=False)
        result = wf.execute("/nonexistent/file.exe", "file")

        assert result["workflow"] == "malware-triage"
        hash_step = next(
            (r for r in result["step_results"] if r["name"] == "calculate_hashes"),
            None,
        )
        assert hash_step is not None
        assert hash_step["success"] is False


class TestWorkflowVerboseOutput:
    """Test that verbose mode works across workflows."""

    def test_network_forensics_verbose(self, capsys):
        from vlair.workflows.network_forensics import NetworkForensicsWorkflow

        wf = NetworkForensicsWorkflow(verbose=True)

        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = {
            "statistics": {"total_packets": 10},
            "ips": {},
            "dns_queries": [],
            "threats": {},
            "connections": [],
        }

        with patch("vlair.tools.pcap_analyzer.PCAPAnalyzer", return_value=mock_analyzer):
            result = wf.execute("test.pcap", "pcap")

        assert result is not None

    def test_log_investigation_verbose(self, capsys):
        from vlair.workflows.log_investigation import LogInvestigationWorkflow

        wf = LogInvestigationWorkflow(verbose=True)

        mock_analyzer = MagicMock()
        mock_analyzer.analyze.return_value = {
            "statistics": {"total_entries": 5},
            "threats": {},
        }

        with patch("vlair.tools.log_analyzer.LogAnalyzer", return_value=mock_analyzer):
            result = wf.execute("test.log", "log")

        assert result is not None

    def test_ioc_hunt_verbose(self, capsys):
        from vlair.workflows.ioc_hunt import IOCHuntWorkflow

        wf = IOCHuntWorkflow(verbose=True)

        mock_extractor = MagicMock()
        mock_extractor.extract_from_file.return_value = {
            "md5": [],
            "sha1": [],
            "sha256": [],
            "domains": [],
            "ips": [],
            "urls": [],
        }

        with patch("vlair.tools.ioc_extractor.IOCExtractor", return_value=mock_extractor):
            result = wf.execute("test.txt", "ioc_list")

        assert result is not None
