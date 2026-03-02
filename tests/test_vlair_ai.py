"""
Tests for vlair.ai — ThreatSummarizer and prompt helpers.
All tests mock the Anthropic API; no real API key is required.
"""

import json
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Add src directory to path (consistent with other vlair tests)
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from vlair.ai import ThreatSummarizer, SummaryConfig
from vlair.ai.prompts import build_prompt, get_system_prompt, SECURITY_ANALYST_SYSTEM_PROMPT

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MOCK_CLAUDE_RESPONSE = """
VERDICT: MALICIOUS (92% confidence)
SEVERITY: HIGH
KEY FINDINGS:
• Confirmed Emotet loader detected by 45/70 AV engines
• Active C2 infrastructure at known Emotet IPs
• First seen 2026-01-15, consistent with recent campaign
THREAT CONTEXT:
Emotet is a modular malware platform operated by TA542.
RECOMMENDED ACTIONS:
IMMEDIATE: Isolate affected host from network
SHORT-TERM: Reset user credentials and check for lateral movement
LONG-TERM: Deploy EDR across all endpoints
MITRE ATT&CK: T1566.001, T1059.001, T1071.001
CONFIDENCE NOTES: HIGH confidence — multiple corroborating sources.
""".strip()


def _make_mock_client(response_text: str = MOCK_CLAUDE_RESPONSE):
    """Return a mock Anthropic client that returns response_text."""
    mock_usage = MagicMock()
    mock_usage.input_tokens = 500
    mock_usage.output_tokens = 250

    mock_content = MagicMock()
    mock_content.text = response_text

    mock_message = MagicMock()
    mock_message.usage = mock_usage
    mock_message.content = [mock_content]

    mock_client = MagicMock()
    mock_client.messages.create.return_value = mock_message
    return mock_client


# ---------------------------------------------------------------------------
# ThreatSummarizer.is_available
# ---------------------------------------------------------------------------


class TestThreatSummarizerAvailability:
    def test_available_when_key_set(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-123")
        s = ThreatSummarizer()
        assert s.is_available() is True

    def test_unavailable_when_key_missing(self, monkeypatch):
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        s = ThreatSummarizer()
        assert s.is_available() is False


# ---------------------------------------------------------------------------
# ThreatSummarizer.summarize — mocked API
# ---------------------------------------------------------------------------


class TestThreatSummarizerSummarize:
    def _summarizer_with_mock_client(self, monkeypatch) -> ThreatSummarizer:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        s = ThreatSummarizer(SummaryConfig(use_cache=False))
        s._client = _make_mock_client()
        return s

    def test_basic_hash_analysis(self, monkeypatch):
        s = self._summarizer_with_mock_client(monkeypatch)
        tool_result = {"virustotal": {"detections": 45, "total": 70}, "malwarebazaar": {"signature": "Emotet"}}
        result = s.summarize("44d88612fea8a8f36de82e1278abb02f", "hash", tool_result)

        assert result["verdict"] == "MALICIOUS"
        assert result["severity"] == "HIGH"
        assert result["confidence"] == pytest.approx(0.92)
        assert len(result["key_findings"]) > 0
        assert result["threat_context"] != ""
        assert len(result["recommended_actions"]) > 0
        assert "T1566.001" in result["mitre_attack"]
        assert result["metadata"]["tokens_used"] == 750

    def test_depth_quick_limits_tokens(self, monkeypatch):
        s = self._summarizer_with_mock_client(monkeypatch)
        # Just verify quick depth path doesn't crash
        result = s.summarize("evil.com", "domain", {"risk_score": 80}, depth="quick")
        assert "verdict" in result

    def test_depth_thorough(self, monkeypatch):
        s = self._summarizer_with_mock_client(monkeypatch)
        result = s.summarize("evil.com", "domain", {"risk_score": 80}, depth="thorough")
        assert "verdict" in result

    def test_metadata_present(self, monkeypatch):
        s = self._summarizer_with_mock_client(monkeypatch)
        result = s.summarize("1.2.3.4", "ip", {})
        assert "metadata" in result
        assert "model" in result["metadata"]
        assert "tokens_used" in result["metadata"]
        assert result["metadata"]["cached"] is False

    def test_unknown_verdict_fallback(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        s = ThreatSummarizer(SummaryConfig(use_cache=False))
        s._client = _make_mock_client("No structured data here at all.")
        result = s.summarize("test", "hash", {})
        # Should default to UNKNOWN without crashing
        assert result["verdict"] == "UNKNOWN"


# ---------------------------------------------------------------------------
# ThreatSummarizer caching
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=False)
def clear_ai_cache():
    """Clear the module-level _CACHE between cache tests."""
    from vlair.ai.summarizer import _CACHE

    _CACHE.clear()
    yield
    _CACHE.clear()


class TestThreatSummarizerCache:
    def test_cache_hit_on_second_call(self, monkeypatch, clear_ai_cache):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        s = ThreatSummarizer(SummaryConfig(use_cache=True))
        s._client = _make_mock_client()

        tool_result = {"score": 90}
        result1 = s.summarize("evil.com", "domain", tool_result)
        # Second call — must hit cache (client.messages.create called only once)
        result2 = s.summarize("evil.com", "domain", tool_result)

        assert result2["metadata"]["cached"] is True
        assert s._client.messages.create.call_count == 1

    def test_different_inputs_not_cached(self, monkeypatch, clear_ai_cache):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        s = ThreatSummarizer(SummaryConfig(use_cache=True))
        s._client = _make_mock_client()

        s.summarize("evil.com-unique1", "domain", {"score": 90})
        s.summarize("other.com-unique1", "domain", {"score": 90})

        assert s._client.messages.create.call_count == 2

    def test_cache_ttl_expiry(self, monkeypatch, clear_ai_cache):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        config = SummaryConfig(use_cache=True, cache_ttl_seconds=1)
        s = ThreatSummarizer(config)
        s._client = _make_mock_client()

        s.summarize("expiry-test.com", "domain", {"score": 90})
        # Expire cache by back-dating the entry
        from vlair.ai.summarizer import _CACHE

        for k in list(_CACHE.keys()):
            _CACHE[k] = (time.time() - 10, _CACHE[k][1])

        s.summarize("expiry-test.com", "domain", {"score": 90})
        assert s._client.messages.create.call_count == 2


# ---------------------------------------------------------------------------
# Prompt helpers
# ---------------------------------------------------------------------------


class TestPrompts:
    def test_system_prompt_has_required_sections(self):
        p = SECURITY_ANALYST_SYSTEM_PROMPT
        for section in ("VERDICT", "SEVERITY", "KEY FINDINGS", "THREAT CONTEXT", "RECOMMENDED ACTIONS"):
            assert section in p, f"Missing section: {section}"

    def test_specialized_prompts_by_type(self):
        for ioc_type, expected_keyword in [
            ("hash", "HASH"),
            ("domain", "DOMAIN"),
            ("ip", "DOMAIN"),  # reuses domain addendum
            ("url", "URL"),
            ("email", "EMAIL"),
            ("log", "LOG"),
            ("pcap", "PCAP"),
            ("cert", "CERTIFICATE"),
            ("script", "SCRIPT"),
        ]:
            prompt = get_system_prompt(ioc_type)
            assert expected_keyword in prompt, f"Missing '{expected_keyword}' in {ioc_type} prompt"

    def test_unknown_type_falls_back_to_base(self):
        prompt = get_system_prompt("completely_unknown_type")
        assert prompt == SECURITY_ANALYST_SYSTEM_PROMPT

    def test_build_prompt_includes_ioc_value(self):
        p = build_prompt("44d88612", "hash", {"detections": 45}, "standard")
        assert "44d88612" in p
        assert "hash" in p

    def test_build_prompt_includes_tool_result_json(self):
        tool_result = {"virustotal": {"detections": 45}}
        p = build_prompt("abc", "hash", tool_result, "standard")
        assert "virustotal" in p
        assert "45" in p

    def test_build_prompt_depth_quick(self):
        p_quick = build_prompt("abc", "hash", {}, "quick")
        p_thorough = build_prompt("abc", "hash", {}, "thorough")
        # Thorough includes SIEM query instructions
        assert "SIEM" in p_thorough
        # Quick should be shorter (fewer instructions)
        assert len(p_quick) < len(p_thorough)


# ---------------------------------------------------------------------------
# _format_ai_assessment helper (CLI formatter)
# ---------------------------------------------------------------------------


class TestFormatAIAssessment:
    def _get_formatter(self):
        from vlair.cli.main import _format_ai_assessment

        return _format_ai_assessment

    def test_renders_verdict_and_severity(self):
        fmt = self._get_formatter()
        ai = {
            "verdict": "MALICIOUS",
            "severity": "HIGH",
            "confidence": 0.92,
            "key_findings": ["Finding A"],
            "threat_context": "Some context",
            "recommended_actions": [{"priority": "immediate", "action": "Isolate host"}],
            "mitre_attack": ["T1566.001"],
            "confidence_notes": "Strong signals",
            "metadata": {"model": "claude-sonnet-4-6", "tokens_used": 750, "cached": False, "analysis_time_ms": 1200},
        }
        output = fmt(ai)
        assert "MALICIOUS" in output
        assert "HIGH" in output
        assert "92%" in output
        assert "T1566.001" in output
        assert "Isolate host" in output
        assert "Finding A" in output

    def test_renders_cache_hit(self):
        fmt = self._get_formatter()
        ai = {
            "verdict": "CLEAN",
            "severity": "INFO",
            "confidence": 0.99,
            "key_findings": [],
            "threat_context": "",
            "recommended_actions": [],
            "mitre_attack": [],
            "confidence_notes": "",
            "metadata": {"model": "claude-sonnet-4-6", "tokens_used": 100, "cached": True, "analysis_time_ms": 5},
        }
        output = fmt(ai)
        assert "Cache: hit" in output

    def test_empty_fields_dont_crash(self):
        fmt = self._get_formatter()
        output = fmt({})
        assert "UNKNOWN" in output
        assert "AI SECURITY ASSESSMENT" in output
