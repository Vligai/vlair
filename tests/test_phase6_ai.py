"""
Tests for Phase 6 AI features:
  - MalwareClassifier
  - IOCCorrelator
  - PlaybookGenerator (mocked AI)
  - AIResponseCache
  - privacy.sanitize_tool_result
  - AIReporter
  - Provider availability checks (anthropic / openai / ollama)
  - ThreatSummarizer refactored with provider abstraction + dry_run
"""

import json
import os
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Helper: minimal VT-style tool result fixture
# ---------------------------------------------------------------------------

SAMPLE_HASH_RESULT = {
    "hash": "44d88612fea8a8f36de82e1278abb02f",
    "verdict": "MALICIOUS",
    "risk_score": 95,
    "detections": 62,
    "total_engines": 70,
    "malware_family": "emotet",
    "suggested_threat_label": "trojan.emotet/heodo",
    "tags": ["emotet", "heodo", "banking-trojan"],
    "categories": ["banking_trojan_loader"],
    "sources": ["virustotal", "malwarebazaar"],
}

SAMPLE_DOMAIN_RESULT = {
    "domain": "malicious-example.com",
    "verdict": "SUSPICIOUS",
    "risk_score": 72,
    "registrar": "Namecheap, Inc.",
    "asn": "12345",
    "country": "RU",
    "categories": ["phishing"],
    "dns": {"a_records": ["185.100.200.1"], "ns_records": ["ns1.malicious-example.com"]},
}


# ===========================================================================
# MalwareClassifier
# ===========================================================================


class TestMalwareClassifier(unittest.TestCase):
    def _get_classifier(self):
        from vlair.ai.classifier import MalwareClassifier

        return MalwareClassifier()

    def test_classify_emotet_by_family_label(self):
        clf = self._get_classifier()
        result = clf.classify(SAMPLE_HASH_RESULT)
        self.assertEqual(result["family"], "emotet")
        self.assertGreater(result["confidence"], 0.3)
        self.assertEqual(result["category"], "banking_trojan_loader")
        self.assertEqual(result["threat_actor"], "TA542")
        self.assertIn("T1566.001", result["mitre_techniques"])

    def test_classify_cobalt_strike(self):
        clf = self._get_classifier()
        result = clf.classify(
            {
                "malware_family": "cobaltstrike",
                "tags": ["beacon", "cobalt strike"],
                "verdict": "MALICIOUS",
            }
        )
        self.assertEqual(result["family"], "cobalt_strike")
        self.assertGreater(result["confidence"], 0.3)

    def test_classify_unknown(self):
        clf = self._get_classifier()
        result = clf.classify({"verdict": "CLEAN", "detections": 0, "total_engines": 70})
        self.assertIsNone(result["family"])
        self.assertEqual(result["confidence"], 0.0)
        self.assertEqual(result["category"], "unknown")

    def test_classify_ransomware(self):
        clf = self._get_classifier()
        result = clf.classify(
            {
                "malware_family": "ryuk",
                "tags": ["ransomware", "ryuk"],
                "suggested_threat_label": "ransom.ryuk",
            }
        )
        self.assertEqual(result["family"], "ryuk")
        self.assertEqual(result["severity"], "critical")

    def test_confidence_capped(self):
        clf = self._get_classifier()
        # Provide many matching signals for the same family
        result = clf.classify(
            {
                "malware_family": "emotet",
                "suggested_threat_label": "emotet",
                "tags": ["emotet", "heodo", "geodo", "mealybug", "banking-trojan"],
                "family_labels": ["emotet"],
                "names": ["emotet", "heodo"],
            }
        )
        self.assertLessEqual(result["confidence"], 0.97)

    def test_matching_signals_present(self):
        clf = self._get_classifier()
        result = clf.classify(SAMPLE_HASH_RESULT)
        self.assertIsInstance(result["matching_signals"], list)
        self.assertGreater(len(result["matching_signals"]), 0)


# ===========================================================================
# IOCCorrelator
# ===========================================================================


class TestIOCCorrelator(unittest.TestCase):
    def _get_correlator(self):
        from vlair.ai.correlator import IOCCorrelator

        return IOCCorrelator()

    def test_correlate_empty(self):
        corr = self._get_correlator()
        result = corr.correlate([], [])
        self.assertEqual(result["campaign_indicators"], [])
        self.assertIsNone(result["attribution"])
        self.assertEqual(result["confidence"], 0.0)

    def test_correlate_shared_family(self):
        corr = self._get_correlator()
        iocs = ["1.2.3.4", "5.6.7.8"]
        results = [
            {"tags": ["emotet", "heodo"], "asn": "12345", "country": "RU"},
            {"tags": ["emotet"], "asn": "12345", "country": "DE"},
        ]
        result = corr.correlate(iocs, results)
        self.assertIn("emotet", result["campaign_indicators"])
        self.assertGreater(result["confidence"], 0.0)
        self.assertGreater(len(result["relationships"]), 0)

    def test_correlate_threat_actor_attribution(self):
        corr = self._get_correlator()
        iocs = ["hash1", "hash2"]
        results = [
            {"malware_family": "ryuk", "tags": ["ryuk", "wizard spider"]},
            {"malware_family": "conti", "tags": ["conti"]},
        ]
        result = corr.correlate(iocs, results)
        self.assertIsNotNone(result["attribution"])

    def test_correlate_no_shared_signals(self):
        corr = self._get_correlator()
        iocs = ["clean1.com", "clean2.com"]
        results = [
            {"tags": ["adware"], "asn": "111"},
            {"tags": ["pua"], "asn": "222"},
        ]
        result = corr.correlate(iocs, results)
        self.assertEqual(result["relationships"], [])

    def test_correlate_summary_string(self):
        corr = self._get_correlator()
        result = corr.correlate(["a", "b"], [{"tags": ["emotet"]}, {"tags": ["emotet"]}])
        self.assertIsInstance(result["summary"], str)
        self.assertGreater(len(result["summary"]), 10)


# ===========================================================================
# AIResponseCache
# ===========================================================================


class TestAIResponseCache(unittest.TestCase):
    def _make_cache(self, ttl_hours=24):
        from vlair.ai.cache import AIResponseCache

        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        return AIResponseCache(db_path=tmp.name, ttl_hours=ttl_hours)

    def test_set_and_get(self):
        cache = self._make_cache()
        cache.set(
            "key1",
            {"verdict": "MALICIOUS"},
            tokens_used=100,
            provider="anthropic",
            model="claude-sonnet-4-6",
        )
        result = cache.get("key1")
        self.assertIsNotNone(result)
        self.assertEqual(result["verdict"], "MALICIOUS")

    def test_cache_miss(self):
        cache = self._make_cache()
        result = cache.get("nonexistent_key")
        self.assertIsNone(result)

    def test_ttl_expiry(self):
        cache = self._make_cache(ttl_hours=0)  # Immediately expired
        cache.set("key_exp", {"data": "test"}, tokens_used=50, provider="anthropic", model="test")
        # Force expiry by directly inserting an old record
        with sqlite3.connect(cache.db_path) as conn:
            conn.execute(
                "UPDATE cache SET created_at = ? WHERE key = ?",
                (time.time() - 10, "key_exp"),
            )
        result = cache.get("key_exp")
        self.assertIsNone(result)

    def test_get_stats_structure(self):
        cache = self._make_cache()
        cache.set("k1", {"v": 1}, tokens_used=500, provider="anthropic", model="claude-sonnet-4-6")
        stats = cache.get_stats()
        self.assertIn("today_requests", stats)
        self.assertIn("today_tokens", stats)
        self.assertIn("month_requests", stats)
        self.assertIn("cache_hit_rate", stats)
        self.assertIn("cost_estimate_today", stats)
        self.assertIn("provider_breakdown", stats)

    def test_clear_expired(self):
        cache = self._make_cache()
        cache.set("old_key", {"data": "old"}, tokens_used=0, provider="test", model="test")
        with sqlite3.connect(cache.db_path) as conn:
            conn.execute(
                "UPDATE cache SET created_at = ? WHERE key = ?",
                (time.time() - cache.ttl_seconds - 10, "old_key"),
            )
        deleted = cache.clear_expired()
        self.assertEqual(deleted, 1)
        self.assertIsNone(cache.get("old_key"))


# ===========================================================================
# Privacy / sanitize_tool_result
# ===========================================================================


class TestPrivacy(unittest.TestCase):
    def test_remove_file_contents(self):
        from vlair.ai.privacy import sanitize_tool_result

        result = sanitize_tool_result(
            {
                "file_contents": "AAABBBCCC",
                "raw_bytes": b"\x00\xff",
                "verdict": "MALICIOUS",
                "hashes": ["abc123"],
            }
        )
        self.assertEqual(result["file_contents"], "[REDACTED]")
        self.assertEqual(result["raw_bytes"], "[REDACTED]")
        self.assertEqual(result["verdict"], "MALICIOUS")
        self.assertEqual(result["hashes"], ["abc123"])

    def test_keep_send_file_contents(self):
        from vlair.ai.privacy import sanitize_tool_result

        result = sanitize_tool_result(
            {"file_contents": "important", "verdict": "CLEAN"},
            send_file_contents=True,
        )
        self.assertEqual(result["file_contents"], "important")

    def test_redact_internal_ip_field(self):
        from vlair.ai.privacy import sanitize_tool_result

        result = sanitize_tool_result({"source_ip": "192.168.1.100", "verdict": "INFO"})
        self.assertIn("REDACTED", result["source_ip"])

    def test_keep_public_ip(self):
        from vlair.ai.privacy import sanitize_tool_result

        result = sanitize_tool_result({"source_ip": "8.8.8.8", "verdict": "INFO"})
        self.assertEqual(result["source_ip"], "8.8.8.8")

    def test_nested_sanitization(self):
        from vlair.ai.privacy import sanitize_tool_result

        result = sanitize_tool_result(
            {
                "analysis": {
                    "raw_content": "should be redacted",
                    "score": 85,
                }
            }
        )
        self.assertEqual(result["analysis"]["raw_content"], "[REDACTED]")
        self.assertEqual(result["analysis"]["score"], 85)

    def test_dry_run_summary_format(self):
        from vlair.ai.privacy import get_dry_run_summary

        summary = get_dry_run_summary("44d88612abc", "hash", SAMPLE_HASH_RESULT)
        self.assertIn("DRY RUN", summary)
        self.assertIn("44d88612abc", summary)
        self.assertIn("hash", summary)
        self.assertIn("bytes", summary)


# ===========================================================================
# AIReporter
# ===========================================================================


class TestAIReporter(unittest.TestCase):
    def _get_ai_result(self):
        return {
            "verdict": "MALICIOUS",
            "severity": "CRITICAL",
            "confidence": 0.92,
            "key_findings": ["Emotet loader detected", "C2 beaconing observed"],
            "threat_context": "This is an Emotet banking trojan sample.",
            "recommended_actions": [
                {"priority": "immediate", "action": "Isolate affected host"},
                {"priority": "short_term", "action": "Block C2 domains at firewall"},
                {"priority": "long_term", "action": "Deploy EDR with ransomware rollback"},
            ],
            "mitre_attack": ["T1566.001", "T1059.001", "T1053.005"],
            "confidence_notes": "High confidence based on VT detections.",
            "metadata": {"model": "claude-sonnet-4-6", "tokens_used": 800, "cached": False},
        }

    def test_to_markdown_structure(self):
        from vlair.ai.reporter import AIReporter

        reporter = AIReporter()
        md = reporter.to_markdown("44d88612abc", "hash", SAMPLE_HASH_RESULT, self._get_ai_result())

        self.assertIn("# Investigation Report:", md)
        self.assertIn("44d88612abc", md)
        self.assertIn("MALICIOUS", md)
        self.assertIn("CRITICAL", md)
        self.assertIn("Emotet loader detected", md)
        self.assertIn("T1566.001", md)
        self.assertIn("Isolate affected host", md)
        self.assertIn("## Recommended Actions", md)
        self.assertIn("## Key Findings", md)
        self.assertIn("## MITRE ATT&CK Coverage", md)

    def test_to_jira_structure(self):
        from vlair.ai.reporter import AIReporter

        reporter = AIReporter()
        jira = reporter.to_jira("44d88612abc", "hash", self._get_ai_result())

        self.assertIn("h2.", jira)
        self.assertIn("MALICIOUS", jira)
        self.assertIn("Emotet loader detected", jira)
        self.assertIn("T1566.001", jira)

    def test_save_to_file(self):
        from vlair.ai.reporter import AIReporter

        reporter = AIReporter()
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = os.path.join(tmpdir, "report.md")
            saved = reporter.save("# Test Report\n", "markdown", out_path)
            self.assertTrue(os.path.exists(saved))
            content = open(saved).read()
            self.assertIn("# Test Report", content)

    def test_markdown_ioc_extraction(self):
        from vlair.ai.reporter import AIReporter

        reporter = AIReporter()
        tool_result_with_iocs = {
            **SAMPLE_HASH_RESULT,
            "iocs": {"domains": ["evil.com", "bad.net"], "ips": ["1.2.3.4"]},
        }
        md = reporter.to_markdown("hash123", "hash", tool_result_with_iocs, self._get_ai_result())
        self.assertIn("evil.com", md)


# ===========================================================================
# Provider availability checks
# ===========================================================================


class TestProviderAvailability(unittest.TestCase):
    def test_anthropic_available_with_key(self):
        from vlair.ai.providers.anthropic import AnthropicProvider

        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            provider = AnthropicProvider()
            self.assertTrue(provider.is_available())
            self.assertEqual(provider.name, "anthropic")

    def test_anthropic_unavailable_without_key(self):
        from vlair.ai.providers.anthropic import AnthropicProvider

        env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
        with patch.dict(os.environ, env, clear=True):
            provider = AnthropicProvider()
            self.assertFalse(provider.is_available())

    def test_openai_unavailable_without_key(self):
        from vlair.ai.providers.openai import OpenAIProvider

        env = {k: v for k, v in os.environ.items() if k != "OPENAI_API_KEY"}
        with patch.dict(os.environ, env, clear=True):
            provider = OpenAIProvider()
            self.assertFalse(provider.is_available())

    def test_openai_unavailable_when_package_missing(self):
        from vlair.ai.providers.openai import OpenAIProvider

        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-key"}):
            with patch.dict("sys.modules", {"openai": None}):
                provider = OpenAIProvider()
                self.assertFalse(provider.is_available())

    def test_ollama_unavailable_when_endpoint_down(self):
        from vlair.ai.providers.ollama import OllamaProvider

        provider = OllamaProvider(endpoint="http://127.0.0.1:19999")
        # Port 19999 should not be listening in test environment
        self.assertFalse(provider.is_available())

    def test_provider_names(self):
        from vlair.ai.providers.anthropic import AnthropicProvider
        from vlair.ai.providers.openai import OpenAIProvider
        from vlair.ai.providers.ollama import OllamaProvider

        self.assertEqual(AnthropicProvider().name, "anthropic")
        self.assertEqual(OpenAIProvider().name, "openai")
        self.assertEqual(OllamaProvider().name, "ollama")

    def test_provider_default_models(self):
        from vlair.ai.providers.anthropic import AnthropicProvider
        from vlair.ai.providers.openai import OpenAIProvider
        from vlair.ai.providers.ollama import OllamaProvider

        self.assertIn("claude", AnthropicProvider().model)
        self.assertIn("gpt", OpenAIProvider().model)
        self.assertEqual(OllamaProvider().model, "llama3")


# ===========================================================================
# PlaybookGenerator (heuristic mode — no AI needed)
# ===========================================================================


class TestPlaybookGenerator(unittest.TestCase):
    def _get_generator(self):
        from vlair.ai.playbook_generator import PlaybookGenerator

        return PlaybookGenerator()

    def test_generate_phishing_heuristic(self):
        gen = self._get_generator()
        playbook = gen._generate_heuristic("phishing", {})
        self.assertEqual(playbook["incident_type"], "phishing")
        self.assertGreater(len(playbook["steps"]), 0)
        self.assertIn("containment_actions", playbook)
        self.assertIn("eradication_actions", playbook)
        self.assertIn("recovery_actions", playbook)
        self.assertIn("lessons_learned", playbook)

    def test_generate_ransomware_heuristic(self):
        gen = self._get_generator()
        playbook = gen._generate_heuristic("ransomware", {})
        self.assertEqual(playbook["severity"], "CRITICAL")
        self.assertGreater(len(playbook["steps"]), 4)

    def test_generate_c2_heuristic(self):
        gen = self._get_generator()
        playbook = gen._generate_heuristic("c2", {})
        self.assertIn("siem_queries", playbook)

    def test_generate_unknown_type_fallback(self):
        gen = self._get_generator()
        playbook = gen._generate_heuristic("some_weird_incident", {})
        self.assertIn("steps", playbook)
        self.assertGreater(len(playbook["steps"]), 0)

    def test_generate_uses_heuristic_when_ai_unavailable(self):
        gen = self._get_generator()
        # Force heuristic path (no AI key set)
        with patch.dict(os.environ, {}, clear=False):
            # Remove AI keys if present
            env = dict(os.environ)
            env.pop("ANTHROPIC_API_KEY", None)
            env.pop("OPENAI_API_KEY", None)
            with patch.dict(os.environ, env, clear=True):
                playbook = gen.generate("phishing")
        self.assertIn("steps", playbook)

    def test_generate_with_mocked_ai(self):
        from vlair.ai.playbook_generator import PlaybookGenerator

        mock_playbook = {
            "title": "AI-Generated Phishing Playbook",
            "incident_type": "phishing",
            "severity": "HIGH",
            "steps": [
                {
                    "step": 1,
                    "title": "Triage",
                    "time": "0-5 min",
                    "actions": ["Check email headers"],
                },
            ],
            "siem_queries": {"splunk": "index=email ..."},
            "containment_actions": ["Block sender"],
            "eradication_actions": ["Remove email"],
            "recovery_actions": ["Notify users"],
            "lessons_learned": ["Update email gateway"],
        }

        gen = PlaybookGenerator()
        mock_provider = MagicMock()
        mock_provider.is_available.return_value = True
        mock_provider.analyze.return_value = MagicMock(content=json.dumps(mock_playbook))
        gen._provider = mock_provider

        result = gen.generate("phishing", depth="standard")
        self.assertIn("steps", result)

    def test_infer_incident_type(self):
        gen = self._get_generator()
        analysis_result = {"type": "email"}
        ai_result = {"mitre_attack": [], "key_findings": ["phishing email detected"]}
        incident_type = gen._infer_incident_type(analysis_result, ai_result)
        self.assertEqual(incident_type, "phishing")

    def test_generate_from_analysis(self):
        gen = self._get_generator()
        analysis_result = {"type": "hash", "tool_results": SAMPLE_HASH_RESULT}
        ai_result = {
            "verdict": "MALICIOUS",
            "severity": "CRITICAL",
            "mitre_attack": ["T1566.001"],
            "key_findings": ["Emotet detected"],
        }
        playbook = gen.generate_from_analysis(analysis_result, ai_result)
        self.assertIn("steps", playbook)


# ===========================================================================
# ThreatSummarizer — dry_run and provider abstraction
# ===========================================================================


class TestThreatSummarizerRefactored(unittest.TestCase):
    def test_dry_run_returns_preview_without_api_call(self):
        from vlair.ai.summarizer import ThreatSummarizer

        summarizer = ThreatSummarizer()
        result = summarizer.summarize("44d88612abc", "hash", SAMPLE_HASH_RESULT, dry_run=True)
        self.assertEqual(result["verdict"], "DRY_RUN")
        self.assertIn("DRY RUN", result["threat_context"])
        self.assertTrue(result["metadata"]["dry_run"])
        self.assertEqual(result["metadata"]["tokens_used"], 0)

    def test_summarize_with_mocked_anthropic_provider(self):
        from vlair.ai.summarizer import ThreatSummarizer, SummaryConfig

        mock_response = MagicMock()
        mock_response.content = (
            "VERDICT: MALICIOUS (90% confidence)\n"
            "SEVERITY: CRITICAL\n"
            "KEY FINDINGS:\n• Emotet loader\n• C2 communication\n"
            "THREAT CONTEXT: Banking trojan\n"
            "RECOMMENDED ACTIONS:\nIMMEDIATE: Isolate host\nSHORT-TERM: Block IOCs\n"
            "LONG-TERM: Harden email gateway\n"
            "MITRE ATT&CK: T1566.001, T1059.001\n"
            "CONFIDENCE NOTES: High confidence from VT detections."
        )
        mock_response.tokens_used = 500
        mock_response.model = "claude-sonnet-4-6"
        mock_response.provider = "anthropic"

        mock_provider = MagicMock()
        mock_provider.is_available.return_value = True
        mock_provider.analyze.return_value = mock_response

        config = SummaryConfig(use_cache=False)
        summarizer = ThreatSummarizer(config=config)
        summarizer._provider = mock_provider

        result = summarizer.summarize("44d88612abc", "hash", SAMPLE_HASH_RESULT)

        self.assertEqual(result["verdict"], "MALICIOUS")
        self.assertEqual(result["severity"], "CRITICAL")
        self.assertAlmostEqual(result["confidence"], 0.9)
        self.assertIn("Emotet loader", result["key_findings"])
        self.assertIn("T1566.001", result["mitre_attack"])
        self.assertIn("metadata", result)

    def test_is_available_delegates_to_provider(self):
        from vlair.ai.summarizer import ThreatSummarizer

        mock_provider = MagicMock()
        mock_provider.is_available.return_value = True
        summarizer = ThreatSummarizer()
        summarizer._provider = mock_provider
        self.assertTrue(summarizer.is_available())

    def test_is_unavailable_when_provider_not_configured(self):
        from vlair.ai.summarizer import ThreatSummarizer

        env = {
            k: v for k, v in os.environ.items() if k not in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY")
        }
        with patch.dict(os.environ, env, clear=True):
            summarizer = ThreatSummarizer()
            # Reset lazy provider
            summarizer._provider = None
            # Should not raise; just return False
            available = summarizer.is_available()
            self.assertFalse(available)

    def test_cache_returns_cached_result(self):
        from vlair.ai.summarizer import ThreatSummarizer, SummaryConfig

        call_count = [0]

        def mock_call(*args, **kwargs):
            call_count[0] += 1
            resp = MagicMock()
            resp.content = "VERDICT: CLEAN (80% confidence)\nSEVERITY: LOW\nKEY FINDINGS:\nTHREAT CONTEXT:\nRECOMMENDED ACTIONS:\nMITRE ATT&CK: N/A\nCONFIDENCE NOTES:"
            resp.tokens_used = 100
            resp.model = "test"
            resp.provider = "anthropic"
            return resp

        mock_provider = MagicMock()
        mock_provider.is_available.return_value = True
        mock_provider.analyze.side_effect = mock_call

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
            db_path = tmp.name

        from vlair.ai.cache import AIResponseCache

        config = SummaryConfig(use_cache=True)
        summarizer = ThreatSummarizer(config=config)
        summarizer._provider = mock_provider
        summarizer._cache = AIResponseCache(db_path=db_path)

        # First call — should hit provider
        summarizer.summarize("abc", "hash", {"data": 1})
        # Second call with same inputs — should hit cache
        result2 = summarizer.summarize("abc", "hash", {"data": 1})

        self.assertTrue(result2["metadata"]["cached"])
        self.assertEqual(call_count[0], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
