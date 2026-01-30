"""
Tests for AI Analysis Module

Tests the AI analyzer, providers, caching, and privacy controls.
"""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import tempfile

from secops_helper.ai import (
    AIAnalyzer,
    AIProvider,
    AIResponse,
    AIResponseCache,
    DataSanitizer,
)
from secops_helper.ai.analyzer import AnalysisConfig
from secops_helper.ai.providers.base import Verdict, Severity, RecommendedAction
from secops_helper.ai.privacy import PrivacyConfig
from secops_helper.ai.prompts.system import get_system_prompt, SECURITY_ANALYST_SYSTEM_PROMPT
from secops_helper.ai.prompts.analysis import build_analysis_prompt


class TestAIResponse:
    """Tests for AIResponse dataclass"""

    def test_basic_response(self):
        """Test creating a basic AIResponse"""
        response = AIResponse(
            content="Test content",
            confidence=0.85,
            tokens_used=100,
            model="gpt-4"
        )
        assert response.content == "Test content"
        assert response.confidence == 0.85
        assert response.tokens_used == 100
        assert response.cached is False

    def test_response_to_dict(self):
        """Test converting response to dictionary"""
        response = AIResponse(
            content="Test",
            confidence=0.9,
            tokens_used=50,
            model="gpt-4",
            verdict=Verdict.MALICIOUS,
            severity=Severity.HIGH,
            key_findings=["Finding 1", "Finding 2"]
        )
        result = response.to_dict()

        assert result['verdict'] == 'MALICIOUS'
        assert result['severity'] == 'HIGH'
        assert result['confidence'] == 0.9
        assert len(result['key_findings']) == 2


class TestDataSanitizer:
    """Tests for privacy data sanitization"""

    def test_sanitize_internal_ips(self):
        """Test that internal IPs are sanitized"""
        sanitizer = DataSanitizer()
        data = {
            'source_ip': '192.168.1.100',
            'dest_ip': '8.8.8.8',
            'internal': '10.0.0.1'
        }
        result = sanitizer.sanitize(data)

        assert '[INTERNAL_IP]' in result['source_ip']
        assert result['dest_ip'] == '8.8.8.8'  # Public IP unchanged
        assert '[INTERNAL_IP]' in result['internal']

    def test_sanitize_paths(self):
        """Test that user paths are sanitized"""
        sanitizer = DataSanitizer()
        data = {
            'path': 'C:\\Users\\john.doe\\Documents\\file.txt'
        }
        result = sanitizer.sanitize(data)

        assert '[USER]' in result['path']
        assert 'john.doe' not in result['path']

    def test_defang_ioc(self):
        """Test IOC defanging"""
        sanitizer = DataSanitizer()

        assert sanitizer.defang_ioc('192.168.1.1', 'ip') == '192[.]168[.]1[.]1'
        assert sanitizer.defang_ioc('evil.com', 'domain') == 'evil[.]com'
        assert 'hxxps://' in sanitizer.defang_ioc('https://evil.com/path', 'url')

    def test_refang_ioc(self):
        """Test IOC refanging"""
        sanitizer = DataSanitizer()

        assert sanitizer.refang_ioc('192[.]168[.]1[.]1') == '192.168.1.1'
        assert sanitizer.refang_ioc('hxxps://evil[.]com') == 'https://evil.com'

    def test_sensitive_file_detection(self):
        """Test detection of sensitive files"""
        sanitizer = DataSanitizer()

        assert sanitizer.is_sensitive_file('.env') is True
        assert sanitizer.is_sensitive_file('credentials.json') is True
        assert sanitizer.is_sensitive_file('private.key') is True
        assert sanitizer.is_sensitive_file('malware.exe') is False

    def test_transmission_preview(self):
        """Test generating transmission preview"""
        sanitizer = DataSanitizer()
        data = {
            'ioc': 'abc123',
            'internal_ip': '10.0.0.1'
        }
        preview = sanitizer.get_transmission_preview(data)

        assert 'will_send' in preview
        assert 'removed_or_sanitized' in preview
        assert 'privacy_config' in preview


class TestAIResponseCache:
    """Tests for AI response caching"""

    def test_cache_operations(self):
        """Test basic cache set/get operations"""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_path = Path(tmpdir) / "test_cache.db"
            cache = AIResponseCache(cache_path=str(cache_path), ttl_hours=24)

            # Create a response
            response = AIResponse(
                content="Test response",
                confidence=0.8,
                tokens_used=100,
                model="gpt-4"
            )

            # Generate cache key
            cache_key = cache.get_cache_key(
                input_value="test_hash",
                input_type="hash",
                prompt_hash="abc123",
                model="gpt-4"
            )

            # Store response
            cache.set(cache_key, response)

            # Retrieve response
            cached = cache.get(cache_key)
            assert cached is not None
            assert cached.content == "Test response"
            assert cached.cached is True

    def test_cache_miss(self):
        """Test cache miss returns None"""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_path = Path(tmpdir) / "test_cache.db"
            cache = AIResponseCache(cache_path=str(cache_path))

            result = cache.get("nonexistent_key")
            assert result is None

    def test_cache_stats(self):
        """Test cache statistics"""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache_path = Path(tmpdir) / "test_cache.db"
            cache = AIResponseCache(cache_path=str(cache_path))

            stats = cache.get_stats()
            assert 'total_entries' in stats
            assert 'valid_entries' in stats
            assert 'cache_path' in stats


class TestPrompts:
    """Tests for prompt templates"""

    def test_system_prompt_exists(self):
        """Test that system prompt is defined"""
        assert len(SECURITY_ANALYST_SYSTEM_PROMPT) > 100
        assert 'VERDICT' in SECURITY_ANALYST_SYSTEM_PROMPT
        assert 'SEVERITY' in SECURITY_ANALYST_SYSTEM_PROMPT

    def test_get_specialized_prompt(self):
        """Test getting specialized prompts by type"""
        hash_prompt = get_system_prompt('hash')
        email_prompt = get_system_prompt('email')
        default_prompt = get_system_prompt('unknown')

        assert 'HASH ANALYSIS' in hash_prompt
        assert 'EMAIL ANALYSIS' in email_prompt
        assert default_prompt == SECURITY_ANALYST_SYSTEM_PROMPT

    def test_build_analysis_prompt(self):
        """Test building analysis prompts"""
        threat_intel = {
            'virustotal': {'detection_ratio': '45/70'},
            'malwarebazaar': {'signature': 'Emotet'}
        }

        prompt = build_analysis_prompt(
            input_type='hash',
            input_value='abc123',
            threat_intel=threat_intel,
            depth='standard'
        )

        assert 'hash' in prompt.lower()
        assert 'abc123' in prompt
        assert 'virustotal' in prompt.lower()

    def test_quick_analysis_prompt(self):
        """Test quick analysis prompt is shorter"""
        threat_intel = {'test': 'data'}

        quick = build_analysis_prompt(
            input_type='hash',
            input_value='test',
            threat_intel=threat_intel,
            depth='quick'
        )

        standard = build_analysis_prompt(
            input_type='hash',
            input_value='test',
            threat_intel=threat_intel,
            depth='standard'
        )

        assert len(quick) < len(standard)


class TestAIAnalyzer:
    """Tests for the main AIAnalyzer class"""

    @patch('secops_helper.ai.providers.get_provider')
    def test_analyzer_initialization(self, mock_get_provider):
        """Test analyzer initializes correctly"""
        config = AnalysisConfig(provider='openai')
        analyzer = AIAnalyzer(config)

        assert analyzer.config.provider == 'openai'
        assert analyzer.config.depth == 'standard'

    @patch('secops_helper.ai.providers.get_provider')
    def test_transmission_preview(self, mock_get_provider):
        """Test dry-run transmission preview"""
        analyzer = AIAnalyzer()

        threat_intel = {
            'hash': 'abc123',
            'internal_source': '192.168.1.1'
        }

        preview = analyzer.get_transmission_preview(threat_intel)
        assert 'will_send' in preview

    def test_stats_tracking(self):
        """Test statistics are tracked"""
        analyzer = AIAnalyzer()
        stats = analyzer.get_stats()

        assert 'requests' in stats
        assert 'tokens' in stats
        assert 'performance' in stats


class TestProviderBase:
    """Tests for AI provider base class"""

    def test_estimate_tokens(self):
        """Test basic token estimation"""
        from secops_helper.ai.providers.base import AIProvider

        # Create a concrete test implementation
        class TestProvider(AIProvider):
            def analyze(self, prompt, context, max_tokens=2000, temperature=0.3):
                return AIResponse("", 0.5, 0, "test")

            def is_available(self):
                return True

            @property
            def name(self):
                return "test"

            @property
            def model(self):
                return "test-model"

        provider = TestProvider()
        tokens = provider.estimate_tokens("Hello, world!")

        # Rough estimate: ~4 chars per token
        assert 2 <= tokens <= 5


# Integration test placeholder (requires API key)
class TestIntegration:
    """Integration tests (require actual API keys)"""

    @pytest.mark.skip(reason="Requires API key")
    def test_openai_integration(self):
        """Test actual OpenAI integration"""
        from secops_helper.ai.providers import OpenAIProvider

        provider = OpenAIProvider()
        if provider.is_available():
            response = provider.analyze(
                prompt="Say hello",
                context={},
                max_tokens=50
            )
            assert response.content
            assert response.tokens_used > 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
