"""
Tests for the SIEM query generator (F-2, Phase 1).
"""

import json
import pytest
from unittest.mock import MagicMock, patch

from vlair.ai.siem_query import SiemQueryGenerator, PLATFORMS, _TEMPLATES, _GENERIC_TEMPLATE

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def gen():
    return SiemQueryGenerator()


# ---------------------------------------------------------------------------
# Platform list
# ---------------------------------------------------------------------------


def test_platforms_constant():
    assert set(PLATFORMS) == {"splunk", "elastic", "sentinel", "sumo"}


# ---------------------------------------------------------------------------
# Template generation — happy paths
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ioc_type", ["ip", "domain", "hash_md5", "hash_sha1", "hash_sha256", "url", "email"])
def test_template_all_platforms_covered(gen, ioc_type):
    """Every supported IOC type must produce a non-empty query for every platform."""
    queries = gen.generate("test-value", ioc_type)
    assert set(queries.keys()) == set(PLATFORMS)
    for platform, query in queries.items():
        assert query, f"Empty query for {ioc_type}/{platform}"


@pytest.mark.parametrize("platform", PLATFORMS)
def test_template_ip_contains_value(gen, platform):
    queries = gen.generate("1.2.3.4", "ip")
    assert "1.2.3.4" in queries[platform]


@pytest.mark.parametrize("platform", PLATFORMS)
def test_template_domain_contains_value(gen, platform):
    queries = gen.generate("evil.example.com", "domain")
    assert "evil.example.com" in queries[platform]


@pytest.mark.parametrize("platform", PLATFORMS)
def test_template_sha256_contains_value(gen, platform):
    sha = "a" * 64
    queries = gen.generate(sha, "hash_sha256")
    assert sha in queries[platform]


@pytest.mark.parametrize("platform", PLATFORMS)
def test_template_url_contains_value(gen, platform):
    queries = gen.generate("http://bad.example.com/path", "url")
    assert "http://bad.example.com/path" in queries[platform]


@pytest.mark.parametrize("platform", PLATFORMS)
def test_template_email_contains_value(gen, platform):
    queries = gen.generate("attacker@evil.com", "email")
    assert "attacker@evil.com" in queries[platform]


# ---------------------------------------------------------------------------
# Platform filtering
# ---------------------------------------------------------------------------


def test_generate_single_platform(gen):
    queries = gen.generate("1.2.3.4", "ip", platforms=["splunk"])
    assert set(queries.keys()) == {"splunk"}


def test_generate_two_platforms(gen):
    queries = gen.generate("1.2.3.4", "ip", platforms=["splunk", "sentinel"])
    assert set(queries.keys()) == {"splunk", "sentinel"}


def test_generate_invalid_platform_raises(gen):
    with pytest.raises(ValueError, match="Unknown platform"):
        gen.generate("1.2.3.4", "ip", platforms=["databricks"])


# ---------------------------------------------------------------------------
# Unknown IOC type falls back to generic template
# ---------------------------------------------------------------------------


def test_unknown_ioc_type_uses_generic(gen):
    queries = gen.generate("some-indicator", "cve")
    assert set(queries.keys()) == set(PLATFORMS)
    for q in queries.values():
        assert "some-indicator" in q


# ---------------------------------------------------------------------------
# generate_from_investigation
# ---------------------------------------------------------------------------


def test_generate_from_investigation_ips(gen):
    inv_result = {"ips": ["1.2.3.4", "5.6.7.8"]}
    result = gen.generate_from_investigation(inv_result, platforms=["splunk"])
    assert "1.2.3.4" in result
    assert "5.6.7.8" in result
    assert "splunk" in result["1.2.3.4"]


def test_generate_from_investigation_nested_iocs(gen):
    inv_result = {
        "iocs": {
            "ip_addresses": ["10.0.0.1"],
            "domains": ["malicious.example.com"],
        }
    }
    result = gen.generate_from_investigation(inv_result, platforms=["elastic"])
    assert "10.0.0.1" in result
    assert "malicious.example.com" in result


def test_generate_from_investigation_hashes(gen):
    sha256 = "b" * 64
    inv_result = {"sha256": sha256}
    result = gen.generate_from_investigation(inv_result, platforms=["sentinel"])
    assert sha256 in result


def test_generate_from_investigation_empty(gen):
    result = gen.generate_from_investigation({})
    assert result == {}


# ---------------------------------------------------------------------------
# AI generation — mocked
# ---------------------------------------------------------------------------


def _make_mock_provider(return_content: str):
    mock_response = MagicMock()
    mock_response.content = return_content
    mock_response.tokens_used = 100
    mock_response.model = "mock-model"
    mock_response.provider = "anthropic"
    mock_response.thinking_trace = None

    mock_provider = MagicMock()
    mock_provider.is_available.return_value = True
    mock_provider.analyze.return_value = mock_response
    return mock_provider


def test_ai_generate_uses_provider_response(gen):
    ai_queries = {
        "splunk": 'index=* src_ip="1.2.3.4"',
        "sentinel": 'NetworkEvents | where SrcIpAddr == "1.2.3.4"',
    }
    mock_provider = _make_mock_provider(json.dumps(ai_queries))

    with patch("vlair.ai.providers.anthropic.AnthropicProvider", return_value=mock_provider):
        queries = gen.generate("1.2.3.4", "ip", platforms=["splunk", "sentinel"], use_ai=True)

    assert queries["splunk"] == ai_queries["splunk"]
    assert queries["sentinel"] == ai_queries["sentinel"]


def test_ai_generate_falls_back_to_template_on_error(gen):
    with patch("vlair.ai.providers.anthropic.AnthropicProvider", side_effect=Exception("no provider")):
        queries = gen.generate("1.2.3.4", "ip", use_ai=True)

    # Should fall back to templates, which always contain the value
    assert "1.2.3.4" in queries["splunk"]


def test_ai_generate_strips_markdown_fence(gen):
    raw = '```json\n{"splunk": "index=* src_ip=\\"1.2.3.4\\""}\n```'
    mock_provider = _make_mock_provider(raw)

    with patch("vlair.ai.providers.anthropic.AnthropicProvider", return_value=mock_provider):
        queries = gen.generate("1.2.3.4", "ip", platforms=["splunk"], use_ai=True)

    assert "splunk" in queries
    assert "1.2.3.4" in queries["splunk"]


# ---------------------------------------------------------------------------
# IOC extraction helper
# ---------------------------------------------------------------------------


def test_extract_iocs_direct_fields():
    result = {
        "ips": ["1.2.3.4"],
        "domains": ["evil.com"],
        "urls": ["http://evil.com/path"],
        "emails": ["a@b.com"],
    }
    iocs = SiemQueryGenerator._extract_iocs(result)
    assert iocs.get("1.2.3.4") == "ip"
    assert iocs.get("evil.com") == "domain"
    assert iocs.get("http://evil.com/path") == "url"
    assert iocs.get("a@b.com") == "email"


def test_extract_iocs_hash_fields():
    iocs = SiemQueryGenerator._extract_iocs({"md5": "abc123", "sha256": "def456"})
    assert iocs.get("abc123") == "hash_md5"
    assert iocs.get("def456") == "hash_sha256"


def test_extract_iocs_nested():
    result = {"iocs": {"ip_addresses": ["9.9.9.9"], "sha256s": ["cafebabe"]}}
    iocs = SiemQueryGenerator._extract_iocs(result)
    assert iocs.get("9.9.9.9") == "ip"
    assert iocs.get("cafebabe") == "hash_sha256"
