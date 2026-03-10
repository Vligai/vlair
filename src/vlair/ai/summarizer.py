"""
vlair AI Analysis — ThreatSummarizer: Claude-powered threat intelligence summaries.

Updated in Phase 6.1 to support:
  - Provider abstraction (anthropic / openai / ollama)
  - Persistent SQLite cache via AIResponseCache
  - dry_run parameter to preview data sent to AI
"""

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .prompts import build_prompt, get_system_prompt

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class SummaryConfig:
    model: str = "claude-sonnet-4-6"
    depth: str = "standard"  # quick | standard | thorough
    max_tokens: int = 1500
    temperature: float = 0.2
    use_cache: bool = True
    cache_ttl_seconds: int = 86400  # 24 hours
    provider: str = "anthropic"  # anthropic | openai | ollama


# ---------------------------------------------------------------------------
# Legacy in-memory cache (kept for backward compatibility when use_cache=False)
# ---------------------------------------------------------------------------

_LEGACY_CACHE: Dict[str, Tuple[float, dict]] = {}


# ---------------------------------------------------------------------------
# Main summarizer
# ---------------------------------------------------------------------------


class ThreatSummarizer:
    """
    Calls an AI provider to generate structured threat assessments from vlair tool results.

    Supports Anthropic (default), OpenAI, and Ollama via the provider abstraction layer.
    Responses are cached in a persistent SQLite database under ~/.vlair/ai_cache.db.

    Usage::

        summarizer = ThreatSummarizer()
        if summarizer.is_available():
            result = summarizer.summarize("44d88612...", "hash", tool_result_dict)
    """

    def __init__(self, config: Optional[SummaryConfig] = None) -> None:
        self.config = config or SummaryConfig()
        self._provider = None  # lazy-initialised
        self._cache: Optional[Any] = None  # lazy-initialised (AIResponseCache)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Return True if the configured AI provider is available."""
        try:
            provider = self._get_provider()
            return provider.is_available()
        except Exception:
            return False

    def summarize(
        self,
        ioc_value: str,
        ioc_type: str,
        tool_result: dict,
        depth: Optional[str] = None,
        dry_run: bool = False,
    ) -> dict:
        """
        Generate a structured AI threat summary.

        Args:
            ioc_value:   Primary indicator string (hash, domain, filename, …)
            ioc_type:    Analysis type: hash|domain|ip|url|email|log|pcap|cert|script|ioc
            tool_result: Parsed JSON result from a vlair tool endpoint
            depth:       Override config depth: quick|standard|thorough
            dry_run:     If True, return a preview of what would be sent without calling AI

        Returns:
            Dict with verdict, severity, key_findings, threat_context,
            recommended_actions, mitre_attack, confidence_notes, metadata.
        """
        effective_depth = depth or self.config.depth

        # Dry-run mode: return description of data that would be sent
        if dry_run:
            from .privacy import get_dry_run_summary  # noqa: PLC0415

            summary = get_dry_run_summary(ioc_value, ioc_type, tool_result)
            return {
                "verdict": "DRY_RUN",
                "severity": "INFO",
                "confidence": 0.0,
                "key_findings": ["Dry-run mode: no AI call was made."],
                "threat_context": summary,
                "recommended_actions": [],
                "mitre_attack": [],
                "confidence_notes": "",
                "metadata": {
                    "model": self.config.model,
                    "tokens_used": 0,
                    "cached": False,
                    "analysis_time_ms": 0,
                    "dry_run": True,
                },
            }

        cache_key = self._cache_key(ioc_value, ioc_type, tool_result, effective_depth)

        if self.config.use_cache:
            cached = self._cache_get(cache_key)
            if cached is not None:
                cached["metadata"]["cached"] = True
                return cached

        result = self._call_provider(ioc_value, ioc_type, tool_result, effective_depth, cache_key)
        return result

    # ------------------------------------------------------------------
    # Private helpers — provider
    # ------------------------------------------------------------------

    def _get_provider(self):
        if self._provider is not None:
            return self._provider

        provider_name = self.config.provider or os.getenv("VLAIR_AI_PROVIDER", "anthropic")

        try:
            if provider_name == "anthropic":
                from .providers.anthropic import AnthropicProvider  # noqa: PLC0415

                p = AnthropicProvider(model=self.config.model, temperature=self.config.temperature)
            elif provider_name == "openai":
                from .providers.openai import OpenAIProvider  # noqa: PLC0415

                p = OpenAIProvider(temperature=self.config.temperature)
            elif provider_name == "ollama":
                from .providers.ollama import OllamaProvider  # noqa: PLC0415

                p = OllamaProvider()
            else:
                # Default to Anthropic
                from .providers.anthropic import AnthropicProvider  # noqa: PLC0415

                p = AnthropicProvider(model=self.config.model, temperature=self.config.temperature)
        except ImportError:
            # If provider package not installed, fall back
            from .providers.anthropic import AnthropicProvider  # noqa: PLC0415

            p = AnthropicProvider(model=self.config.model, temperature=self.config.temperature)

        self._provider = p
        return p

    # ------------------------------------------------------------------
    # Private helpers — persistent cache
    # ------------------------------------------------------------------

    def _get_cache(self):
        if self._cache is None:
            try:
                from .cache import AIResponseCache  # noqa: PLC0415

                self._cache = AIResponseCache(ttl_hours=self.config.cache_ttl_seconds // 3600)
            except Exception:
                self._cache = None
        return self._cache

    def _cache_get(self, key: str) -> Optional[dict]:
        """Try persistent cache first, then fall back to legacy in-memory cache."""
        cache = self._get_cache()
        if cache is not None:
            return cache.get(key)

        # Legacy fallback
        entry = _LEGACY_CACHE.get(key)
        if entry is None:
            return None
        ts, result = entry
        if time.time() - ts > self.config.cache_ttl_seconds:
            del _LEGACY_CACHE[key]
            return None
        return dict(result)

    def _cache_set(self, key: str, result: dict, tokens_used: int = 0) -> None:
        """Store in persistent cache; also update legacy in-memory cache as fallback."""
        cache = self._get_cache()
        if cache is not None:
            try:
                provider_name = str(getattr(self._provider, "name", "anthropic")) if self._provider else "anthropic"
                model_name = str(getattr(self._provider, "model", self.config.model)) if self._provider else self.config.model
                cache.set(key, result, tokens_used=tokens_used, provider=provider_name, model=model_name)
            except Exception:
                # Fallback to legacy cache if SQLite write fails
                pass
        # Always keep in-memory copy too
        _LEGACY_CACHE[key] = (time.time(), result)

    # ------------------------------------------------------------------
    # Private helpers — cache key
    # ------------------------------------------------------------------

    def _cache_key(self, ioc_value: str, ioc_type: str, tool_result: dict, depth: str) -> str:
        raw = f"{ioc_value}|{ioc_type}|{json.dumps(tool_result, sort_keys=True, default=str)}|{depth}"
        return hashlib.sha256(raw.encode()).hexdigest()

    # ------------------------------------------------------------------
    # Private helpers — AI call
    # ------------------------------------------------------------------

    def _call_provider(
        self,
        ioc_value: str,
        ioc_type: str,
        tool_result: dict,
        depth: str,
        cache_key: str,
    ) -> dict:
        t_start = time.time()

        max_tokens = self.config.max_tokens
        if depth == "quick":
            max_tokens = min(max_tokens, 600)
        elif depth == "thorough":
            max_tokens = max(max_tokens, 2000)

        system_prompt = get_system_prompt(ioc_type)
        user_message = build_prompt(ioc_value, ioc_type, tool_result, depth)

        provider = self._get_provider()
        response = provider.analyze(system_prompt, user_message, max_tokens=max_tokens)

        elapsed_ms = int((time.time() - t_start) * 1000)
        tokens_used = response.tokens_used
        content = response.content

        parsed = self._parse_response(content)
        parsed["metadata"] = {
            "model": response.model or self.config.model,
            "provider": response.provider or self.config.provider,
            "tokens_used": tokens_used,
            "cached": False,
            "analysis_time_ms": elapsed_ms,
        }

        if self.config.use_cache:
            self._cache_set(cache_key, parsed, tokens_used=tokens_used)

        return parsed

    # ------------------------------------------------------------------
    # Private helpers — response parser (unchanged from v1)
    # ------------------------------------------------------------------

    def _parse_response(self, content: str) -> dict:
        """
        Extract structured fields from the AI's free-text response.
        All fields fall back gracefully if missing.
        """
        result: Dict[str, Any] = {
            "verdict": "UNKNOWN",
            "severity": "INFO",
            "confidence": 0.5,
            "key_findings": [],
            "threat_context": "",
            "recommended_actions": [],
            "mitre_attack": [],
            "confidence_notes": "",
        }

        # VERDICT
        m = re.search(r"VERDICT\s*:\s*(MALICIOUS|SUSPICIOUS|CLEAN|UNKNOWN)", content, re.IGNORECASE)
        if m:
            result["verdict"] = m.group(1).upper()

        # Confidence percentage
        m = re.search(r"\((\d+(?:\.\d+)?)\s*%\s*confidence\)", content, re.IGNORECASE)
        if m:
            result["confidence"] = round(float(m.group(1)) / 100.0, 4)

        # SEVERITY
        m = re.search(r"SEVERITY\s*:\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)", content, re.IGNORECASE)
        if m:
            result["severity"] = m.group(1).upper()

        # KEY FINDINGS
        kf_match = re.search(
            r"KEY FINDINGS\s*:(.*?)(?:THREAT CONTEXT|RECOMMENDED ACTIONS|MITRE|CONFIDENCE NOTES|$)",
            content,
            re.IGNORECASE | re.DOTALL,
        )
        if kf_match:
            block = kf_match.group(1)
            bullets = re.findall(r"[•\-\*]\s*(.+)", block)
            if not bullets:
                bullets = re.findall(r"\d+\.\s+(.+)", block)
            result["key_findings"] = [b.strip() for b in bullets[:5] if b.strip()]

        # THREAT CONTEXT
        tc_match = re.search(
            r"THREAT CONTEXT\s*:(.*?)(?:RECOMMENDED ACTIONS|MITRE|CONFIDENCE NOTES|$)",
            content,
            re.IGNORECASE | re.DOTALL,
        )
        if tc_match:
            result["threat_context"] = tc_match.group(1).strip()

        # RECOMMENDED ACTIONS (IMMEDIATE / SHORT-TERM / LONG-TERM)
        actions: List[dict] = []
        for priority, pattern in [
            ("immediate", r"IMMEDIATE\s*:\s*(.+?)(?:SHORT.TERM|LONG.TERM|MITRE|CONFIDENCE|$)"),
            ("short_term", r"SHORT.TERM\s*:\s*(.+?)(?:LONG.TERM|MITRE|CONFIDENCE|$)"),
            ("long_term", r"LONG.TERM\s*:\s*(.+?)(?:MITRE|CONFIDENCE|$)"),
        ]:
            am = re.search(pattern, content, re.IGNORECASE | re.DOTALL)
            if am:
                text = am.group(1).strip()
                items = [i.strip().lstrip("•-* ") for i in re.split(r"[\n•\-\*]", text) if i.strip().lstrip("•-* ")]
                for item in items[:3]:
                    if item:
                        actions.append({"priority": priority, "action": item})
        result["recommended_actions"] = actions

        # MITRE ATT&CK technique IDs
        mitre_ids = re.findall(r"\bT[AS]?\d{4}(?:\.\d{3})?\b", content)
        seen: set = set()
        unique_mitre: List[str] = []
        for tid in mitre_ids:
            if tid not in seen:
                seen.add(tid)
                unique_mitre.append(tid)
        result["mitre_attack"] = unique_mitre

        # CONFIDENCE NOTES
        cn_match = re.search(r"CONFIDENCE NOTES\s*:(.*?)$", content, re.IGNORECASE | re.DOTALL)
        if cn_match:
            result["confidence_notes"] = cn_match.group(1).strip()

        return result
