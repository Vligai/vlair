"""
vlair AI Analysis — ThreatSummarizer: Claude-powered threat intelligence summaries.
"""

import hashlib
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


# ---------------------------------------------------------------------------
# In-memory cache  (key → (timestamp, result_dict))
# ---------------------------------------------------------------------------

_CACHE: Dict[str, Tuple[float, dict]] = {}


# ---------------------------------------------------------------------------
# Main summarizer
# ---------------------------------------------------------------------------


class ThreatSummarizer:
    """
    Calls Claude to generate structured threat assessments from vlair tool results.

    Usage::

        summarizer = ThreatSummarizer()
        if summarizer.is_available():
            result = summarizer.summarize("44d88612...", "hash", tool_result_dict)
    """

    def __init__(self, config: Optional[SummaryConfig] = None) -> None:
        self.config = config or SummaryConfig()
        self._client = None  # lazy-initialised

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Return True if ANTHROPIC_API_KEY is set."""
        return bool(os.getenv("ANTHROPIC_API_KEY"))

    def summarize(
        self,
        ioc_value: str,
        ioc_type: str,
        tool_result: dict,
        depth: Optional[str] = None,
    ) -> dict:
        """
        Generate a structured AI threat summary.

        Args:
            ioc_value:   Primary indicator string (hash, domain, filename, …)
            ioc_type:    Analysis type: hash|domain|ip|url|email|log|pcap|cert|script|ioc
            tool_result: Parsed JSON result from a vlair tool endpoint
            depth:       Override config depth: quick|standard|thorough

        Returns:
            Dict with verdict, severity, key_findings, threat_context,
            recommended_actions, mitre_attack, confidence_notes, metadata.
        """
        effective_depth = depth or self.config.depth

        cache_key = self._cache_key(ioc_value, ioc_type, tool_result, effective_depth)

        if self.config.use_cache:
            cached = self._get_cached(cache_key)
            if cached is not None:
                cached["metadata"]["cached"] = True
                return cached

        result = self._call_claude(ioc_value, ioc_type, tool_result, effective_depth, cache_key)
        return result

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_client(self):
        if self._client is None:
            import anthropic  # noqa: PLC0415

            self._client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        return self._client

    def _cache_key(self, ioc_value: str, ioc_type: str, tool_result: dict, depth: str) -> str:
        import json

        raw = (
            f"{ioc_value}|{ioc_type}|{json.dumps(tool_result, sort_keys=True, default=str)}|{depth}"
        )
        return hashlib.sha256(raw.encode()).hexdigest()

    def _get_cached(self, key: str) -> Optional[dict]:
        entry = _CACHE.get(key)
        if entry is None:
            return None
        ts, result = entry
        if time.time() - ts > self.config.cache_ttl_seconds:
            del _CACHE[key]
            return None
        return dict(result)  # shallow copy

    def _set_cached(self, key: str, result: dict) -> None:
        _CACHE[key] = (time.time(), result)

    def _call_claude(
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

        client = self._get_client()
        response = client.messages.create(
            model=self.config.model,
            max_tokens=max_tokens,
            temperature=self.config.temperature,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
        )

        elapsed_ms = int((time.time() - t_start) * 1000)
        tokens_used = response.usage.input_tokens + response.usage.output_tokens
        content = response.content[0].text if response.content else ""

        parsed = self._parse_response(content)
        parsed["metadata"] = {
            "model": self.config.model,
            "tokens_used": tokens_used,
            "cached": False,
            "analysis_time_ms": elapsed_ms,
        }

        if self.config.use_cache:
            self._set_cached(cache_key, parsed)

        return parsed

    def _parse_response(self, content: str) -> dict:
        """
        Extract structured fields from Claude's free-text response.
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

        # KEY FINDINGS — bullet points after "KEY FINDINGS:"
        kf_match = re.search(
            r"KEY FINDINGS\s*:(.*?)(?:THREAT CONTEXT|RECOMMENDED ACTIONS|MITRE|CONFIDENCE NOTES|$)",
            content,
            re.IGNORECASE | re.DOTALL,
        )
        if kf_match:
            block = kf_match.group(1)
            bullets = re.findall(r"[•\-\*]\s*(.+)", block)
            # Also pick up numbered bullets like "1. ..."
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
                # Split on newlines/bullets to get individual action items
                items = [
                    i.strip().lstrip("•-* ")
                    for i in re.split(r"[\n•\-\*]", text)
                    if i.strip().lstrip("•-* ")
                ]
                for item in items[:3]:  # cap at 3 per priority
                    if item:
                        actions.append({"priority": priority, "action": item})
        result["recommended_actions"] = actions

        # MITRE ATT&CK technique IDs
        mitre_ids = re.findall(r"\bT[AS]?\d{4}(?:\.\d{3})?\b", content)
        # deduplicate while preserving order
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
