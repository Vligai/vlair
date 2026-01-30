"""
AI Analyzer - Main Orchestration for AI-Powered Analysis

Coordinates between threat intelligence tools, AI providers, caching,
and privacy controls to provide enhanced security analysis.
"""

import hashlib
import json
import time
from typing import Dict, Any, Optional, List
from dataclasses import dataclass

from .providers import get_provider, AIProvider, AIResponse
from .providers.base import Verdict, Severity, RecommendedAction
from .prompts.system import get_system_prompt
from .prompts.analysis import build_analysis_prompt, build_correlation_prompt
from .prompts.report import format_markdown_report, format_json_report
from .cache import AIResponseCache
from .privacy import DataSanitizer, PrivacyConfig


@dataclass
class AnalysisConfig:
    """Configuration for AI analysis"""
    provider: str = "openai"
    model: Optional[str] = None
    depth: str = "standard"  # quick, standard, thorough
    max_tokens: int = 2000
    temperature: float = 0.3
    use_cache: bool = True
    cache_ttl_hours: int = 24
    privacy_config: Optional[PrivacyConfig] = None


class AIAnalyzer:
    """
    Main AI analysis orchestrator.

    Coordinates threat intel gathering, AI analysis, caching, and privacy.
    """

    def __init__(self, config: Optional[AnalysisConfig] = None):
        """
        Initialize the AI analyzer.

        Args:
            config: Analysis configuration
        """
        self.config = config or AnalysisConfig()
        self._provider: Optional[AIProvider] = None
        self._cache: Optional[AIResponseCache] = None
        self._sanitizer = DataSanitizer(self.config.privacy_config)

        # Statistics tracking
        self._stats = {
            'total_requests': 0,
            'cache_hits': 0,
            'tokens_used': 0,
            'analysis_time_ms': 0,
        }

    @property
    def provider(self) -> AIProvider:
        """Lazy initialization of AI provider"""
        if self._provider is None:
            provider_kwargs = {}
            if self.config.model:
                provider_kwargs['model'] = self.config.model

            self._provider = get_provider(
                self.config.provider,
                **provider_kwargs
            )
        return self._provider

    @property
    def cache(self) -> AIResponseCache:
        """Lazy initialization of cache"""
        if self._cache is None:
            self._cache = AIResponseCache(ttl_hours=self.config.cache_ttl_hours)
        return self._cache

    def analyze(
        self,
        input_value: str,
        input_type: str,
        threat_intel: Dict[str, Any],
        behavioral_data: Optional[Dict[str, Any]] = None,
        org_context: Optional[Dict[str, str]] = None,
    ) -> AIResponse:
        """
        Perform AI-enhanced analysis of an IOC.

        Args:
            input_value: The IOC value (hash, domain, IP, etc.)
            input_type: Type of IOC
            threat_intel: Aggregated threat intelligence data
            behavioral_data: Optional sandbox/behavioral analysis data
            org_context: Optional organization context

        Returns:
            AIResponse with analysis results
        """
        start_time = time.time()
        self._stats['total_requests'] += 1

        # Sanitize data before processing
        sanitized_intel = self._sanitizer.sanitize(threat_intel)
        sanitized_behavioral = (
            self._sanitizer.sanitize(behavioral_data)
            if behavioral_data else None
        )

        # Check cache
        if self.config.use_cache:
            prompt_hash = self._get_prompt_hash(input_type, self.config.depth)
            cache_key = self.cache.get_cache_key(
                input_value,
                input_type,
                prompt_hash,
                self.provider.model
            )
            cached_response = self.cache.get(cache_key)
            if cached_response:
                self._stats['cache_hits'] += 1
                return cached_response

        # Build prompt
        prompt = build_analysis_prompt(
            input_type=input_type,
            input_value=input_value,
            threat_intel=sanitized_intel,
            depth=self.config.depth,
            behavioral_data=sanitized_behavioral,
            org_context=org_context
        )

        # Get system prompt
        system_prompt = get_system_prompt(input_type)

        # Send to AI provider
        response = self.provider.analyze(
            prompt=prompt,
            context={'system_prompt': system_prompt},
            max_tokens=self.config.max_tokens,
            temperature=self.config.temperature
        )

        # Parse structured data from response
        response = self._parse_response(response)

        # Update stats
        self._stats['tokens_used'] += response.tokens_used
        self._stats['analysis_time_ms'] += int((time.time() - start_time) * 1000)

        # Cache response
        if self.config.use_cache:
            self.cache.set(cache_key, response)

        return response

    def analyze_correlation(
        self,
        iocs: List[Dict[str, str]],
        threat_intel_results: Dict[str, Dict[str, Any]],
        org_context: Optional[Dict[str, str]] = None
    ) -> AIResponse:
        """
        Perform correlation analysis across multiple IOCs.

        Args:
            iocs: List of IOC dictionaries with 'type' and 'value' keys
            threat_intel_results: Dict mapping IOC values to their threat intel
            org_context: Optional organization context

        Returns:
            AIResponse with correlation analysis
        """
        start_time = time.time()
        self._stats['total_requests'] += 1

        # Sanitize all threat intel data
        sanitized_results = {
            ioc: self._sanitizer.sanitize(intel)
            for ioc, intel in threat_intel_results.items()
        }

        # Build correlation prompt
        prompt = build_correlation_prompt(
            iocs=iocs,
            threat_intel_results=sanitized_results,
            org_context=org_context
        )

        # Get correlation system prompt
        system_prompt = get_system_prompt('correlation')

        # Send to AI provider (correlation not cached due to complexity)
        response = self.provider.analyze(
            prompt=prompt,
            context={'system_prompt': system_prompt},
            max_tokens=self.config.max_tokens * 2,  # Larger for correlations
            temperature=self.config.temperature
        )

        # Parse structured data
        response = self._parse_response(response)

        # Update stats
        self._stats['tokens_used'] += response.tokens_used
        self._stats['analysis_time_ms'] += int((time.time() - start_time) * 1000)

        return response

    def generate_report(
        self,
        analysis_results: AIResponse,
        primary_ioc: str,
        report_format: str = "markdown"
    ) -> str:
        """
        Generate a formatted report from analysis results.

        Args:
            analysis_results: The AIResponse from analysis
            primary_ioc: The main IOC analyzed
            report_format: Output format (markdown, json)

        Returns:
            Formatted report string
        """
        if report_format == "json":
            report = format_json_report(
                analysis_results=analysis_results.to_dict(),
                primary_ioc=primary_ioc,
                metadata={'stats': self._stats}
            )
            return json.dumps(report, indent=2)
        else:
            return format_markdown_report(
                analysis_results=analysis_results.to_dict(),
                primary_ioc=primary_ioc
            )

    def get_transmission_preview(
        self,
        threat_intel: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Preview what data would be sent to the AI provider.

        Implements FR-9 dry-run capability.

        Args:
            threat_intel: Raw threat intelligence data

        Returns:
            Preview showing what will/won't be transmitted
        """
        return self._sanitizer.get_transmission_preview(threat_intel)

    def get_stats(self) -> Dict[str, Any]:
        """
        Get AI analysis statistics.

        Returns:
            Dictionary with usage statistics
        """
        cache_stats = self.cache.get_stats() if self._cache else {}

        return {
            'requests': {
                'total': self._stats['total_requests'],
                'cache_hits': self._stats['cache_hits'],
                'cache_hit_rate': (
                    self._stats['cache_hits'] / self._stats['total_requests']
                    if self._stats['total_requests'] > 0 else 0
                )
            },
            'tokens': {
                'total_used': self._stats['tokens_used'],
                'estimated_cost_usd': self._estimate_cost(self._stats['tokens_used'])
            },
            'performance': {
                'total_analysis_time_ms': self._stats['analysis_time_ms'],
                'avg_analysis_time_ms': (
                    self._stats['analysis_time_ms'] / self._stats['total_requests']
                    if self._stats['total_requests'] > 0 else 0
                )
            },
            'cache': cache_stats,
            'provider': {
                'name': self.provider.name if self._provider else self.config.provider,
                'model': self.provider.model if self._provider else self.config.model
            }
        }

    def _get_prompt_hash(self, input_type: str, depth: str) -> str:
        """Generate a hash representing the prompt template used"""
        template_id = f"{input_type}:{depth}:v1"
        return hashlib.sha256(template_id.encode()).hexdigest()[:16]

    def _parse_response(self, response: AIResponse) -> AIResponse:
        """
        Parse structured data from AI response content.

        Extracts verdict, severity, findings, etc. from the response text.
        """
        content = response.content

        # Extract verdict
        verdict = self._extract_verdict(content)
        if verdict:
            response.verdict = verdict

        # Extract severity
        severity = self._extract_severity(content)
        if severity:
            response.severity = severity

        # Extract key findings
        response.key_findings = self._extract_findings(content)

        # Extract threat context
        response.threat_context = self._extract_section(content, "Threat Context")

        # Extract recommended actions
        response.recommended_actions = self._extract_actions(content)

        # Extract MITRE ATT&CK
        response.mitre_attack = self._extract_mitre(content)

        # Extract confidence notes
        response.confidence_notes = self._extract_section(content, "Confidence Notes")

        return response

    def _extract_verdict(self, content: str) -> Optional[Verdict]:
        """Extract verdict from response"""
        import re
        match = re.search(
            r'VERDICT:\s*(MALICIOUS|SUSPICIOUS|CLEAN|UNKNOWN)',
            content,
            re.IGNORECASE
        )
        if match:
            verdict_str = match.group(1).upper()
            return Verdict[verdict_str]
        return None

    def _extract_severity(self, content: str) -> Optional[Severity]:
        """Extract severity from response"""
        import re
        match = re.search(
            r'SEVERITY:\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)',
            content,
            re.IGNORECASE
        )
        if match:
            severity_str = match.group(1).upper()
            return Severity[severity_str]
        return None

    def _extract_findings(self, content: str) -> List[str]:
        """Extract key findings bullet points"""
        import re
        findings = []

        # Look for "Key Findings:" section
        match = re.search(
            r'Key Findings:?\s*([\s\S]*?)(?=\n\n|\n[A-Z]|\Z)',
            content,
            re.IGNORECASE
        )
        if match:
            section = match.group(1)
            # Extract bullet points
            bullets = re.findall(r'[•\-\*]\s*(.+?)(?=\n|$)', section)
            findings.extend([b.strip() for b in bullets if b.strip()])

        return findings[:5]  # Limit to 5

    def _extract_section(self, content: str, section_name: str) -> Optional[str]:
        """Extract a named section from response"""
        import re
        pattern = rf'{section_name}:?\s*([\s\S]*?)(?=\n\n[A-Z]|\n##|\Z)'
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return None

    def _extract_actions(self, content: str) -> List[RecommendedAction]:
        """Extract recommended actions"""
        import re
        actions = []

        # Look for prioritized action sections
        patterns = [
            (r'IMMEDIATE[:\s]*([\s\S]*?)(?=\n\n|\nSHORT|\nLONG|\Z)', 'immediate'),
            (r'SHORT[- ]TERM[:\s]*([\s\S]*?)(?=\n\n|\nLONG|\Z)', 'short_term'),
            (r'LONG[- ]TERM[:\s]*([\s\S]*?)(?=\n\n|\Z)', 'long_term'),
        ]

        for pattern, priority in patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                section = match.group(1)
                # Extract numbered items
                items = re.findall(r'\d+\.\s*(.+?)(?=\n\d+\.|\n\n|\Z)', section)
                for item in items:
                    actions.append(RecommendedAction(
                        priority=priority,
                        action=item.strip(),
                        details=""
                    ))

        return actions

    def _extract_mitre(self, content: str) -> List[str]:
        """Extract MITRE ATT&CK technique IDs"""
        import re
        # Match patterns like T1566.001, T1059, TA0001
        matches = re.findall(r'T[AS]?\d{4}(?:\.\d{3})?', content)
        return list(set(matches))  # Deduplicate

    def _estimate_cost(self, tokens: int) -> float:
        """
        Estimate cost in USD based on tokens used.

        Uses approximate GPT-4 pricing as baseline.
        """
        # Approximate: $0.01 per 1K tokens (input + output average)
        return tokens * 0.00001


# Convenience function for quick analysis
def quick_analyze(
    input_value: str,
    input_type: str,
    threat_intel: Dict[str, Any],
    provider: str = "openai"
) -> AIResponse:
    """
    Convenience function for quick AI analysis.

    Args:
        input_value: The IOC value
        input_type: Type of IOC
        threat_intel: Threat intelligence data
        provider: AI provider to use

    Returns:
        AIResponse with analysis results
    """
    config = AnalysisConfig(provider=provider, depth="quick")
    analyzer = AIAnalyzer(config)
    return analyzer.analyze(input_value, input_type, threat_intel)
