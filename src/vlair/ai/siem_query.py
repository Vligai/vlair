#!/usr/bin/env python3
"""
vlair AI — SIEM Query Generator

Given one or more IOCs (or a full investigation result), generate ready-to-paste
detection queries for Splunk SPL, Elastic ESQL, Microsoft Sentinel KQL, and
Sumo Logic.

Template generation works offline.  AI-powered generation requires a configured
AI provider (ANTHROPIC_API_KEY, OPENAI_API_KEY, or local Ollama).
"""

import json
from typing import Dict, List, Optional, Union

# ---------------------------------------------------------------------------
# Supported platforms
# ---------------------------------------------------------------------------

PLATFORMS = ["splunk", "elastic", "sentinel", "sumo"]

# ---------------------------------------------------------------------------
# IOC type → query templates
# ---------------------------------------------------------------------------

_TEMPLATES: Dict[str, Dict[str, str]] = {
    "ip": {
        "splunk": (
            'index=* (src_ip="{value}" OR dest_ip="{value}" OR '
            'ClientIP="{value}" OR c-ip="{value}")\n'
            "| stats count by src_ip, dest_ip, host, sourcetype\n"
            "| sort -count"
        ),
        "elastic": (
            "FROM logs-*\n"
            '| WHERE source.ip == "{value}" OR destination.ip == "{value}" '
            'OR client.ip == "{value}"\n'
            "| STATS count(*) BY source.ip, destination.ip, host.name"
        ),
        "sentinel": (
            'let target_ip = "{value}";\n'
            "union isfuzzy=true\n"
            "  (NetworkEvents | where SrcIpAddr == target_ip or DstIpAddr == target_ip),\n"
            "  (DeviceNetworkEvents | where RemoteIP == target_ip or LocalIP == target_ip),\n"
            "  (CommonSecurityLog | where SourceIP == target_ip or DestinationIP == target_ip)\n"
            "| project TimeGenerated, Computer, SrcIpAddr, DstIpAddr, RemoteIP"
        ),
        "sumo": (
            '_sourceCategory=* ("{value}")\n'
            '| where src_ip = "{value}" or dst_ip = "{value}"\n'
            "| count by src_ip, dst_ip, _sourceHost"
        ),
    },
    "domain": {
        "splunk": (
            'index=* (query="{value}" OR url="*{value}*" OR '
            'site="{value}" OR hostname="{value}")\n'
            "| stats count by src_ip, query, url\n"
            "| sort -count"
        ),
        "elastic": (
            "FROM logs-*\n"
            '| WHERE dns.question.name == "{value}" OR url.domain == "{value}" '
            'OR host.hostname == "{value}"\n'
            "| STATS count(*) BY dns.question.name, source.ip, url.full"
        ),
        "sentinel": (
            'let target_domain = "{value}";\n'
            "union isfuzzy=true\n"
            '  (DnsEvents | where Name == target_domain or Name endswith strcat(".", target_domain)),\n'
            "  (NetworkEvents | where RemoteUrl has target_domain),\n"
            "  (DeviceNetworkEvents | where RemoteUrl has target_domain)\n"
            "| project TimeGenerated, Computer, Name, RemoteUrl, RemoteIP"
        ),
        "sumo": (
            '_sourceCategory=* ("{value}")\n'
            '| parse "* " as domain\n'
            '| where domain matches "*{value}*"\n'
            "| count by domain, _sourceHost"
        ),
    },
    "hash_md5": {
        "splunk": (
            'index=* (md5="{value}" OR file_hash="{value}" OR hash="{value}")\n'
            "| stats count by host, process_name, file_path, user\n"
            "| sort -count"
        ),
        "elastic": (
            "FROM logs-*\n"
            '| WHERE hash.md5 == "{value}" OR file.hash.md5 == "{value}"\n'
            "| STATS count(*) BY host.name, process.name, file.path"
        ),
        "sentinel": (
            'let target_hash = "{value}";\n'
            "union isfuzzy=true\n"
            "  (DeviceFileEvents | where MD5 == target_hash),\n"
            "  (DeviceProcessEvents | where MD5 == target_hash)\n"
            "| project TimeGenerated, DeviceName, FileName, FolderPath, MD5"
        ),
        "sumo": ('_sourceCategory=* md5="{value}"\n' "| count by host, file_path, process_name"),
    },
    "hash_sha1": {
        "splunk": (
            'index=* (sha1="{value}" OR file_hash="{value}" OR hash="{value}")\n'
            "| stats count by host, process_name, file_path, user\n"
            "| sort -count"
        ),
        "elastic": (
            "FROM logs-*\n"
            '| WHERE hash.sha1 == "{value}" OR file.hash.sha1 == "{value}"\n'
            "| STATS count(*) BY host.name, process.name, file.path"
        ),
        "sentinel": (
            'let target_hash = "{value}";\n'
            "union isfuzzy=true\n"
            "  (DeviceFileEvents | where SHA1 == target_hash),\n"
            "  (DeviceProcessEvents | where SHA1 == target_hash)\n"
            "| project TimeGenerated, DeviceName, FileName, FolderPath, SHA1"
        ),
        "sumo": ('_sourceCategory=* sha1="{value}"\n' "| count by host, file_path, process_name"),
    },
    "hash_sha256": {
        "splunk": (
            'index=* (sha256="{value}" OR file_hash="{value}" OR hash="{value}")\n'
            "| stats count by host, process_name, file_path, user\n"
            "| sort -count"
        ),
        "elastic": (
            "FROM logs-*\n"
            '| WHERE hash.sha256 == "{value}" OR file.hash.sha256 == "{value}"\n'
            "| STATS count(*) BY host.name, process.name, file.path"
        ),
        "sentinel": (
            'let target_hash = "{value}";\n'
            "union isfuzzy=true\n"
            "  (DeviceFileEvents | where SHA256 == target_hash),\n"
            "  (DeviceProcessEvents | where SHA256 == target_hash)\n"
            "| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256"
        ),
        "sumo": ('_sourceCategory=* sha256="{value}"\n' "| count by host, file_path, process_name"),
    },
    "url": {
        "splunk": (
            'index=* (url="{value}" OR cs-uri="{value}")\n'
            "| stats count by src_ip, url, status, user_agent\n"
            "| sort -count"
        ),
        "elastic": (
            "FROM logs-*\n"
            '| WHERE url.full == "{value}" OR url.original == "{value}"\n'
            "| STATS count(*) BY source.ip, url.full, http.response.status_code"
        ),
        "sentinel": (
            'let target_url = "{value}";\n'
            "union isfuzzy=true\n"
            "  (NetworkEvents | where RemoteUrl == target_url),\n"
            "  (DeviceNetworkEvents | where RemoteUrl == target_url)\n"
            "| project TimeGenerated, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessFileName"
        ),
        "sumo": ('_sourceCategory=* url="{value}"\n' "| count by src_ip, url, status"),
    },
    "email": {
        "splunk": (
            'index=* (sender="{value}" OR recipient="{value}" OR '
            'from="{value}" OR to="{value}" OR "reply-to"="{value}")\n'
            "| stats count by sender, recipient, subject\n"
            "| sort -count"
        ),
        "elastic": (
            "FROM logs-*\n"
            '| WHERE email.from.address == "{value}" OR email.to.address == "{value}"\n'
            "| STATS count(*) BY email.from.address, email.to.address, email.subject"
        ),
        "sentinel": (
            'let target_email = "{value}";\n'
            "EmailEvents\n"
            "| where SenderFromAddress == target_email or RecipientEmailAddress == target_email\n"
            "| project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject, DeliveryAction"
        ),
        "sumo": (
            '_sourceCategory=* ("{value}")\n'
            '| where sender = "{value}" or recipient = "{value}"\n'
            "| count by sender, recipient, subject"
        ),
    },
}

# Generic fallback when IOC type is not directly mapped
_GENERIC_TEMPLATE: Dict[str, str] = {
    "splunk": ('index=* "{value}"\n' "| stats count by host, sourcetype, source\n" "| sort -count"),
    "elastic": (
        "FROM logs-*\n"
        '| WHERE TO_LOWER(CONCAT(COALESCE(TO_STRING(message), ""), " ")) LIKE "%{value_lower}%"\n'
        "| STATS count(*) BY host.name"
    ),
    "sentinel": (
        'search "{value}"\n' "| summarize count() by $table, Computer\n" "| sort by count_ desc"
    ),
    "sumo": ('_sourceCategory=* "{value}"\n' "| count by _sourceHost, _sourceName"),
}

# ---------------------------------------------------------------------------
# AI system prompt for SIEM query generation
# ---------------------------------------------------------------------------

_SIEM_SYSTEM_PROMPT = """
You are an expert SIEM engineer. Your task is to generate accurate, production-ready
detection queries for the platforms requested.

RULES:
1. Output ONLY a valid JSON object — no prose, no markdown fences.
2. Keys must be exactly: splunk, elastic, sentinel, sumo (only include requested platforms).
3. Values are the complete query strings (multi-line is fine with \\n).
4. Queries must search for the exact IOC value provided.
5. Include reasonable field aliases so the query works across common log sources.
6. Add a stats/aggregation step so analysts see hit counts, not raw events.
7. Use native query syntax: SPL for Splunk, ESQL for Elastic, KQL for Sentinel, keyword for Sumo.

OUTPUT FORMAT (example):
{
  "splunk": "index=* src_ip=\\"1.2.3.4\\" | stats count by host",
  "elastic": "FROM logs-* | WHERE source.ip == \\"1.2.3.4\\" | STATS count(*) BY host.name",
  "sentinel": "NetworkEvents | where SrcIpAddr == \\"1.2.3.4\\"",
  "sumo": "_sourceCategory=* src_ip=\\"1.2.3.4\\" | count by _sourceHost"
}
""".strip()


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------


class SiemQueryGenerator:
    """
    Generate SIEM detection queries for a given IOC across multiple platforms.

    Template generation works without any AI provider.
    Pass ``use_ai=True`` (and have a provider configured) for context-aware queries
    that take investigation findings into account.

    Usage::

        gen = SiemQueryGenerator()
        queries = gen.generate("1.2.3.4", "ip", platforms=["splunk", "sentinel"])
        print(queries["splunk"])
    """

    def generate(
        self,
        ioc_value: str,
        ioc_type: str,
        platforms: Optional[List[str]] = None,
        investigation_context: Optional[dict] = None,
        use_ai: bool = False,
    ) -> Dict[str, str]:
        """
        Generate SIEM queries for *ioc_value*.

        Args:
            ioc_value:              The indicator string (IP, domain, hash, URL, email).
            ioc_type:               Type hint from vlair detector output
                                    (ip, domain, hash_md5, hash_sha1, hash_sha256, url, email).
            platforms:              Subset of ``["splunk", "elastic", "sentinel", "sumo"]``;
                                    defaults to all four.
            investigation_context:  Optional dict with extra info (alerts, findings, etc.)
                                    passed to the AI for richer queries.
            use_ai:                 When True, attempt AI-powered generation first,
                                    falling back to templates on failure.

        Returns:
            Dict mapping platform name → query string.
        """
        target_platforms = [p.lower() for p in (platforms or PLATFORMS)]
        invalid = [p for p in target_platforms if p not in PLATFORMS]
        if invalid:
            raise ValueError(f"Unknown platform(s): {', '.join(invalid)}. Choose from {PLATFORMS}")

        if use_ai:
            try:
                return self._ai_generate(
                    ioc_value, ioc_type, target_platforms, investigation_context
                )
            except Exception:
                pass  # fall through to templates

        return self._template_generate(ioc_value, ioc_type, target_platforms)

    def generate_from_investigation(
        self,
        investigation_result: dict,
        platforms: Optional[List[str]] = None,
        use_ai: bool = False,
    ) -> Dict[str, Dict[str, str]]:
        """
        Generate SIEM queries for every IOC found in an investigation result dict.

        Returns a nested dict: {ioc_value: {platform: query}}.
        """
        target_platforms = platforms or PLATFORMS
        iocs = self._extract_iocs(investigation_result)
        results: Dict[str, Dict[str, str]] = {}

        for ioc_val, ioc_type in iocs.items():
            results[ioc_val] = self.generate(
                ioc_val,
                ioc_type,
                platforms=target_platforms,
                investigation_context=investigation_result,
                use_ai=use_ai,
            )

        return results

    # ------------------------------------------------------------------
    # Template generation
    # ------------------------------------------------------------------

    def _template_generate(self, value: str, ioc_type: str, platforms: List[str]) -> Dict[str, str]:
        templates = _TEMPLATES.get(ioc_type, _GENERIC_TEMPLATE)
        result: Dict[str, str] = {}
        for platform in platforms:
            tmpl = templates.get(
                platform, _GENERIC_TEMPLATE.get(platform, "# No template available")
            )
            result[platform] = tmpl.format(value=value, value_lower=value.lower())
        return result

    # ------------------------------------------------------------------
    # AI generation
    # ------------------------------------------------------------------

    def _ai_generate(
        self,
        value: str,
        ioc_type: str,
        platforms: List[str],
        context: Optional[dict],
    ) -> Dict[str, str]:
        from .providers.anthropic import AnthropicProvider

        provider = AnthropicProvider()
        if not provider.is_available():
            # Try OpenAI
            from .providers.openai import OpenAIProvider

            provider_oi = OpenAIProvider()
            if not provider_oi.is_available():
                raise RuntimeError("No AI provider available")
            ai_provider = provider_oi
        else:
            ai_provider = provider

        platform_list = ", ".join(platforms)
        user_msg = (
            f"Generate detection queries for the following IOC.\n\n"
            f"IOC value: {value}\n"
            f"IOC type: {ioc_type}\n"
            f"Platforms: {platform_list}\n"
        )
        if context:
            ctx_snippet = json.dumps(context, default=str)[:2000]
            user_msg += f"\nInvestigation context (excerpt):\n{ctx_snippet}\n"

        user_msg += f"\nReturn ONLY the JSON object with keys: {platform_list}."

        response = ai_provider.analyze(
            system_prompt=_SIEM_SYSTEM_PROMPT,
            user_message=user_msg,
            max_tokens=1500,
        )

        # Parse JSON from response
        content = response.content.strip()
        # Strip optional markdown fences if the model added them
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
            content = content.strip()

        parsed = json.loads(content)
        return {k: str(v) for k, v in parsed.items() if k in platforms}

    # ------------------------------------------------------------------
    # IOC extraction helper
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_iocs(investigation_result: dict) -> Dict[str, str]:
        """Pull IOCs from a vlair investigation/tool result, returning {value: type}."""
        iocs: Dict[str, str] = {}

        # Direct IOC fields from investigation results
        for ioc_type, key in [
            ("ip", "ips"),
            ("ip", "ip_addresses"),
            ("domain", "domains"),
            ("url", "urls"),
            ("email", "emails"),
        ]:
            for val in investigation_result.get(key, []):
                if val:
                    iocs[str(val)] = ioc_type

        # Hash fields
        for hash_type in ("md5", "sha1", "sha256"):
            for val in investigation_result.get(f"{hash_type}s", []):
                if val:
                    iocs[str(val)] = f"hash_{hash_type}"
            # Also check hashes dict
            hash_val = investigation_result.get(hash_type)
            if hash_val:
                iocs[str(hash_val)] = f"hash_{hash_type}"

        # Nested 'iocs' sub-dict (IOC extractor output)
        nested = investigation_result.get("iocs", {})
        if isinstance(nested, dict):
            for key, vals in nested.items():
                if not isinstance(vals, list):
                    continue
                if "ip" in key:
                    ioc_type = "ip"
                elif "domain" in key:
                    ioc_type = "domain"
                elif "url" in key:
                    ioc_type = "url"
                elif "email" in key:
                    ioc_type = "email"
                elif "md5" in key:
                    ioc_type = "hash_md5"
                elif "sha256" in key:
                    ioc_type = "hash_sha256"
                elif "sha1" in key:
                    ioc_type = "hash_sha1"
                else:
                    continue
                for val in vals:
                    if val:
                        iocs.setdefault(str(val), ioc_type)

        return iocs
