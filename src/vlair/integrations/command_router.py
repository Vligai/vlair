"""
vlair Command Router — routes @vlair <cmd> <args> to vlair tools and the AI layer.
"""

import os
import re
from typing import Dict, List, Optional, Tuple


HELP_TEXT = """*vlair Security Assistant* — available commands:

• `analyze <hash|domain|ip|url>` — auto-detect IOC type, run threat intelligence, return verdict + risk score
• `investigate <text>` — extract IOCs from free text and summarise findings
• `workflow <name>` — guidance for a named investigation workflow
  _Available workflows: phishing-email, malware-triage, ioc-hunt, network-forensics, log-investigation_
• `explain <term>` — explain a security concept or finding in plain language
• `ask <question>` — free-form AI question (uses thread context when available)
• `summary` — AI summary of all findings posted in the current thread
• `status` — check which API keys and integrations are configured
• `help` — show this message

_Tip: mention me inside a thread to keep context from the whole conversation._
"""

# Regex to strip the @mention prefix (e.g. "<@U12345> " or "@vlair ")
_MENTION_RE = re.compile(r"^(<@[A-Z0-9]+>|@vlair)\s*", re.IGNORECASE)


def _first_available_provider():
    """
    Try providers in order (Anthropic → OpenAI → Ollama) and return the first
    one that reports is_available(). Returns None if none are available.
    """
    try:
        from vlair.ai.providers.anthropic import AnthropicProvider

        p = AnthropicProvider()
        if p.is_available():
            return p
    except ImportError:
        pass

    try:
        from vlair.ai.providers.openai import OpenAIProvider

        p = OpenAIProvider()
        if p.is_available():
            return p
    except ImportError:
        pass

    try:
        from vlair.ai.providers.ollama import OllamaProvider

        p = OllamaProvider()
        if p.is_available():
            return p
    except ImportError:
        pass

    return None


class CommandRouter:
    """Routes parsed bot commands to the appropriate vlair tool or AI provider."""

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def parse_command(self, text: str) -> Tuple[str, str]:
        """
        Strip the @mention prefix and split into (command, args).

        Examples
        --------
        "<@U123> analyze malicious.com" → ("analyze", "malicious.com")
        "help"                          → ("help", "")
        """
        text = _MENTION_RE.sub("", text).strip()
        parts = text.split(None, 1)
        if not parts:
            return ("help", "")
        command = parts[0].lower()
        args = parts[1].strip() if len(parts) > 1 else ""
        return command, args

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    def route(
        self,
        command: str,
        args: str,
        thread_context: Optional[List[Dict]] = None,
    ) -> Dict:
        """
        Dispatch *command* with *args* and return a result dict::

            {
                "text":       str,   # human-readable response
                "error":      bool,
                "raw_result": dict | None,
            }
        """
        handlers = {
            "analyze": self._handle_analyze,
            "investigate": self._handle_investigate,
            "workflow": self._handle_workflow,
            "explain": self._handle_explain,
            "ask": self._handle_ask,
            "summary": self._handle_summary,
            "status": self._handle_status,
            "help": self._handle_help,
        }

        handler = handlers.get(command)
        if handler is None:
            return self._unknown_command(command)

        try:
            if command in ("ask", "summary"):
                return handler(args, thread_context=thread_context)
            return handler(args)
        except Exception as exc:  # pragma: no cover
            return {
                "text": f"An unexpected error occurred: {exc}",
                "error": True,
                "raw_result": None,
            }

    # ------------------------------------------------------------------
    # Individual handlers
    # ------------------------------------------------------------------

    def _handle_help(self, args: str) -> Dict:
        return {"text": HELP_TEXT, "error": False, "raw_result": None}

    def _handle_status(self, args: str) -> Dict:
        checks = {
            "VT_API_KEY": "VirusTotal",
            "ABUSEIPDB_KEY": "AbuseIPDB",
            "ANTHROPIC_API_KEY": "Anthropic AI",
            "OPENAI_API_KEY": "OpenAI",
        }
        lines = ["*vlair Status*\n"]
        for env_var, label in checks.items():
            configured = bool(os.environ.get(env_var))
            icon = "green_circle" if configured else "red_circle"
            status = "configured" if configured else "not set"
            lines.append(f":{icon}: {label} — {status}")

        # Check Ollama availability
        try:
            from vlair.ai.providers.ollama import OllamaProvider

            ollama_available = OllamaProvider().is_available()
        except ImportError:
            ollama_available = False
        icon = "green_circle" if ollama_available else "white_circle"
        lines.append(
            f":{icon}: Ollama (local) — {'available' if ollama_available else 'not detected'}"
        )

        return {"text": "\n".join(lines), "error": False, "raw_result": None}

    def _handle_analyze(self, args: str) -> Dict:
        if not args:
            return {
                "text": "Please provide a target to analyze. Example: `analyze malicious.com`",
                "error": True,
                "raw_result": None,
            }

        target = args.split()[0]

        try:
            from vlair.core.analyzer import Analyzer

            analyzer = Analyzer()
            result = analyzer.analyze(target)
        except Exception as exc:
            return {
                "text": f"Analysis failed: {exc}",
                "error": True,
                "raw_result": None,
            }

        verdict = result.get("verdict", "Unknown")
        risk_score = result.get("risk_score", 0)
        input_type = result.get("type", "unknown")
        findings = result.get("findings", [])

        # Attempt AI enrichment
        ai_summary = ""
        try:
            from vlair.ai import ThreatSummarizer

            summarizer = ThreatSummarizer()
            if summarizer.is_available():
                tool_results = result.get("tool_results", {})
                ai_resp = summarizer.summarize(target, input_type, tool_results)
                if ai_resp and not getattr(ai_resp, "error", False):
                    ai_summary = f"\n\n*AI Insight:* {getattr(ai_resp, 'summary', '')}"
        except Exception:
            pass

        # Risk score emoji
        if risk_score >= 70:
            risk_icon = ":red_circle:"
        elif risk_score >= 40:
            risk_icon = ":large_yellow_circle:"
        else:
            risk_icon = ":large_green_circle:"

        lines = [
            f"*Analysis: {target}*",
            f"{risk_icon} Verdict: *{verdict}* | Risk Score: *{risk_score}/100* | Type: {input_type}",
        ]
        if findings:
            lines.append("\n*Key Findings:*")
            for finding in findings[:5]:
                lines.append(f"• {finding}")

        lines.append(ai_summary)

        return {
            "text": "\n".join(lines).strip(),
            "error": False,
            "raw_result": result,
        }

    def _handle_investigate(self, args: str) -> Dict:
        if not args:
            return {
                "text": "Please provide text to investigate. Example: `investigate Check this IP 8.8.8.8`",
                "error": True,
                "raw_result": None,
            }

        try:
            from vlair.tools.ioc_extractor import IOCExtractor

            extractor = IOCExtractor()
            iocs = extractor.extract_from_text(args)
        except Exception as exc:
            return {
                "text": f"IOC extraction failed: {exc}",
                "error": True,
                "raw_result": None,
            }

        total = sum(len(v) for v in iocs.values() if isinstance(v, list))
        if total == 0:
            return {
                "text": "No IOCs detected in the provided text.",
                "error": False,
                "raw_result": iocs,
            }

        lines = [f"*IOC Extraction Results* — {total} indicator(s) found:\n"]
        ioc_labels = {
            "ips": "IP Addresses",
            "domains": "Domains",
            "urls": "URLs",
            "emails": "Email Addresses",
            "hashes": "File Hashes",
            "cves": "CVEs",
        }
        for key, label in ioc_labels.items():
            items = iocs.get(key, [])
            if items:
                lines.append(f"*{label}:* {', '.join(str(i) for i in items[:10])}")
                if len(items) > 10:
                    lines.append(f"  _...and {len(items) - 10} more_")

        lines.append("\n_Use `analyze <ioc>` to get threat intelligence on any indicator._")

        return {
            "text": "\n".join(lines),
            "error": False,
            "raw_result": iocs,
        }

    def _handle_workflow(self, args: str) -> Dict:
        workflow_name = args.split()[0].lower() if args else ""
        workflows = {
            "phishing-email": (
                "*Phishing Email Investigation Workflow*\n"
                "Run: `vlair workflow phishing-email <email.eml>`\n\n"
                "Steps:\n"
                "1. Parse email headers and metadata\n"
                "2. Validate SPF / DKIM / DMARC authentication\n"
                "3. Extract all IOCs (links, attachments, IPs)\n"
                "4. Check sender domain reputation\n"
                "5. Hash and submit attachments to VirusTotal\n"
                "6. Analyze embedded URLs\n"
                "7. Calculate verdict and recommended actions"
            ),
            "malware-triage": (
                "*Malware Triage Workflow*\n"
                "Run: `vlair workflow malware-triage <sample.exe>`\n\n"
                "Steps:\n"
                "1. Hash file (MD5, SHA1, SHA256)\n"
                "2. Query VirusTotal and MalwareBazaar\n"
                "3. Run YARA rules against sample\n"
                "4. Attempt script deobfuscation (if applicable)\n"
                "5. Extract embedded IOCs\n"
                "6. Classify malware family\n"
                "7. Generate triage report"
            ),
            "ioc-hunt": (
                "*IOC Hunt Workflow*\n"
                "Run: `vlair workflow ioc-hunt <iocs.txt>`\n\n"
                "Steps:\n"
                "1. Parse IOC list (IPs, domains, hashes, URLs)\n"
                "2. Batch threat intelligence lookups\n"
                "3. Score and classify each IOC\n"
                "4. Correlate related indicators\n"
                "5. Generate pivot queries for SIEM\n"
                "6. Export results (JSON / CSV)"
            ),
            "network-forensics": (
                "*Network Forensics Workflow*\n"
                "Run: `vlair workflow network-forensics <capture.pcap>`\n\n"
                "Steps:\n"
                "1. Parse PCAP / PCAPNG file\n"
                "2. Extract protocol statistics\n"
                "3. Detect port scans and beaconing\n"
                "4. Analyse DNS queries for DGA patterns\n"
                "5. Inspect HTTP payloads for threats\n"
                "6. Extract embedded files (file carving)\n"
                "7. Generate network forensics report"
            ),
            "log-investigation": (
                "*Log Investigation Workflow*\n"
                "Run: `vlair workflow log-investigation <access.log>`\n\n"
                "Steps:\n"
                "1. Auto-detect log format (Apache / Nginx / syslog)\n"
                "2. Parse and normalise log entries\n"
                "3. Detect web attacks (SQLi, XSS, path traversal)\n"
                "4. Identify brute-force and scanner activity\n"
                "5. Build traffic and attacker statistics\n"
                "6. Enrich top attacker IPs with threat intelligence\n"
                "7. Generate investigation timeline"
            ),
        }

        if workflow_name in workflows:
            return {
                "text": workflows[workflow_name],
                "error": False,
                "raw_result": None,
            }

        available = ", ".join(f"`{w}`" for w in workflows)
        return {
            "text": (
                f"Workflows cannot run directly inside the bot — they need local file access.\n\n"
                f"Available workflows: {available}\n\n"
                f"Use `workflow <name>` to see the steps for a specific workflow,\n"
                f"or run `vlair workflow <name> <file>` from the command line."
            ),
            "error": False,
            "raw_result": None,
        }

    def _handle_explain(self, args: str) -> Dict:
        if not args:
            return {
                "text": "Please provide a term to explain. Example: `explain lateral movement`",
                "error": True,
                "raw_result": None,
            }

        provider = _first_available_provider()
        if provider is None:
            return {
                "text": (
                    "No AI provider is configured. Set `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`,\n"
                    "or start a local Ollama instance to enable AI-powered explanations."
                ),
                "error": False,
                "raw_result": None,
            }

        system_prompt = (
            "You are a concise security expert assistant. "
            "Explain security concepts clearly for SOC analysts. "
            "Keep explanations under 200 words and use plain language."
        )
        user_message = f"Explain this security concept or finding in plain language: {args}"

        try:
            response = provider.analyze(system_prompt, user_message, max_tokens=400)
            text = getattr(response, "content", str(response))
            return {"text": text, "error": False, "raw_result": None}
        except Exception as exc:
            return {
                "text": f"AI explanation failed: {exc}",
                "error": True,
                "raw_result": None,
            }

    def _handle_ask(self, args: str, thread_context: Optional[List[Dict]] = None) -> Dict:
        if not args:
            return {
                "text": "Please provide a question. Example: `ask Is 8.8.8.8 likely malicious?`",
                "error": True,
                "raw_result": None,
            }

        provider = _first_available_provider()
        if provider is None:
            return {
                "text": (
                    "No AI provider is configured. Set `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`,\n"
                    "or start a local Ollama instance to enable AI-powered Q&A."
                ),
                "error": False,
                "raw_result": None,
            }

        system_prompt = (
            "You are a helpful security operations assistant. "
            "Answer questions concisely and accurately. "
            "Focus on practical, actionable guidance for SOC analysts."
        )

        context_block = ""
        if thread_context:
            context_lines = []
            for msg in thread_context[-8:]:  # last 8 messages for context
                role = msg.get("role", "user")
                content = msg.get("content", "")
                context_lines.append(f"{role.upper()}: {content}")
            context_block = "Thread context:\n" + "\n".join(context_lines) + "\n\n"

        user_message = context_block + f"Question: {args}"

        try:
            response = provider.analyze(system_prompt, user_message, max_tokens=600)
            text = getattr(response, "content", str(response))
            return {"text": text, "error": False, "raw_result": None}
        except Exception as exc:
            return {
                "text": f"AI Q&A failed: {exc}",
                "error": True,
                "raw_result": None,
            }

    def _handle_summary(self, args: str, thread_context: Optional[List[Dict]] = None) -> Dict:
        if not thread_context:
            return {
                "text": "No thread context available to summarise.",
                "error": False,
                "raw_result": None,
            }

        provider = _first_available_provider()
        if provider is None:
            # Fallback: simple text summary without AI
            assistant_msgs = [m["content"] for m in thread_context if m.get("role") == "assistant"]
            if not assistant_msgs:
                return {
                    "text": "No bot responses found in this thread to summarise.",
                    "error": False,
                    "raw_result": None,
                }
            summary = f"*Thread Summary ({len(assistant_msgs)} finding(s)):*\n" + "\n---\n".join(
                f"• {m[:200]}" for m in assistant_msgs
            )
            return {"text": summary, "error": False, "raw_result": None}

        system_prompt = (
            "You are a security analyst assistant. "
            "Summarise the security findings and key conclusions from this thread. "
            "Be concise — maximum 300 words. List the most important action items."
        )
        context_lines = []
        for msg in thread_context:
            role = msg.get("role", "user")
            content = msg.get("content", "")
            context_lines.append(f"{role.upper()}: {content}")
        user_message = "Summarise the security findings in this thread:\n\n" + "\n".join(
            context_lines
        )

        try:
            response = provider.analyze(system_prompt, user_message, max_tokens=500)
            text = getattr(response, "content", str(response))
            return {"text": f"*Thread Summary*\n{text}", "error": False, "raw_result": None}
        except Exception as exc:
            return {
                "text": f"Summary generation failed: {exc}",
                "error": True,
                "raw_result": None,
            }

    def _unknown_command(self, command: str) -> Dict:
        return {
            "text": (f"Unknown command: `{command}`\n\n" "Type `help` to see available commands."),
            "error": True,
            "raw_result": None,
        }
