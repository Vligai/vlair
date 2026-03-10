"""
vlair AI Playbook Generator — Phase 6.3: AI-powered incident response playbook generation.

Uses Claude (or any configured AI provider) to generate step-by-step IR playbooks.
Falls back to built-in heuristic templates when no AI provider is available.
"""

import json
import os
import re
from typing import Optional

# ---------------------------------------------------------------------------
# Built-in heuristic templates (used when AI is unavailable)
# ---------------------------------------------------------------------------

_HEURISTIC_PLAYBOOKS: dict = {
    "phishing": {
        "title": "Incident Response: Phishing Email",
        "incident_type": "phishing",
        "severity": "HIGH",
        "steps": [
            {
                "step": 1,
                "title": "Triage",
                "time": "0-5 min",
                "actions": [
                    "Collect the suspected phishing email (full headers + body)",
                    "Record the reporter's name, time received, and any actions taken",
                    "Assign a case ID and severity",
                ],
            },
            {
                "step": 2,
                "title": "Contain",
                "time": "5-15 min",
                "actions": [
                    "Block sender address and domain in email gateway",
                    "Pull back / quarantine the email from all mailboxes",
                    "Suspend any clicked links in URL rewriting proxy",
                ],
            },
            {
                "step": 3,
                "title": "Investigate",
                "time": "15-60 min",
                "actions": [
                    "Extract IOCs: sender domain, reply-to, URLs, attachment hashes",
                    "Run vlair analyze on attachment hashes and URLs",
                    "Check SPF/DKIM/DMARC authentication results",
                    "Search SIEM for other recipients and click events",
                ],
            },
            {
                "step": 4,
                "title": "Scope",
                "time": "30-90 min",
                "actions": [
                    "Identify all recipients of the phishing campaign",
                    "Determine who opened, clicked, or executed attachments",
                    "Check EDR for process executions or downloads on affected hosts",
                ],
            },
            {
                "step": 5,
                "title": "Eradicate",
                "time": "60-120 min",
                "actions": [
                    "Block all extracted IOCs at firewall, proxy, and DNS",
                    "Reset credentials for any users who entered credentials",
                    "Isolate hosts where malware execution was confirmed",
                ],
            },
            {
                "step": 6,
                "title": "Recover",
                "time": "120+ min",
                "actions": [
                    "Restore affected hosts from clean backup if needed",
                    "Re-enable email flow after gateway rules are validated",
                    "Notify affected users with security awareness guidance",
                ],
            },
            {
                "step": 7,
                "title": "Post-Incident",
                "time": "24-48 h",
                "actions": [
                    "Write incident report with timeline and IOCs",
                    "Update detection rules (YARA, SIGMA, email gateway signatures)",
                    "Submit threat intelligence to sharing platforms (MISP, ISACs)",
                    "Conduct lessons-learned review",
                ],
            },
        ],
        "siem_queries": {
            "splunk": 'index=email_logs (subject="*" OR from="*") | stats count by from, to, subject',
            "elastic": '{"query": {"match": {"email.from.address": "<SENDER_DOMAIN>"}}}',
            "qradar": "SELECT * FROM events WHERE \"Email From\" ILIKE '%<SENDER_DOMAIN>%'",
        },
        "containment_actions": [
            "Block sender domain in email security gateway",
            "Quarantine email from all mailboxes",
            "Disable clicked URLs via proxy block list",
            "Force password reset for affected users",
        ],
        "eradication_actions": [
            "Remove malicious email from all mailboxes",
            "Block all extracted IOCs at perimeter",
            "Isolate and reimage compromised endpoints",
        ],
        "recovery_actions": [
            "Restore clean system images where needed",
            "Re-enable services after validation",
            "Notify impacted users and provide guidance",
        ],
        "lessons_learned": [
            "Review email gateway configuration",
            "Consider additional phishing simulation training",
            "Update playbook with new IOC types encountered",
        ],
    },
    "ransomware": {
        "title": "Incident Response: Ransomware",
        "incident_type": "ransomware",
        "severity": "CRITICAL",
        "steps": [
            {
                "step": 1,
                "title": "Immediate Detection",
                "time": "0-5 min",
                "actions": [
                    "Confirm ransomware activity (ransom note, encrypted files, EDR alert)",
                    "Activate IR team and notify management",
                    "Do NOT reboot affected systems without guidance",
                ],
            },
            {
                "step": 2,
                "title": "Emergency Containment",
                "time": "5-15 min",
                "actions": [
                    "Isolate affected hosts from network (physical disconnect or VLAN quarantine)",
                    "Block ransomware C2 indicators at firewall",
                    "Disable affected user accounts to prevent lateral movement",
                    "Suspend affected network shares to prevent spread",
                ],
            },
            {
                "step": 3,
                "title": "Scope Assessment",
                "time": "15-60 min",
                "actions": [
                    "Identify all encrypted systems and data",
                    "Determine patient zero and initial infection vector",
                    "Search SIEM/EDR for lateral movement activity",
                    "Assess backup integrity and availability",
                ],
            },
            {
                "step": 4,
                "title": "Forensic Preservation",
                "time": "30-90 min",
                "actions": [
                    "Capture memory dumps from affected systems if safe",
                    "Preserve system logs before they are overwritten",
                    "Document all encrypted file types and ransom note contents",
                    "Collect network logs for IOC extraction",
                ],
            },
            {
                "step": 5,
                "title": "Eradicate",
                "time": "2-24 h",
                "actions": [
                    "Remove ransomware binaries from all infected systems",
                    "Clean persistence mechanisms (registry, scheduled tasks, services)",
                    "Patch the vulnerability used for initial access",
                ],
            },
            {
                "step": 6,
                "title": "Recover",
                "time": "1-7 days",
                "actions": [
                    "Restore systems from verified clean backups",
                    "Validate backup integrity before restoration",
                    "Rebuild systems where backups are unavailable",
                    "Restore network connectivity in stages",
                ],
            },
            {
                "step": 7,
                "title": "Post-Incident",
                "time": "7-14 days",
                "actions": [
                    "File incident report (legal, regulatory, insurance)",
                    "Notify affected parties per breach notification laws",
                    "Implement recommended hardening measures",
                    "Conduct red team exercise to validate defences",
                ],
            },
        ],
        "siem_queries": {
            "splunk": "index=endpoint (vssadmin delete OR bcdedit OR wbadmin delete) | stats count by host",
            "elastic": '{"query": {"match": {"process.name": "vssadmin.exe"}}}',
        },
        "containment_actions": [
            "Network-isolate all affected hosts",
            "Block ransomware C2 IPs and domains at firewall",
            "Suspend affected Active Directory accounts",
            "Disable SMB on unaffected hosts as precaution",
        ],
        "eradication_actions": [
            "Remove ransomware binaries and persistence",
            "Patch initial access vulnerability",
            "Rotate all privileged credentials",
        ],
        "recovery_actions": [
            "Restore from verified clean backups",
            "Rebuild unrecoverable systems",
            "Validate restored data integrity",
        ],
        "lessons_learned": [
            "Review backup strategy (offline/immutable copies)",
            "Segment network to limit lateral movement",
            "Deploy EDR with ransomware rollback capability",
        ],
    },
    "c2": {
        "title": "Incident Response: Command & Control Beacon",
        "incident_type": "c2",
        "severity": "HIGH",
        "steps": [
            {
                "step": 1,
                "title": "Alert Triage",
                "time": "0-10 min",
                "actions": [
                    "Confirm C2 beacon via network logs (regular intervals, beaconing pattern)",
                    "Identify affected host and associated user account",
                    "Check EDR for process establishing the connection",
                ],
            },
            {
                "step": 2,
                "title": "Contain",
                "time": "10-30 min",
                "actions": [
                    "Block C2 IP / domain at firewall and DNS",
                    "Isolate affected host from production network",
                    "Terminate identified malicious process if safe to do so",
                ],
            },
            {
                "step": 3,
                "title": "Investigate",
                "time": "30-120 min",
                "actions": [
                    "Identify initial infection vector (phishing, drive-by, supply chain)",
                    "Extract full C2 infrastructure (IPs, domains, certificates)",
                    "Check for lateral movement and credential theft",
                    "Identify data accessed or exfiltrated",
                ],
            },
            {
                "step": 4,
                "title": "Eradicate",
                "time": "1-4 h",
                "actions": [
                    "Remove malware and persistence mechanisms from all affected hosts",
                    "Block full C2 infrastructure at all enforcement points",
                    "Reset compromised credentials",
                ],
            },
            {
                "step": 5,
                "title": "Recover",
                "time": "4-24 h",
                "actions": [
                    "Restore affected hosts from clean baseline",
                    "Re-enable network connectivity after validation",
                    "Monitor for re-infection",
                ],
            },
        ],
        "siem_queries": {
            "splunk": "index=network dest_ip=<C2_IP> | stats count by src_ip, dest_port",
            "elastic": '{"query": {"match": {"destination.ip": "<C2_IP>"}}}',
        },
        "containment_actions": [
            "Block C2 infrastructure at perimeter firewall",
            "Network-isolate affected host",
            "Disable affected user accounts pending investigation",
        ],
        "eradication_actions": [
            "Remove implant and all persistence mechanisms",
            "Patch exploited vulnerability",
            "Rotate compromised credentials",
        ],
        "recovery_actions": [
            "Restore host from clean snapshot",
            "Re-enable in monitored environment",
            "Hunt for additional compromised hosts",
        ],
        "lessons_learned": [
            "Improve network egress monitoring",
            "Deploy DNS sinkholing for known C2 domains",
            "Implement application allowlisting",
        ],
    },
    "data_exfil": {
        "title": "Incident Response: Data Exfiltration",
        "incident_type": "data_exfil",
        "severity": "CRITICAL",
        "steps": [
            {
                "step": 1,
                "title": "Detect and Triage",
                "time": "0-15 min",
                "actions": [
                    "Confirm data exfiltration via DLP, proxy, or UEBA alert",
                    "Identify data type and classification",
                    "Notify legal, privacy, and executive teams",
                ],
            },
            {
                "step": 2,
                "title": "Contain",
                "time": "15-30 min",
                "actions": [
                    "Block outbound connections to exfiltration destination",
                    "Suspend affected user and service accounts",
                    "Preserve network logs for forensics",
                ],
            },
            {
                "step": 3,
                "title": "Scope",
                "time": "30-120 min",
                "actions": [
                    "Determine volume and types of data exfiltrated",
                    "Identify all affected data subjects",
                    "Assess breach notification obligations",
                ],
            },
            {
                "step": 4,
                "title": "Eradicate",
                "time": "2-8 h",
                "actions": [
                    "Remove attacker access (malware, backdoors, compromised accounts)",
                    "Revoke exposed API keys and service credentials",
                    "Patch exploited vulnerability",
                ],
            },
            {
                "step": 5,
                "title": "Recover and Notify",
                "time": "1-7 days",
                "actions": [
                    "Notify affected individuals per GDPR / state privacy laws",
                    "File regulatory notifications within required timeframes",
                    "Implement additional DLP controls",
                ],
            },
        ],
        "siem_queries": {
            "splunk": "index=proxy bytes_out>10000000 | stats sum(bytes_out) by src_ip, dest",
            "elastic": '{"query": {"range": {"network.bytes": {"gte": 10000000}}}}',
        },
        "containment_actions": [
            "Block destination at firewall and proxy",
            "Revoke exposed credentials immediately",
            "Enable enhanced logging on affected systems",
        ],
        "eradication_actions": [
            "Remove malware and persistence",
            "Rotate all potentially exposed secrets",
        ],
        "recovery_actions": [
            "Restore affected systems to clean state",
            "Implement additional access controls",
        ],
        "lessons_learned": [
            "Review DLP policy coverage",
            "Implement data classification and labelling",
            "Strengthen egress filtering",
        ],
    },
}


# ---------------------------------------------------------------------------
# Playbook Generator
# ---------------------------------------------------------------------------


class PlaybookGenerator:
    """
    Generate step-by-step incident response playbooks using Claude (or a
    heuristic fallback when AI is unavailable).

    Phase 6.3: Automated Playbook Generation.
    """

    def __init__(self, config=None) -> None:
        self._config = config
        self._provider = None  # lazy-initialised

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Return True if an AI provider is available."""
        try:
            provider = self._get_provider()
            return provider is not None and provider.is_available()
        except Exception:
            return False

    def generate(
        self,
        incident_type: str,
        context: Optional[dict] = None,
        depth: str = "standard",
    ) -> dict:
        """
        Generate an IR playbook for the given incident type.

        Args:
            incident_type: "phishing", "ransomware", "c2", "data_exfil", etc.
            context:       Optional context dict (affected_systems, tools_available, …).
            depth:         "quick" | "standard" | "thorough"

        Returns:
            Playbook dict with title, steps, SIEM queries, and remediation actions.
        """
        context = context or {}

        # Try AI generation first
        if self.is_available():
            try:
                return self._generate_with_ai(incident_type, context, depth)
            except Exception:
                pass

        # Fall back to heuristic templates
        return self._generate_heuristic(incident_type, context)

    def generate_from_analysis(self, analysis_result: dict, ai_result: dict) -> dict:
        """
        Generate a playbook from a vlair analyze result + AI assessment.

        Args:
            analysis_result: Dict from Analyzer.analyze().
            ai_result:       Dict from ThreatSummarizer.summarize().

        Returns:
            Playbook dict.
        """
        # Infer incident type from analysis result and AI verdict
        incident_type = self._infer_incident_type(analysis_result, ai_result)
        context = {
            "verdict": ai_result.get("verdict", "UNKNOWN"),
            "severity": ai_result.get("severity", "HIGH"),
            "ioc_type": analysis_result.get("type", "unknown"),
            "mitre_techniques": ai_result.get("mitre_attack", []),
            "key_findings": ai_result.get("key_findings", []),
        }
        return self.generate(incident_type, context)

    # ------------------------------------------------------------------
    # AI generation
    # ------------------------------------------------------------------

    def _generate_with_ai(self, incident_type: str, context: dict, depth: str) -> dict:
        """Generate a playbook using the configured AI provider."""
        from vlair.ai.prompts import SECURITY_ANALYST_SYSTEM_PROMPT  # noqa: PLC0415

        max_tokens = {"quick": 1000, "standard": 2000, "thorough": 3000}.get(depth, 2000)

        system_prompt = (
            SECURITY_ANALYST_SYSTEM_PROMPT
            + "\n\nYou are generating a structured incident response playbook. "
            "Output valid JSON only. Do not include any explanation outside the JSON object."
        )

        context_str = json.dumps(context, indent=2, default=str) if context else "{}"
        user_message = (
            f"Generate a detailed incident response playbook for: {incident_type}\n\n"
            f"Context:\n{context_str}\n\n"
            "Return a JSON object with these keys:\n"
            "  title, incident_type, severity, steps (list of step objects with: step, title, time, actions),\n"
            "  siem_queries (dict with splunk/elastic/qradar keys), containment_actions,\n"
            "  eradication_actions, recovery_actions, lessons_learned\n\n"
            "Each step should have 3-5 concrete actions. Steps should cover: Triage, Contain, "
            "Investigate, Scope, Eradicate, Recover, Post-Incident."
        )

        provider = self._get_provider()
        response = provider.analyze(system_prompt, user_message, max_tokens=max_tokens)

        return self._parse_ai_playbook(response.content, incident_type)

    def _parse_ai_playbook(self, content: str, incident_type: str) -> dict:
        """Parse AI-generated playbook JSON from response content."""
        # Try to extract JSON from the response
        json_match = re.search(r"\{[\s\S]+\}", content)
        if json_match:
            try:
                parsed = json.loads(json_match.group(0))
                if "steps" in parsed:
                    return parsed
            except (json.JSONDecodeError, KeyError):
                pass

        # Fallback if AI response can't be parsed
        return self._generate_heuristic(incident_type, {})

    # ------------------------------------------------------------------
    # Heuristic generation
    # ------------------------------------------------------------------

    def _generate_heuristic(self, incident_type: str, context: dict) -> dict:
        """Return a built-in heuristic playbook template."""
        # Normalise incident type
        normalised = incident_type.lower().replace("-", "_").replace(" ", "_")
        aliases = {
            "phishing_email": "phishing",
            "email_phishing": "phishing",
            "bec": "phishing",
            "c2_beacon": "c2",
            "command_and_control": "c2",
            "command_control": "c2",
            "c2_activity": "c2",
            "ransomware_attack": "ransomware",
            "crypto_ransomware": "ransomware",
            "exfiltration": "data_exfil",
            "data_theft": "data_exfil",
            "data_breach": "data_exfil",
        }
        normalised = aliases.get(normalised, normalised)

        playbook = _HEURISTIC_PLAYBOOKS.get(normalised)
        if playbook is None:
            # Generic fallback
            playbook = {
                "title": f"Incident Response: {incident_type.replace('_', ' ').title()}",
                "incident_type": incident_type,
                "severity": context.get("severity", "HIGH"),
                "steps": [
                    {
                        "step": 1,
                        "title": "Triage",
                        "time": "0-15 min",
                        "actions": [
                            "Confirm incident and collect initial evidence",
                            "Assign severity and owner",
                        ],
                    },
                    {
                        "step": 2,
                        "title": "Contain",
                        "time": "15-60 min",
                        "actions": ["Isolate affected systems", "Block known IOCs at perimeter"],
                    },
                    {
                        "step": 3,
                        "title": "Eradicate",
                        "time": "1-4 h",
                        "actions": ["Remove malicious artefacts", "Patch vulnerabilities"],
                    },
                    {
                        "step": 4,
                        "title": "Recover",
                        "time": "4-24 h",
                        "actions": ["Restore from clean backup", "Monitor for recurrence"],
                    },
                    {
                        "step": 5,
                        "title": "Post-Incident",
                        "time": "1-7 days",
                        "actions": [
                            "Write incident report",
                            "Update detection rules",
                            "Lessons learned review",
                        ],
                    },
                ],
                "siem_queries": {},
                "containment_actions": ["Isolate affected hosts", "Block IOCs at firewall"],
                "eradication_actions": ["Remove malware", "Patch vulnerability"],
                "recovery_actions": ["Restore from backup", "Validate integrity"],
                "lessons_learned": ["Review detection capabilities", "Update playbooks"],
            }
        else:
            import copy

            playbook = copy.deepcopy(playbook)

        # Enrich with context if provided
        if context.get("mitre_techniques"):
            playbook["mitre_techniques"] = context["mitre_techniques"]
        if context.get("key_findings"):
            playbook["context_findings"] = context["key_findings"]

        return playbook

    # ------------------------------------------------------------------
    # Provider helpers
    # ------------------------------------------------------------------

    def _get_provider(self):
        if self._provider is not None:
            return self._provider

        # Use config if provided
        if self._config is not None:
            provider_name = getattr(self._config, "provider", "anthropic")
        else:
            provider_name = os.getenv("VLAIR_AI_PROVIDER", "anthropic")

        provider = self._build_provider(provider_name)
        self._provider = provider
        return provider

    def _build_provider(self, name: str):
        """Instantiate the appropriate AI provider."""
        name = name.lower()
        try:
            if name == "anthropic":
                from vlair.ai.providers.anthropic import AnthropicProvider  # noqa: PLC0415

                return AnthropicProvider()
            elif name == "openai":
                from vlair.ai.providers.openai import OpenAIProvider  # noqa: PLC0415

                return OpenAIProvider()
            elif name == "ollama":
                from vlair.ai.providers.ollama import OllamaProvider  # noqa: PLC0415

                return OllamaProvider()
        except Exception:
            pass
        return None

    def _infer_incident_type(self, analysis_result: dict, ai_result: dict) -> str:
        """Infer the most appropriate playbook type from analysis context."""
        ioc_type = str(analysis_result.get("type", "")).lower()
        mitre = " ".join(ai_result.get("mitre_attack", [])).lower()
        findings = " ".join(ai_result.get("key_findings", [])).lower()
        context = (mitre + " " + findings).lower()

        if ioc_type == "email" or "phishing" in context or "bec" in context:
            return "phishing"
        if "ransomware" in context or "encryption" in context or "t1486" in context:
            return "ransomware"
        if "c2" in context or "beacon" in context or "command" in context or "t1071" in context:
            return "c2"
        if "exfil" in context or "t1041" in context or "t1048" in context:
            return "data_exfil"
        return "generic"
