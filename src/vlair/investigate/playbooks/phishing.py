#!/usr/bin/env python3
"""
Phishing Investigation Playbook - 10-step automated phishing analysis

Integrates existing vlair tools with enterprise connectors to perform
comprehensive phishing email investigations.
"""

import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional

from .base import BasePlaybook, PlaybookStep
from ..models import (
    InvestigationState,
    StepResult,
    StepStatus,
    RemediationAction,
    RemediationStatus,
)
from ..registry import PlaybookRegistry


class PhishingPlaybook(BasePlaybook):
    """
    10-step phishing investigation playbook.

    Steps:
    1. parse_email - Parse email using eml_parser
    2. validate_authentication - Check SPF/DKIM/DMARC
    3. extract_iocs - Extract IOCs using ioc_extractor
    4. check_sender_domain - Check sender domain reputation
    5. analyze_attachments - Check attachment hashes
    6. analyze_urls - Analyze extracted URLs
    7. find_recipients - Find all email recipients (via connector)
    8. find_clicks - Find users who clicked URLs (via SIEM)
    9. calculate_verdict - Calculate risk score and verdict
    10. prepare_remediation - Prepare remediation actions
    """

    @property
    def name(self) -> str:
        return "phishing"

    @property
    def description(self) -> str:
        return "Automated 10-step phishing email investigation"

    def _define_steps(self):
        """Define the playbook steps."""
        self.steps = [
            PlaybookStep(
                name="parse_email",
                description="Parse email file and extract metadata",
                required=True,
            ),
            PlaybookStep(
                name="validate_authentication",
                description="Validate SPF/DKIM/DMARC authentication",
                depends_on=["parse_email"],
            ),
            PlaybookStep(
                name="extract_iocs",
                description="Extract IOCs from email content",
                depends_on=["parse_email"],
            ),
            PlaybookStep(
                name="check_sender_domain",
                description="Check sender domain reputation",
                depends_on=["parse_email"],
            ),
            PlaybookStep(
                name="analyze_attachments",
                description="Analyze attachment hashes",
                depends_on=["parse_email"],
                required=False,
            ),
            PlaybookStep(
                name="analyze_urls",
                description="Analyze URLs for threats",
                depends_on=["extract_iocs"],
            ),
            PlaybookStep(
                name="find_recipients",
                description="Find all email recipients",
                depends_on=["parse_email"],
                required=False,
            ),
            PlaybookStep(
                name="find_clicks",
                description="Find users who clicked URLs",
                depends_on=["extract_iocs"],
                required=False,
            ),
            PlaybookStep(
                name="calculate_verdict",
                description="Calculate risk score and verdict",
                depends_on=[
                    "validate_authentication",
                    "check_sender_domain",
                    "analyze_urls",
                ],
            ),
            PlaybookStep(
                name="prepare_remediation",
                description="Prepare recommended remediation actions",
                depends_on=["calculate_verdict"],
            ),
        ]

    def _execute_step(
        self,
        step: PlaybookStep,
        state: InvestigationState,
        connectors: Dict[str, Any],
    ) -> StepResult:
        """Execute a single step."""
        step_handlers = {
            "parse_email": self._step_parse_email,
            "validate_authentication": self._step_validate_auth,
            "extract_iocs": self._step_extract_iocs,
            "check_sender_domain": self._step_check_sender,
            "analyze_attachments": self._step_analyze_attachments,
            "analyze_urls": self._step_analyze_urls,
            "find_recipients": self._step_find_recipients,
            "find_clicks": self._step_find_clicks,
            "calculate_verdict": self._step_calculate_verdict,
            "prepare_remediation": self._step_prepare_remediation,
        }

        handler = step_handlers.get(step.name)
        if handler:
            return handler(step, state, connectors)

        return StepResult(
            name=step.name,
            status=StepStatus.FAILED,
            error=f"Unknown step: {step.name}",
        )

    def _step_parse_email(
        self,
        step: PlaybookStep,
        state: InvestigationState,
        connectors: Dict[str, Any],
    ) -> StepResult:
        """Parse the email file."""
        file_path = state.inputs.get("file_path")
        if not file_path:
            return StepResult(
                name=step.name,
                status=StepStatus.FAILED,
                error="No file_path provided in inputs",
            )

        if not os.path.exists(file_path):
            return StepResult(
                name=step.name,
                status=StepStatus.FAILED,
                error=f"File not found: {file_path}",
            )

        try:
            # Use the eml_parser tool
            from vlair.tools.eml_parser import (
                parse_eml,
                extract_basic_headers,
                extract_ips_and_servers,
                extract_auth_results,
                extract_attachments,
                extract_body,
            )

            parsed = parse_eml(file_path)
            headers = extract_basic_headers(parsed)
            ips = extract_ips_and_servers(parsed)
            auth = extract_auth_results(parsed)
            attachments = extract_attachments(parsed)

            # Extract URLs from body content
            body_content = extract_body(parsed)
            urls = []
            for body in body_content:
                # Body text may contain URLs - extract them
                body_text = body.get("body_text", "")
                if body_text:
                    import re
                    found_urls = re.findall(r'https?://[^\s<>"\']+', body_text)
                    urls.extend(found_urls)

            # Store parsed data
            output = {
                "headers": headers,
                "ips": ips,
                "authentication": auth,
                "attachments": attachments,
                "urls": urls,
                "subject": headers.get("Subject", ""),
                "sender": headers.get("From", ""),
                "recipients": headers.get("To", []),
            }

            # Extract sender domain
            sender = headers.get("From", "")
            if "@" in sender:
                sender_domain = sender.split("@")[-1].rstrip(">").strip()
                output["sender_domain"] = sender_domain

            return StepResult(
                name=step.name,
                status=StepStatus.COMPLETED,
                output=output,
            )

        except Exception as e:
            return StepResult(
                name=step.name,
                status=StepStatus.FAILED,
                error=str(e),
            )

    def _step_validate_auth(
        self,
        step: PlaybookStep,
        state: InvestigationState,
        connectors: Dict[str, Any],
    ) -> StepResult:
        """Validate email authentication results."""
        # Get parsed email data from previous step
        parse_result = self._get_step_output(state, "parse_email")
        if not parse_result:
            return StepResult(
                name=step.name,
                status=StepStatus.FAILED,
                error="No parse_email output available",
            )

        auth = parse_result.get("authentication", {})

        # Analyze authentication results
        spf_result = auth.get("SPF", "N/A")
        dkim_result = auth.get("DKIM", "N/A")
        dmarc_result = auth.get("DMARC", "N/A")

        failures = []
        if "fail" in spf_result.lower():
            failures.append("SPF")
            state.add_finding("high", "SPF validation failed - sender may be spoofed", "validate_auth")
        if "fail" in dkim_result.lower():
            failures.append("DKIM")
            state.add_finding("medium", "DKIM validation failed", "validate_auth")
        if "fail" in dmarc_result.lower():
            failures.append("DMARC")
            state.add_finding("high", "DMARC validation failed", "validate_auth")

        output = {
            "spf": spf_result,
            "dkim": dkim_result,
            "dmarc": dmarc_result,
            "failures": failures,
            "all_passed": len(failures) == 0,
        }

        return StepResult(
            name=step.name,
            status=StepStatus.COMPLETED,
            output=output,
        )

    def _step_extract_iocs(
        self,
        step: PlaybookStep,
        state: InvestigationState,
        connectors: Dict[str, Any],
    ) -> StepResult:
        """Extract IOCs from email content."""
        file_path = state.inputs.get("file_path")

        try:
            from vlair.tools.ioc_extractor import IOCExtractor

            extractor = IOCExtractor(exclude_private_ips=True)

            # Read email content
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            iocs = extractor.extract_from_text(content)

            # Add IOCs to state
            if iocs.get("ips"):
                state.add_iocs("ips", iocs["ips"])
            if iocs.get("domains"):
                state.add_iocs("domains", iocs["domains"])
            if iocs.get("urls"):
                state.add_iocs("urls", iocs["urls"])
            if iocs.get("emails"):
                state.add_iocs("emails", iocs["emails"])
            if iocs.get("hashes"):
                hashes = iocs.get("md5", []) + iocs.get("sha1", []) + iocs.get("sha256", [])
                state.add_iocs("hashes", hashes)

            return StepResult(
                name=step.name,
                status=StepStatus.COMPLETED,
                output=iocs,
            )

        except Exception as e:
            return StepResult(
                name=step.name,
                status=StepStatus.FAILED,
                error=str(e),
            )

    def _step_check_sender(
        self,
        step: PlaybookStep,
        state: InvestigationState,
        connectors: Dict[str, Any],
    ) -> StepResult:
        """Check sender domain reputation."""
        parse_result = self._get_step_output(state, "parse_email")
        if not parse_result:
            return StepResult(
                name=step.name,
                status=StepStatus.FAILED,
                error="No parse_email output available",
            )

        sender_domain = parse_result.get("sender_domain")
        if not sender_domain:
            return StepResult(
                name=step.name,
                status=StepStatus.COMPLETED,
                output={"message": "No sender domain to check"},
            )

        try:
            from vlair.tools.domain_ip_intel import DomainIPIntelligence

            intel = DomainIPIntelligence(verbose=self.verbose)
            result = intel.lookup(sender_domain)

            # Check for malicious indicators
            verdict = result.get("verdict", "UNKNOWN")
            risk_score = result.get("risk_score", 0)

            if verdict == "MALICIOUS" or risk_score >= 70:
                state.add_finding(
                    "critical",
                    f"Sender domain {sender_domain} is malicious (risk: {risk_score})",
                    "check_sender"
                )
            elif verdict == "SUSPICIOUS" or risk_score >= 40:
                state.add_finding(
                    "high",
                    f"Sender domain {sender_domain} is suspicious (risk: {risk_score})",
                    "check_sender"
                )

            return StepResult(
                name=step.name,
                status=StepStatus.COMPLETED,
                output={
                    "domain": sender_domain,
                    "verdict": verdict,
                    "risk_score": risk_score,
                    "details": result,
                },
            )

        except Exception as e:
            return StepResult(
                name=step.name,
                status=StepStatus.COMPLETED,  # Non-critical failure
                output={"error": str(e), "domain": sender_domain},
            )

    def _step_analyze_attachments(
        self,
        step: PlaybookStep,
        state: InvestigationState,
        connectors: Dict[str, Any],
    ) -> StepResult:
        """Analyze attachment hashes."""
        parse_result = self._get_step_output(state, "parse_email")
        if not parse_result:
            return StepResult(
                name=step.name,
                status=StepStatus.SKIPPED,
                output={"message": "No parse_email output"},
            )

        attachments = parse_result.get("attachments", [])
        if not attachments:
            return StepResult(
                name=step.name,
                status=StepStatus.COMPLETED,
                output={"message": "No attachments to analyze"},
            )

        try:
            from vlair.tools.hash_lookup import HashLookup

            lookup = HashLookup(verbose=self.verbose)
            results = []

            for att in attachments:
                hashes = att.get("hashes", {})
                sha256 = hashes.get("sha256")

                if sha256 and sha256 != "N/A":
                    hash_result = lookup.lookup(sha256)
                    results.append({
                        "filename": att.get("filename"),
                        "sha256": sha256,
                        "result": hash_result,
                    })

                    # Add finding if malicious
                    if hash_result.get("verdict") == "MALICIOUS":
                        state.add_finding(
                            "critical",
                            f"Attachment '{att.get('filename')}' is malicious",
                            "analyze_attachments",
                            {"hash": sha256}
                        )
                        state.add_iocs("hashes", [sha256])

            return StepResult(
                name=step.name,
                status=StepStatus.COMPLETED,
                output={"attachments": results},
            )

        except Exception as e:
            return StepResult(
                name=step.name,
                status=StepStatus.COMPLETED,
                output={"error": str(e)},
            )

    def _step_analyze_urls(
        self,
        step: PlaybookStep,
        state: InvestigationState,
        connectors: Dict[str, Any],
    ) -> StepResult:
        """Analyze URLs for threats."""
        urls = state.iocs.get("urls", [])

        # Also get URLs from parsed email
        parse_result = self._get_step_output(state, "parse_email")
        if parse_result:
            email_urls = parse_result.get("urls", [])
            for url in email_urls:
                if url not in urls:
                    urls.append(url)
                    state.add_iocs("urls", [url])

        if not urls:
            return StepResult(
                name=step.name,
                status=StepStatus.COMPLETED,
                output={"message": "No URLs to analyze"},
            )

        try:
            from vlair.tools.url_analyzer import URLAnalyzer

            analyzer = URLAnalyzer(verbose=self.verbose)
            results = []
            malicious_urls = []

            for url in urls[:10]:  # Limit to 10 URLs
                try:
                    result = analyzer.analyze(url)
                    results.append({
                        "url": url,
                        "verdict": result.get("verdict", "UNKNOWN"),
                        "risk_score": result.get("risk_score", 0),
                        "threats": result.get("threats", []),
                    })

                    verdict = result.get("verdict", "UNKNOWN")
                    risk_score = result.get("risk_score", 0)

                    if verdict == "MALICIOUS" or risk_score >= 70:
                        malicious_urls.append(url)
                        state.add_finding(
                            "critical",
                            f"Malicious URL detected: {url}",
                            "analyze_urls",
                            {"risk_score": risk_score}
                        )
                    elif verdict == "SUSPICIOUS" or risk_score >= 40:
                        state.add_finding(
                            "high",
                            f"Suspicious URL detected: {url}",
                            "analyze_urls",
                            {"risk_score": risk_score}
                        )

                except Exception as e:
                    results.append({"url": url, "error": str(e)})

            return StepResult(
                name=step.name,
                status=StepStatus.COMPLETED,
                output={
                    "urls_analyzed": len(results),
                    "malicious_urls": malicious_urls,
                    "results": results,
                },
            )

        except Exception as e:
            return StepResult(
                name=step.name,
                status=StepStatus.COMPLETED,
                output={"error": str(e)},
            )

    def _step_find_recipients(
        self,
        step: PlaybookStep,
        state: InvestigationState,
        connectors: Dict[str, Any],
    ) -> StepResult:
        """Find all email recipients using email connector."""
        email_connector = connectors.get("email")

        parse_result = self._get_step_output(state, "parse_email")
        if not parse_result:
            return StepResult(
                name=step.name,
                status=StepStatus.SKIPPED,
                output={"message": "No parse_email output"},
            )

        # Get recipients from parsed email
        recipients = parse_result.get("recipients", [])
        if isinstance(recipients, str):
            recipients = [recipients]

        # If we have an email connector, try to find more recipients
        if email_connector:
            try:
                sender = parse_result.get("sender", "")
                subject = parse_result.get("subject", "")

                # Search for similar emails
                similar_emails = email_connector.search_messages(
                    sender=sender,
                    subject=subject,
                    limit=100,
                )

                for email in similar_emails:
                    for r in email.recipients:
                        if r not in recipients:
                            recipients.append(r)

            except Exception as e:
                pass  # Non-critical

        return StepResult(
            name=step.name,
            status=StepStatus.COMPLETED,
            output={
                "recipient_count": len(recipients),
                "recipients": recipients,
            },
        )

    def _step_find_clicks(
        self,
        step: PlaybookStep,
        state: InvestigationState,
        connectors: Dict[str, Any],
    ) -> StepResult:
        """Find users who clicked URLs using SIEM connector."""
        siem_connector = connectors.get("siem")

        urls = state.iocs.get("urls", [])
        if not urls:
            return StepResult(
                name=step.name,
                status=StepStatus.COMPLETED,
                output={"message": "No URLs to search for clicks"},
            )

        if not siem_connector:
            return StepResult(
                name=step.name,
                status=StepStatus.SKIPPED,
                output={"message": "No SIEM connector available"},
            )

        try:
            all_clicks = []
            users_who_clicked = set()

            for url in urls[:5]:  # Limit to 5 URLs
                clicks = siem_connector.get_url_clicks(url=url)
                for click in clicks:
                    all_clicks.append(click.to_dict())
                    users_who_clicked.add(click.user)

            if users_who_clicked:
                state.add_finding(
                    "high",
                    f"{len(users_who_clicked)} user(s) clicked malicious URL(s)",
                    "find_clicks",
                    {"users": list(users_who_clicked)}
                )

            return StepResult(
                name=step.name,
                status=StepStatus.COMPLETED,
                output={
                    "click_count": len(all_clicks),
                    "users_clicked": list(users_who_clicked),
                    "clicks": all_clicks,
                },
            )

        except Exception as e:
            return StepResult(
                name=step.name,
                status=StepStatus.COMPLETED,
                output={"error": str(e)},
            )

    def _step_calculate_verdict(
        self,
        step: PlaybookStep,
        state: InvestigationState,
        connectors: Dict[str, Any],
    ) -> StepResult:
        """Calculate overall risk score and verdict."""
        try:
            from vlair.core.scorer import RiskScorer, Severity

            scorer = RiskScorer()

            # Add findings to scorer
            for finding in state.findings:
                severity_map = {
                    "critical": Severity.CRITICAL,
                    "high": Severity.HIGH,
                    "medium": Severity.MEDIUM,
                    "low": Severity.LOW,
                    "info": Severity.INFO,
                }
                severity = severity_map.get(finding["severity"].lower(), Severity.MEDIUM)
                scorer.add_finding(
                    severity=severity,
                    message=finding["message"],
                    source=finding["source"],
                    details=finding.get("details"),
                )

            # Calculate score and verdict
            risk_score = scorer.calculate_score()
            verdict = scorer.get_verdict(risk_score)

            # Update state
            state.risk_score = risk_score
            state.verdict = verdict.value

            return StepResult(
                name=step.name,
                status=StepStatus.COMPLETED,
                output={
                    "risk_score": risk_score,
                    "verdict": verdict.value,
                    "finding_count": len(state.findings),
                    "summary": scorer.get_summary(),
                },
            )

        except Exception as e:
            # Fallback calculation
            risk_score = 0
            for finding in state.findings:
                if finding["severity"] == "critical":
                    risk_score += 30
                elif finding["severity"] == "high":
                    risk_score += 15
                elif finding["severity"] == "medium":
                    risk_score += 5
            risk_score = min(risk_score, 100)

            if risk_score >= 70:
                verdict = "MALICIOUS"
            elif risk_score >= 40:
                verdict = "SUSPICIOUS"
            elif risk_score >= 10:
                verdict = "LOW_RISK"
            else:
                verdict = "CLEAN"

            state.risk_score = risk_score
            state.verdict = verdict

            return StepResult(
                name=step.name,
                status=StepStatus.COMPLETED,
                output={"risk_score": risk_score, "verdict": verdict, "error": str(e)},
            )

    def _step_prepare_remediation(
        self,
        step: PlaybookStep,
        state: InvestigationState,
        connectors: Dict[str, Any],
    ) -> StepResult:
        """Prepare recommended remediation actions."""
        actions = []

        # Get parsed email data
        parse_result = self._get_step_output(state, "parse_email")
        sender = parse_result.get("sender", "") if parse_result else ""
        sender_domain = parse_result.get("sender_domain", "") if parse_result else ""

        # Get click data
        click_result = self._get_step_output(state, "find_clicks")
        users_clicked = click_result.get("users_clicked", []) if click_result else []

        # If malicious, recommend blocking sender
        if state.verdict in ["MALICIOUS", "SUSPICIOUS"]:
            if sender_domain:
                action = RemediationAction(
                    id=str(uuid.uuid4())[:8],
                    name=f"Block sender domain: {sender_domain}",
                    action_type="block_sender",
                    target=sender_domain,
                    description=f"Block the sender domain {sender_domain} at the email gateway",
                    requires_approval=True,
                    priority=2,
                )
                actions.append(action)
                state.add_remediation_action(action)

            # Delete the malicious email from mailboxes
            action = RemediationAction(
                id=str(uuid.uuid4())[:8],
                name="Delete phishing email from mailboxes",
                action_type="delete_email",
                target=state.inputs.get("file_path", ""),
                description="Search and delete the phishing email from all recipient mailboxes",
                requires_approval=True,
                priority=1,
            )
            actions.append(action)
            state.add_remediation_action(action)

        # If users clicked, recommend password reset
        for user in users_clicked:
            action = RemediationAction(
                id=str(uuid.uuid4())[:8],
                name=f"Reset credentials for {user}",
                action_type="reset_password",
                target=user,
                description=f"Reset password and revoke sessions for {user} who clicked the phishing link",
                requires_approval=True,
                priority=1,
            )
            actions.append(action)
            state.add_remediation_action(action)

        # Block malicious URLs at proxy
        url_result = self._get_step_output(state, "analyze_urls")
        malicious_urls = url_result.get("malicious_urls", []) if url_result else []

        for url in malicious_urls[:5]:  # Limit to 5
            action = RemediationAction(
                id=str(uuid.uuid4())[:8],
                name=f"Block URL at proxy",
                action_type="block_url",
                target=url,
                description=f"Block the malicious URL at the web proxy",
                requires_approval=True,
                priority=2,
            )
            actions.append(action)
            state.add_remediation_action(action)

        return StepResult(
            name=step.name,
            status=StepStatus.COMPLETED,
            output={
                "action_count": len(actions),
                "actions": [a.to_dict() for a in actions],
            },
        )

    def _get_step_output(self, state: InvestigationState, step_name: str) -> Optional[Dict]:
        """Get the output from a previous step."""
        for result in state.steps:
            if result.name == step_name and result.output:
                return result.output
        return None


# Register the playbook
PlaybookRegistry.register(PhishingPlaybook)
