#!/usr/bin/env python3
"""
Mock Email Connector - Simulated email system for testing

Provides simulated email data for development and testing
without requiring actual email system connections.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
import uuid
import random

from ..base import EmailConnector, Email


class MockEmailConnector(EmailConnector):
    """
    Mock email connector that returns simulated phishing-related data.

    Useful for testing investigation workflows without real email system access.
    """

    def __init__(self, scenario: str = "phishing"):
        """
        Initialize the mock connector.

        Args:
            scenario: The scenario to simulate ("phishing", "clean", "malware")
        """
        self.scenario = scenario
        self._messages: Dict[str, Email] = {}
        self._setup_mock_data()

    def _setup_mock_data(self):
        """Set up mock email data based on scenario."""
        if self.scenario == "phishing":
            self._setup_phishing_scenario()
        elif self.scenario == "clean":
            self._setup_clean_scenario()
        elif self.scenario == "malware":
            self._setup_malware_scenario()

    def _setup_phishing_scenario(self):
        """Set up a phishing email scenario."""
        now = datetime.now(timezone.utc)

        # The suspicious email
        phishing_email = Email(
            message_id="<phishing123@malicious.com>",
            subject="Urgent: Your Account Has Been Compromised!",
            sender="security@micros0ft-support.com",
            sender_domain="micros0ft-support.com",
            recipients=[
                "user1@company.com",
                "user2@company.com",
                "user3@company.com",
            ],
            cc=["admin@company.com"],
            received_time=now - timedelta(hours=2),
            headers={
                "Return-Path": "<bounce@bulk-mailer.net>",
                "Reply-To": "phishing@badactor.net",
                "X-Mailer": "Mass Mailer Pro 2.0",
                "X-Originating-IP": "203.0.113.100",
            },
            body_text="""
Dear valued customer,

Your Microsoft account has been compromised. You must verify your identity immediately.

Click here to secure your account: http://micros0ft-secure-login.com/verify?user=target

If you do not verify within 24 hours, your account will be permanently deleted.

Microsoft Security Team
            """,
            body_html="""
<html>
<body>
<h2>Security Alert</h2>
<p>Dear valued customer,</p>
<p>Your <strong>Microsoft</strong> account has been compromised.</p>
<p><a href="http://micros0ft-secure-login.com/verify?user=target">Click here to secure your account</a></p>
<p>Microsoft Security Team</p>
</body>
</html>
            """,
            urls=[
                "http://micros0ft-secure-login.com/verify?user=target",
                "http://micros0ft-secure-login.com/images/logo.png",
            ],
            spf_result="fail",
            dkim_result="fail",
            dmarc_result="fail",
        )
        self._messages[phishing_email.message_id] = phishing_email

        # Some related legitimate emails for context
        legit_email = Email(
            message_id="<legit456@microsoft.com>",
            subject="Your Microsoft 365 subscription renewal",
            sender="noreply@microsoft.com",
            sender_domain="microsoft.com",
            recipients=["user1@company.com"],
            received_time=now - timedelta(days=5),
            spf_result="pass",
            dkim_result="pass",
            dmarc_result="pass",
        )
        self._messages[legit_email.message_id] = legit_email

    def _setup_clean_scenario(self):
        """Set up clean email scenario."""
        now = datetime.now(timezone.utc)

        clean_email = Email(
            message_id="<clean789@trusted.com>",
            subject="Weekly team update",
            sender="manager@company.com",
            sender_domain="company.com",
            recipients=["team@company.com"],
            received_time=now - timedelta(hours=1),
            body_text="Hi team, here's our weekly update...",
            spf_result="pass",
            dkim_result="pass",
            dmarc_result="pass",
        )
        self._messages[clean_email.message_id] = clean_email

    def _setup_malware_scenario(self):
        """Set up malware delivery email scenario."""
        now = datetime.now(timezone.utc)

        malware_email = Email(
            message_id="<malware999@badactor.net>",
            subject="Invoice #INV-2025-001",
            sender="billing@invoice-service.net",
            sender_domain="invoice-service.net",
            recipients=["finance@company.com"],
            received_time=now - timedelta(hours=3),
            attachments=[
                {
                    "filename": "invoice.pdf.exe",
                    "size": 1245678,
                    "content_type": "application/octet-stream",
                    "hashes": {
                        "md5": "44d88612fea8a8f36de82e1278abb02f",
                        "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                    },
                }
            ],
            spf_result="neutral",
            dkim_result="none",
            dmarc_result="none",
        )
        self._messages[malware_email.message_id] = malware_email

    def get_message(self, message_id: str) -> Optional[Email]:
        """Retrieve a specific email message by ID."""
        return self._messages.get(message_id)

    def search_messages(
        self,
        sender: Optional[str] = None,
        subject: Optional[str] = None,
        recipient: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[Email]:
        """Search for email messages matching criteria."""
        results = []

        for email in self._messages.values():
            # Apply filters
            if sender and sender.lower() not in email.sender.lower():
                continue
            if subject and subject.lower() not in email.subject.lower():
                continue
            if recipient:
                all_recipients = email.recipients + email.cc + email.bcc
                if not any(recipient.lower() in r.lower() for r in all_recipients):
                    continue
            if start_time and email.received_time and email.received_time < start_time:
                continue
            if end_time and email.received_time and email.received_time > end_time:
                continue

            results.append(email)

            if len(results) >= limit:
                break

        return results

    def get_recipients(self, message_id: str) -> List[str]:
        """Get all recipients of a message."""
        email = self._messages.get(message_id)
        if not email:
            return []

        return email.recipients + email.cc + email.bcc

    def delete_message(self, message_id: str) -> bool:
        """Delete a message (mock - just removes from local cache)."""
        if message_id in self._messages:
            del self._messages[message_id]
            return True
        return False

    def block_sender(self, sender_email: str) -> bool:
        """Block a sender (mock - always succeeds)."""
        # In a real implementation, this would add to blocklist
        return True

    def find_similar_messages(
        self,
        sender_domain: Optional[str] = None,
        subject_pattern: Optional[str] = None,
    ) -> List[Email]:
        """
        Find messages similar to a known phishing email.

        This is a mock-specific method to simulate threat hunting.
        """
        results = []

        for email in self._messages.values():
            if sender_domain and email.sender_domain == sender_domain:
                results.append(email)
            elif subject_pattern and subject_pattern.lower() in email.subject.lower():
                results.append(email)

        return results

    def add_test_message(self, email: Email):
        """Add a test message to the mock connector."""
        self._messages[email.message_id] = email
