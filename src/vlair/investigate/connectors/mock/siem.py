#!/usr/bin/env python3
"""
Mock SIEM Connector - Simulated SIEM system for testing

Provides simulated security event data for development and testing
without requiring actual SIEM system connections.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
import uuid
import random

from ..base import SIEMConnector, URLClickEvent


class MockSIEMConnector(SIEMConnector):
    """
    Mock SIEM connector that returns simulated security event data.

    Useful for testing investigation workflows without real SIEM access.
    """

    def __init__(self, scenario: str = "phishing"):
        """
        Initialize the mock connector.

        Args:
            scenario: The scenario to simulate ("phishing", "clean", "breach")
        """
        self.scenario = scenario
        self._events: List[Dict[str, Any]] = []
        self._url_clicks: List[URLClickEvent] = []
        self._setup_mock_data()

    def _setup_mock_data(self):
        """Set up mock event data based on scenario."""
        if self.scenario == "phishing":
            self._setup_phishing_scenario()
        elif self.scenario == "clean":
            self._setup_clean_scenario()
        elif self.scenario == "breach":
            self._setup_breach_scenario()

    def _setup_phishing_scenario(self):
        """Set up phishing investigation scenario with URL clicks."""
        now = datetime.now(timezone.utc)

        # Simulate users who clicked the phishing link
        clicked_users = [
            ("user1@company.com", "WORKSTATION-01", "192.168.1.101"),
            ("user2@company.com", "WORKSTATION-02", "192.168.1.102"),
        ]

        for user, hostname, ip in clicked_users:
            # URL click event
            click_event = URLClickEvent(
                event_id=str(uuid.uuid4()),
                timestamp=now - timedelta(hours=1, minutes=random.randint(0, 30)),
                user=user,
                url="http://micros0ft-secure-login.com/verify?user=target",
                source_ip=ip,
                hostname=hostname,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
                response_code=200,
                bytes_transferred=random.randint(5000, 50000),
                was_blocked=False,
                threat_category="phishing",
            )
            self._url_clicks.append(click_event)

            # General event for the click
            self._events.append({
                "event_id": click_event.event_id,
                "timestamp": click_event.timestamp.isoformat(),
                "event_type": "proxy_access",
                "user": user,
                "hostname": hostname,
                "source_ip": ip,
                "url": click_event.url,
                "action": "allowed",
                "category": "phishing",
            })

        # User who received but didn't click
        self._events.append({
            "event_id": str(uuid.uuid4()),
            "timestamp": (now - timedelta(hours=2)).isoformat(),
            "event_type": "email_received",
            "user": "user3@company.com",
            "hostname": "WORKSTATION-03",
            "source_ip": "192.168.1.103",
            "action": "delivered",
            "subject": "Urgent: Your Account Has Been Compromised!",
        })

        # Suspicious credential entry after phishing click
        self._events.append({
            "event_id": str(uuid.uuid4()),
            "timestamp": (now - timedelta(minutes=55)).isoformat(),
            "event_type": "credential_submission",
            "user": "user1@company.com",
            "hostname": "WORKSTATION-01",
            "source_ip": "192.168.1.101",
            "target_url": "http://micros0ft-secure-login.com/verify",
            "action": "submitted",
            "risk_indicator": "credentials_harvested",
        })

    def _setup_clean_scenario(self):
        """Set up clean/normal activity scenario."""
        now = datetime.now(timezone.utc)

        # Normal web browsing events
        for i in range(10):
            self._events.append({
                "event_id": str(uuid.uuid4()),
                "timestamp": (now - timedelta(hours=i)).isoformat(),
                "event_type": "proxy_access",
                "user": f"user{i % 3 + 1}@company.com",
                "url": f"https://legitimate-site-{i}.com",
                "action": "allowed",
                "category": "business",
            })

    def _setup_breach_scenario(self):
        """Set up post-breach scenario with suspicious activity."""
        now = datetime.now(timezone.utc)

        # Data exfiltration indicators
        self._events.append({
            "event_id": str(uuid.uuid4()),
            "timestamp": (now - timedelta(hours=1)).isoformat(),
            "event_type": "file_upload",
            "user": "compromised_user@company.com",
            "hostname": "WORKSTATION-COMPROMISED",
            "destination": "suspicious-cloud-storage.com",
            "file_size_mb": 250,
            "action": "uploaded",
            "risk_indicator": "data_exfiltration",
        })

        # Lateral movement
        self._events.append({
            "event_id": str(uuid.uuid4()),
            "timestamp": (now - timedelta(hours=2)).isoformat(),
            "event_type": "remote_login",
            "user": "compromised_user@company.com",
            "source_hostname": "WORKSTATION-COMPROMISED",
            "target_hostname": "FILE-SERVER-01",
            "action": "success",
            "risk_indicator": "lateral_movement",
        })

    def search(
        self,
        query: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """Execute a search query (mock - simple keyword matching)."""
        results = []
        query_lower = query.lower()

        for event in self._events:
            # Simple keyword matching in event values
            event_str = str(event).lower()
            if query_lower in event_str:
                # Apply time filters
                event_time = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
                if start_time and event_time < start_time:
                    continue
                if end_time and event_time > end_time:
                    continue

                results.append(event)

                if len(results) >= limit:
                    break

        return results

    def get_events_by_host(
        self,
        hostname: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        event_types: Optional[List[str]] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """Get security events for a specific host."""
        results = []
        hostname_lower = hostname.lower()

        for event in self._events:
            # Check hostname match
            event_hostname = event.get("hostname", "").lower()
            if hostname_lower not in event_hostname:
                continue

            # Apply event type filter
            if event_types:
                if event.get("event_type") not in event_types:
                    continue

            # Apply time filters
            event_time = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
            if start_time and event_time < start_time:
                continue
            if end_time and event_time > end_time:
                continue

            results.append(event)

            if len(results) >= limit:
                break

        return results

    def get_events_by_user(
        self,
        username: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        event_types: Optional[List[str]] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """Get security events for a specific user."""
        results = []
        username_lower = username.lower()

        for event in self._events:
            # Check username match
            event_user = event.get("user", "").lower()
            if username_lower not in event_user:
                continue

            # Apply event type filter
            if event_types:
                if event.get("event_type") not in event_types:
                    continue

            # Apply time filters
            event_time = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
            if start_time and event_time < start_time:
                continue
            if end_time and event_time > end_time:
                continue

            results.append(event)

            if len(results) >= limit:
                break

        return results

    def get_url_clicks(
        self,
        url: Optional[str] = None,
        domain: Optional[str] = None,
        user: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 1000,
    ) -> List[URLClickEvent]:
        """Get URL click events from proxy/web logs."""
        results = []

        for click in self._url_clicks:
            # Apply filters
            if url and url.lower() not in click.url.lower():
                continue
            if domain:
                # Extract domain from URL
                click_domain = click.url.split("//")[-1].split("/")[0]
                if domain.lower() not in click_domain.lower():
                    continue
            if user and user.lower() not in click.user.lower():
                continue
            if start_time and click.timestamp < start_time:
                continue
            if end_time and click.timestamp > end_time:
                continue

            results.append(click)

            if len(results) >= limit:
                break

        return results

    def get_credential_submissions(
        self,
        url: Optional[str] = None,
        user: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get credential submission events.

        This is a mock-specific method to identify potential credential theft.
        """
        results = []

        for event in self._events:
            if event.get("event_type") != "credential_submission":
                continue

            if url and url.lower() not in event.get("target_url", "").lower():
                continue
            if user and user.lower() not in event.get("user", "").lower():
                continue

            # Apply time filters
            event_time = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
            if start_time and event_time < start_time:
                continue
            if end_time and event_time > end_time:
                continue

            results.append(event)

        return results

    def add_test_event(self, event: Dict[str, Any]):
        """Add a test event to the mock connector."""
        self._events.append(event)

    def add_test_url_click(self, click: URLClickEvent):
        """Add a test URL click event to the mock connector."""
        self._url_clicks.append(click)
