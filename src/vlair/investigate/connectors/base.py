#!/usr/bin/env python3
"""
Connector Base Classes - Abstract interfaces for enterprise security systems

Defines abstract base classes (ABCs) for connecting to:
- Email systems (Exchange, Gmail, etc.)
- SIEM platforms (Splunk, Sentinel, etc.)
- EDR solutions (CrowdStrike, Defender, etc.)
- Identity providers (Azure AD, Okta, etc.)

Also defines DTOs (Data Transfer Objects) for standardized data exchange.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any


# =============================================================================
# Data Transfer Objects (DTOs)
# =============================================================================

@dataclass
class Email:
    """Represents an email message"""
    message_id: str
    subject: str
    sender: str
    sender_domain: str
    recipients: List[str]
    cc: List[str] = field(default_factory=list)
    bcc: List[str] = field(default_factory=list)
    received_time: Optional[datetime] = None
    headers: Dict[str, str] = field(default_factory=dict)
    body_text: Optional[str] = None
    body_html: Optional[str] = None
    attachments: List[Dict[str, Any]] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    spf_result: Optional[str] = None
    dkim_result: Optional[str] = None
    dmarc_result: Optional[str] = None
    raw_content: Optional[bytes] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "message_id": self.message_id,
            "subject": self.subject,
            "sender": self.sender,
            "sender_domain": self.sender_domain,
            "recipients": self.recipients,
            "cc": self.cc,
            "bcc": self.bcc,
            "received_time": self.received_time.isoformat() if self.received_time else None,
            "headers": self.headers,
            "body_text": self.body_text,
            "body_html": self.body_html,
            "attachments": self.attachments,
            "urls": self.urls,
            "spf_result": self.spf_result,
            "dkim_result": self.dkim_result,
            "dmarc_result": self.dmarc_result,
        }


@dataclass
class Host:
    """Represents a host/endpoint"""
    hostname: str
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    os_type: Optional[str] = None
    os_version: Optional[str] = None
    domain: Optional[str] = None
    last_seen: Optional[datetime] = None
    is_online: bool = False
    is_isolated: bool = False
    agent_version: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    owner: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hostname": self.hostname,
            "ip_address": self.ip_address,
            "mac_address": self.mac_address,
            "os_type": self.os_type,
            "os_version": self.os_version,
            "domain": self.domain,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "is_online": self.is_online,
            "is_isolated": self.is_isolated,
            "agent_version": self.agent_version,
            "tags": self.tags,
            "owner": self.owner,
        }


@dataclass
class Process:
    """Represents a process on a host"""
    pid: int
    name: str
    command_line: Optional[str] = None
    executable_path: Optional[str] = None
    parent_pid: Optional[int] = None
    parent_name: Optional[str] = None
    user: Optional[str] = None
    start_time: Optional[datetime] = None
    hash_sha256: Optional[str] = None
    is_suspicious: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pid": self.pid,
            "name": self.name,
            "command_line": self.command_line,
            "executable_path": self.executable_path,
            "parent_pid": self.parent_pid,
            "parent_name": self.parent_name,
            "user": self.user,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "hash_sha256": self.hash_sha256,
            "is_suspicious": self.is_suspicious,
        }


@dataclass
class User:
    """Represents a user account"""
    user_id: str
    username: str
    email: Optional[str] = None
    display_name: Optional[str] = None
    department: Optional[str] = None
    manager: Optional[str] = None
    is_enabled: bool = True
    is_admin: bool = False
    last_login: Optional[datetime] = None
    created_at: Optional[datetime] = None
    risk_score: int = 0
    groups: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "username": self.username,
            "email": self.email,
            "display_name": self.display_name,
            "department": self.department,
            "manager": self.manager,
            "is_enabled": self.is_enabled,
            "is_admin": self.is_admin,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "risk_score": self.risk_score,
            "groups": self.groups,
        }


@dataclass
class AuthenticationEvent:
    """Represents an authentication event"""
    event_id: str
    timestamp: datetime
    user: str
    source_ip: Optional[str] = None
    source_hostname: Optional[str] = None
    target_service: Optional[str] = None
    auth_method: Optional[str] = None
    result: str = "unknown"  # success, failure, blocked
    failure_reason: Optional[str] = None
    location: Optional[str] = None
    user_agent: Optional[str] = None
    is_anomalous: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "user": self.user,
            "source_ip": self.source_ip,
            "source_hostname": self.source_hostname,
            "target_service": self.target_service,
            "auth_method": self.auth_method,
            "result": self.result,
            "failure_reason": self.failure_reason,
            "location": self.location,
            "user_agent": self.user_agent,
            "is_anomalous": self.is_anomalous,
        }


@dataclass
class URLClickEvent:
    """Represents a URL click event from SIEM/proxy logs"""
    event_id: str
    timestamp: datetime
    user: str
    url: str
    source_ip: Optional[str] = None
    hostname: Optional[str] = None
    user_agent: Optional[str] = None
    referrer: Optional[str] = None
    response_code: Optional[int] = None
    bytes_transferred: Optional[int] = None
    was_blocked: bool = False
    threat_category: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "user": self.user,
            "url": self.url,
            "source_ip": self.source_ip,
            "hostname": self.hostname,
            "user_agent": self.user_agent,
            "referrer": self.referrer,
            "response_code": self.response_code,
            "bytes_transferred": self.bytes_transferred,
            "was_blocked": self.was_blocked,
            "threat_category": self.threat_category,
        }


# =============================================================================
# Abstract Connector Interfaces
# =============================================================================

class EmailConnector(ABC):
    """Abstract interface for email system connectors (Exchange, Gmail, etc.)"""

    @abstractmethod
    def get_message(self, message_id: str) -> Optional[Email]:
        """
        Retrieve a specific email message by ID.

        Args:
            message_id: The unique identifier of the message

        Returns:
            Email object if found, None otherwise
        """
        pass

    @abstractmethod
    def search_messages(
        self,
        sender: Optional[str] = None,
        subject: Optional[str] = None,
        recipient: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[Email]:
        """
        Search for email messages matching criteria.

        Args:
            sender: Filter by sender email address
            subject: Filter by subject (substring match)
            recipient: Filter by recipient email address
            start_time: Filter by received time (start)
            end_time: Filter by received time (end)
            limit: Maximum number of results

        Returns:
            List of matching Email objects
        """
        pass

    @abstractmethod
    def get_recipients(self, message_id: str) -> List[str]:
        """
        Get all recipients of a message (To, CC, BCC).

        Args:
            message_id: The unique identifier of the message

        Returns:
            List of recipient email addresses
        """
        pass

    @abstractmethod
    def delete_message(self, message_id: str) -> bool:
        """
        Delete a message from mailboxes.

        Args:
            message_id: The unique identifier of the message

        Returns:
            True if successful, False otherwise
        """
        pass

    def block_sender(self, sender_email: str) -> bool:
        """
        Block a sender at the email gateway.

        Args:
            sender_email: The email address to block

        Returns:
            True if successful, False otherwise
        """
        raise NotImplementedError("block_sender not implemented")


class SIEMConnector(ABC):
    """Abstract interface for SIEM connectors (Splunk, Sentinel, etc.)"""

    @abstractmethod
    def search(
        self,
        query: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """
        Execute a search query against the SIEM.

        Args:
            query: The search query (platform-specific syntax)
            start_time: Search start time
            end_time: Search end time
            limit: Maximum number of results

        Returns:
            List of matching events as dictionaries
        """
        pass

    @abstractmethod
    def get_events_by_host(
        self,
        hostname: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        event_types: Optional[List[str]] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """
        Get security events for a specific host.

        Args:
            hostname: The hostname to search for
            start_time: Search start time
            end_time: Search end time
            event_types: Filter by event types
            limit: Maximum number of results

        Returns:
            List of events as dictionaries
        """
        pass

    @abstractmethod
    def get_events_by_user(
        self,
        username: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        event_types: Optional[List[str]] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """
        Get security events for a specific user.

        Args:
            username: The username to search for
            start_time: Search start time
            end_time: Search end time
            event_types: Filter by event types
            limit: Maximum number of results

        Returns:
            List of events as dictionaries
        """
        pass

    @abstractmethod
    def get_url_clicks(
        self,
        url: Optional[str] = None,
        domain: Optional[str] = None,
        user: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 1000,
    ) -> List[URLClickEvent]:
        """
        Get URL click events from proxy/web logs.

        Args:
            url: Filter by specific URL
            domain: Filter by domain
            user: Filter by user
            start_time: Search start time
            end_time: Search end time
            limit: Maximum number of results

        Returns:
            List of URLClickEvent objects
        """
        pass


class EDRConnector(ABC):
    """Abstract interface for EDR connectors (CrowdStrike, Defender, etc.)"""

    @abstractmethod
    def get_host_details(self, hostname: str) -> Optional[Host]:
        """
        Get detailed information about a host.

        Args:
            hostname: The hostname to look up

        Returns:
            Host object if found, None otherwise
        """
        pass

    @abstractmethod
    def isolate_host(self, hostname: str, reason: str) -> bool:
        """
        Isolate a host from the network.

        Args:
            hostname: The hostname to isolate
            reason: Reason for isolation

        Returns:
            True if successful, False otherwise
        """
        pass

    @abstractmethod
    def get_file_sample(self, hostname: str, file_path: str) -> Optional[bytes]:
        """
        Retrieve a file sample from a host.

        Args:
            hostname: The hostname
            file_path: Path to the file on the host

        Returns:
            File contents as bytes if successful, None otherwise
        """
        pass

    @abstractmethod
    def search_ioc(
        self,
        ioc_type: str,
        ioc_value: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """
        Search for IOC matches across the environment.

        Args:
            ioc_type: Type of IOC (hash, ip, domain, etc.)
            ioc_value: The IOC value to search for
            start_time: Search start time
            end_time: Search end time

        Returns:
            List of hosts/events where IOC was found
        """
        pass

    def get_processes(
        self,
        hostname: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> List[Process]:
        """
        Get process execution history for a host.

        Args:
            hostname: The hostname
            start_time: Search start time
            end_time: Search end time

        Returns:
            List of Process objects
        """
        raise NotImplementedError("get_processes not implemented")


class IdentityConnector(ABC):
    """Abstract interface for identity provider connectors (Azure AD, Okta, etc.)"""

    @abstractmethod
    def get_user(self, user_id: str) -> Optional[User]:
        """
        Get user details by user ID or email.

        Args:
            user_id: User ID or email address

        Returns:
            User object if found, None otherwise
        """
        pass

    @abstractmethod
    def disable_user(self, user_id: str, reason: str) -> bool:
        """
        Disable a user account.

        Args:
            user_id: User ID or email address
            reason: Reason for disabling

        Returns:
            True if successful, False otherwise
        """
        pass

    @abstractmethod
    def reset_password(self, user_id: str, force_change: bool = True) -> bool:
        """
        Reset a user's password.

        Args:
            user_id: User ID or email address
            force_change: Whether to force password change on next login

        Returns:
            True if successful, False otherwise
        """
        pass

    @abstractmethod
    def revoke_sessions(self, user_id: str) -> bool:
        """
        Revoke all active sessions for a user.

        Args:
            user_id: User ID or email address

        Returns:
            True if successful, False otherwise
        """
        pass

    def get_user_auth_events(
        self,
        user_id: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[AuthenticationEvent]:
        """
        Get authentication events for a user.

        Args:
            user_id: User ID or email address
            start_time: Search start time
            end_time: Search end time
            limit: Maximum number of results

        Returns:
            List of AuthenticationEvent objects
        """
        raise NotImplementedError("get_user_auth_events not implemented")
