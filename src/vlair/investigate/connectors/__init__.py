#!/usr/bin/env python3
"""
Investigation Connectors - Interfaces to enterprise security systems

This module defines abstract interfaces for connecting to:
- Email systems (Exchange, Gmail, etc.)
- SIEM platforms (Splunk, Sentinel, etc.)
- EDR solutions (CrowdStrike, Defender, etc.)
- Identity providers (Azure AD, Okta, etc.)

Real connector implementations:
- CrowdStrikeConnector (EDR) — requires CROWDSTRIKE_CLIENT_ID/SECRET env vars
- SplunkConnector (SIEM)    — requires SPLUNK_TOKEN env var
"""

from .base import (
    # DTOs
    Email,
    Host,
    Process,
    User,
    AuthenticationEvent,
    URLClickEvent,
    # Connector interfaces
    EmailConnector,
    SIEMConnector,
    EDRConnector,
    IdentityConnector,
)
from .crowdstrike import CrowdStrikeConnector
from .splunk import SplunkConnector

__all__ = [
    # DTOs
    "Email",
    "Host",
    "Process",
    "User",
    "AuthenticationEvent",
    "URLClickEvent",
    # Abstract interfaces
    "EmailConnector",
    "SIEMConnector",
    "EDRConnector",
    "IdentityConnector",
    # Real connectors
    "CrowdStrikeConnector",
    "SplunkConnector",
]
