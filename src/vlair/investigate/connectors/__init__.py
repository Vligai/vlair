#!/usr/bin/env python3
"""
Investigation Connectors - Interfaces to enterprise security systems

This module defines abstract interfaces for connecting to:
- Email systems (Exchange, Gmail, etc.)
- SIEM platforms (Splunk, Sentinel, etc.)
- EDR solutions (CrowdStrike, Defender, etc.)
- Identity providers (Azure AD, Okta, etc.)
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

__all__ = [
    # DTOs
    "Email",
    "Host",
    "Process",
    "User",
    "AuthenticationEvent",
    "URLClickEvent",
    # Connectors
    "EmailConnector",
    "SIEMConnector",
    "EDRConnector",
    "IdentityConnector",
]
