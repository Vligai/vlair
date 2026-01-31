#!/usr/bin/env python3
"""
Investigation Playbooks - Pre-built investigation workflows

Available playbooks:
- PhishingPlaybook: 10-step phishing email investigation
"""

from .base import BasePlaybook, PlaybookStep
from .phishing import PhishingPlaybook

__all__ = [
    "BasePlaybook",
    "PlaybookStep",
    "PhishingPlaybook",
]
