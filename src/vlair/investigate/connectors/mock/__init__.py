#!/usr/bin/env python3
"""
Mock Connectors - Simulated enterprise system connectors for testing

These connectors provide simulated data for development and testing
without requiring actual enterprise system connections.
"""

from .email import MockEmailConnector
from .siem import MockSIEMConnector

__all__ = [
    "MockEmailConnector",
    "MockSIEMConnector",
]
