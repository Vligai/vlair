"""
SecOps Helper - Security Operations Toolkit

A collection of security operations tools for SOC analysts,
incident responders, and security researchers.

Subpackages:
- tools: Individual security analysis tools
- core: Orchestration engine and smart analysis
- workflows: Pre-built investigation workflows
- cli: Command-line interface
- common: Shared utilities
"""

__version__ = "5.0.0"
__author__ = "Vligai"

# Expose key components at package level
from .core import (
    Analyzer,
    InputDetector,
    InputType,
    RiskScorer,
    Severity,
    Verdict,
    Reporter,
)

from .tools import get_tool_registry

__all__ = [
    # Version info
    "__version__",
    "__author__",
    # Core components
    "Analyzer",
    "InputDetector",
    "InputType",
    "RiskScorer",
    "Severity",
    "Verdict",
    "Reporter",
    # Tool registry
    "get_tool_registry",
]
