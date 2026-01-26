"""
SecOps Helper Workflows - Pre-built investigation patterns
Part of SecOps Helper Operationalization (Phase 5)
"""

from .phishing_email import PhishingEmailWorkflow
from .malware_triage import MalwareTriageWorkflow
from .ioc_hunt import IOCHuntWorkflow
from .network_forensics import NetworkForensicsWorkflow
from .log_investigation import LogInvestigationWorkflow

__all__ = [
    "PhishingEmailWorkflow",
    "MalwareTriageWorkflow",
    "IOCHuntWorkflow",
    "NetworkForensicsWorkflow",
    "LogInvestigationWorkflow",
]
