#!/usr/bin/env python3
"""
Investigation Models - Core dataclasses for investigation automation

Defines the data structures for:
- Investigation state and status tracking
- Step execution results
- Remediation actions
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Any, Optional
import uuid


class InvestigationStatus(Enum):
    """Status of an investigation"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class StepStatus(Enum):
    """Status of an investigation step"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class RemediationStatus(Enum):
    """Status of a remediation action"""
    PENDING = "pending"
    APPROVED = "approved"
    EXECUTED = "executed"
    FAILED = "failed"


@dataclass
class StepResult:
    """Result of executing a single investigation step"""
    name: str
    status: StepStatus
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    output: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "name": self.name,
            "status": self.status.value,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "output": self.output,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "StepResult":
        """Create from dictionary"""
        return cls(
            name=data["name"],
            status=StepStatus(data["status"]),
            started_at=datetime.fromisoformat(data["started_at"]) if data.get("started_at") else None,
            completed_at=datetime.fromisoformat(data["completed_at"]) if data.get("completed_at") else None,
            duration_seconds=data.get("duration_seconds"),
            output=data.get("output"),
            error=data.get("error"),
        )


@dataclass
class RemediationAction:
    """A remediation action to be taken"""
    id: str
    name: str
    action_type: str  # e.g., "block_sender", "isolate_host", "disable_user"
    target: str  # e.g., email address, hostname, user ID
    command: Optional[str] = None  # The actual command/API call to execute
    status: RemediationStatus = RemediationStatus.PENDING
    requires_approval: bool = True
    priority: int = 0  # Higher = more urgent
    description: Optional[str] = None
    executed_at: Optional[datetime] = None
    executed_by: Optional[str] = None
    result: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "id": self.id,
            "name": self.name,
            "action_type": self.action_type,
            "target": self.target,
            "command": self.command,
            "status": self.status.value,
            "requires_approval": self.requires_approval,
            "priority": self.priority,
            "description": self.description,
            "executed_at": self.executed_at.isoformat() if self.executed_at else None,
            "executed_by": self.executed_by,
            "result": self.result,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RemediationAction":
        """Create from dictionary"""
        return cls(
            id=data["id"],
            name=data["name"],
            action_type=data["action_type"],
            target=data["target"],
            command=data.get("command"),
            status=RemediationStatus(data.get("status", "pending")),
            requires_approval=data.get("requires_approval", True),
            priority=data.get("priority", 0),
            description=data.get("description"),
            executed_at=datetime.fromisoformat(data["executed_at"]) if data.get("executed_at") else None,
            executed_by=data.get("executed_by"),
            result=data.get("result"),
        )


@dataclass
class InvestigationState:
    """Complete state of an investigation"""
    id: str
    type: str  # e.g., "phishing", "malware", "incident"
    status: InvestigationStatus
    inputs: Dict[str, Any] = field(default_factory=dict)
    steps: List[StepResult] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    iocs: Dict[str, List[str]] = field(default_factory=lambda: {
        "hashes": [],
        "domains": [],
        "ips": [],
        "urls": [],
        "emails": [],
    })
    risk_score: int = 0
    verdict: str = "UNKNOWN"
    remediation_actions: List[RemediationAction] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    error: Optional[str] = None

    @staticmethod
    def generate_id() -> str:
        """Generate a unique investigation ID"""
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        short_uuid = str(uuid.uuid4())[:8].upper()
        return f"INV-{date_str}-{short_uuid}"

    def add_step_result(self, result: StepResult):
        """Add a step result and update timestamp"""
        self.steps.append(result)
        self.updated_at = datetime.now(timezone.utc)

    def add_finding(self, severity: str, message: str, source: str, details: Optional[Dict] = None):
        """Add a finding"""
        self.findings.append({
            "severity": severity,
            "message": message,
            "source": source,
            "details": details or {},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        self.updated_at = datetime.now(timezone.utc)

    def add_iocs(self, ioc_type: str, values: List[str]):
        """Add IOCs to the investigation"""
        if ioc_type not in self.iocs:
            self.iocs[ioc_type] = []
        for value in values:
            if value not in self.iocs[ioc_type]:
                self.iocs[ioc_type].append(value)
        self.updated_at = datetime.now(timezone.utc)

    def add_remediation_action(self, action: RemediationAction):
        """Add a remediation action"""
        self.remediation_actions.append(action)
        self.updated_at = datetime.now(timezone.utc)

    def mark_completed(self, risk_score: int, verdict: str):
        """Mark the investigation as completed"""
        self.status = InvestigationStatus.COMPLETED
        self.risk_score = risk_score
        self.verdict = verdict
        self.completed_at = datetime.now(timezone.utc)
        self.updated_at = datetime.now(timezone.utc)

    def mark_failed(self, error: str):
        """Mark the investigation as failed"""
        self.status = InvestigationStatus.FAILED
        self.error = error
        self.updated_at = datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "id": self.id,
            "type": self.type,
            "status": self.status.value,
            "inputs": self.inputs,
            "steps": [s.to_dict() for s in self.steps],
            "findings": self.findings,
            "iocs": self.iocs,
            "risk_score": self.risk_score,
            "verdict": self.verdict,
            "remediation_actions": [a.to_dict() for a in self.remediation_actions],
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "InvestigationState":
        """Create from dictionary"""
        state = cls(
            id=data["id"],
            type=data["type"],
            status=InvestigationStatus(data["status"]),
            inputs=data.get("inputs", {}),
            findings=data.get("findings", []),
            iocs=data.get("iocs", {"hashes": [], "domains": [], "ips": [], "urls": [], "emails": []}),
            risk_score=data.get("risk_score", 0),
            verdict=data.get("verdict", "UNKNOWN"),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else datetime.now(timezone.utc),
            updated_at=datetime.fromisoformat(data["updated_at"]) if data.get("updated_at") else datetime.now(timezone.utc),
            completed_at=datetime.fromisoformat(data["completed_at"]) if data.get("completed_at") else None,
            error=data.get("error"),
        )

        # Deserialize steps
        state.steps = [StepResult.from_dict(s) for s in data.get("steps", [])]

        # Deserialize remediation actions
        state.remediation_actions = [
            RemediationAction.from_dict(a) for a in data.get("remediation_actions", [])
        ]

        return state

    def get_duration_seconds(self) -> Optional[float]:
        """Get the duration of the investigation in seconds"""
        if self.completed_at:
            return (self.completed_at - self.created_at).total_seconds()
        return None

    def get_completed_steps(self) -> List[StepResult]:
        """Get all completed steps"""
        return [s for s in self.steps if s.status == StepStatus.COMPLETED]

    def get_failed_steps(self) -> List[StepResult]:
        """Get all failed steps"""
        return [s for s in self.steps if s.status == StepStatus.FAILED]

    def get_pending_remediation_actions(self) -> List[RemediationAction]:
        """Get pending remediation actions"""
        return [a for a in self.remediation_actions if a.status == RemediationStatus.PENDING]
