#!/usr/bin/env python3
"""
Base Playbook - Abstract base class for investigation playbooks

Defines the structure and execution model for automated investigation playbooks.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Callable
import sys
import time

from ..models import (
    InvestigationState,
    InvestigationStatus,
    StepResult,
    StepStatus,
    RemediationAction,
)


@dataclass
class PlaybookStep:
    """Definition of a single playbook step"""

    name: str
    description: str
    required: bool = True
    depends_on: List[str] = field(default_factory=list)
    timeout_seconds: int = 300  # 5 minutes default
    retry_count: int = 0
    on_failure: str = "continue"  # "continue", "stop", "skip_dependents"

    def __post_init__(self):
        if self.depends_on is None:
            self.depends_on = []


class BasePlaybook(ABC):
    """
    Abstract base class for investigation playbooks.

    Playbooks define a series of steps to execute during an investigation.
    Each step can use existing vlair tools or custom logic.
    """

    def __init__(self, verbose: bool = False):
        """
        Initialize the playbook.

        Args:
            verbose: If True, print detailed progress information
        """
        self.verbose = verbose
        self.steps: List[PlaybookStep] = []
        self._define_steps()

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the playbook name (e.g., 'phishing-investigation')"""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Return a description of what this playbook does"""
        pass

    @property
    def investigation_type(self) -> str:
        """Return the type of investigation (e.g., 'phishing', 'malware')"""
        return self.name.split("-")[0] if "-" in self.name else self.name

    @abstractmethod
    def _define_steps(self):
        """Define the steps for this playbook. Sets self.steps."""
        pass

    @abstractmethod
    def _execute_step(
        self,
        step: PlaybookStep,
        state: InvestigationState,
        connectors: Dict[str, Any],
    ) -> StepResult:
        """
        Execute a single step of the playbook.

        Args:
            step: The step to execute
            state: The current investigation state
            connectors: Dictionary of available connectors

        Returns:
            StepResult with the outcome
        """
        pass

    def execute(
        self,
        inputs: Dict[str, Any],
        connectors: Optional[Dict[str, Any]] = None,
        state: Optional[InvestigationState] = None,
    ) -> InvestigationState:
        """
        Execute the playbook.

        Args:
            inputs: Input parameters for the investigation
            connectors: Optional dictionary of connectors (email, siem, etc.)
            state: Optional existing state to resume from

        Returns:
            The final investigation state
        """
        connectors = connectors or {}

        # Create or use existing state
        if state is None:
            state = InvestigationState(
                id=InvestigationState.generate_id(),
                type=self.investigation_type,
                status=InvestigationStatus.RUNNING,
                inputs=inputs,
            )

        if self.verbose:
            print(f"\n{'='*60}", file=sys.stderr)
            print(f"  {self.name.upper()} INVESTIGATION", file=sys.stderr)
            print(f"  ID: {state.id}", file=sys.stderr)
            print(f"{'='*60}\n", file=sys.stderr)

        # Track completed steps for dependency checking
        completed_steps: Dict[str, StepResult] = {}
        for existing_result in state.steps:
            if existing_result.status == StepStatus.COMPLETED:
                completed_steps[existing_result.name] = existing_result

        # Execute each step
        for step in self.steps:
            # Skip if already completed
            if step.name in completed_steps:
                if self.verbose:
                    print(f"  [SKIP] {step.name} (already completed)", file=sys.stderr)
                continue

            # Check dependencies
            can_execute = True
            for dep in step.depends_on:
                if dep not in completed_steps:
                    can_execute = False
                    if self.verbose:
                        print(f"  [WAIT] {step.name} - waiting for: {dep}", file=sys.stderr)
                    break
                # Check if dependency failed
                dep_result = completed_steps[dep]
                if dep_result.status == StepStatus.FAILED:
                    can_execute = False
                    if self.verbose:
                        print(f"  [SKIP] {step.name} - dependency {dep} failed", file=sys.stderr)
                    break

            if not can_execute:
                # Skip step if dependencies not met
                skipped_result = StepResult(
                    name=step.name,
                    status=StepStatus.SKIPPED,
                    started_at=datetime.now(timezone.utc),
                    completed_at=datetime.now(timezone.utc),
                    error="Dependencies not met",
                )
                state.add_step_result(skipped_result)
                continue

            # Execute the step
            if self.verbose:
                print(f"  [RUN ] {step.name}: {step.description}", file=sys.stderr)

            start_time = time.time()
            started_at = datetime.now(timezone.utc)

            try:
                result = self._execute_step(step, state, connectors)
                result.started_at = started_at
                result.completed_at = datetime.now(timezone.utc)
                result.duration_seconds = time.time() - start_time

                if self.verbose:
                    status_icon = "[OK  ]" if result.status == StepStatus.COMPLETED else "[FAIL]"
                    print(
                        f"  {status_icon} {step.name} ({result.duration_seconds:.1f}s)",
                        file=sys.stderr,
                    )

            except Exception as e:
                result = StepResult(
                    name=step.name,
                    status=StepStatus.FAILED,
                    started_at=started_at,
                    completed_at=datetime.now(timezone.utc),
                    duration_seconds=time.time() - start_time,
                    error=str(e),
                )
                if self.verbose:
                    print(f"  [ERR ] {step.name}: {e}", file=sys.stderr)

            # Record result
            state.add_step_result(result)

            if result.status == StepStatus.COMPLETED:
                completed_steps[step.name] = result
            elif result.status == StepStatus.FAILED:
                if step.on_failure == "stop":
                    state.mark_failed(f"Step '{step.name}' failed: {result.error}")
                    break

        # Determine final status if not already set
        if state.status == InvestigationStatus.RUNNING:
            failed_required = [
                r
                for r in state.steps
                if r.status == StepStatus.FAILED
                and any(s.name == r.name and s.required for s in self.steps)
            ]

            if failed_required:
                state.mark_failed(
                    f"Required step(s) failed: {', '.join(r.name for r in failed_required)}"
                )
            else:
                # Mark as completed - risk score and verdict should be set by calculate_verdict step
                state.status = InvestigationStatus.COMPLETED
                state.completed_at = datetime.now(timezone.utc)
                state.updated_at = datetime.now(timezone.utc)

        if self.verbose:
            print(f"\n{'='*60}", file=sys.stderr)
            print(f"  Investigation {state.status.value.upper()}", file=sys.stderr)
            print(f"  Risk Score: {state.risk_score}/100", file=sys.stderr)
            print(f"  Verdict: {state.verdict}", file=sys.stderr)
            if state.remediation_actions:
                print(f"  Remediation Actions: {len(state.remediation_actions)}", file=sys.stderr)
            print(f"{'='*60}\n", file=sys.stderr)

        return state

    def get_step(self, step_name: str) -> Optional[PlaybookStep]:
        """Get a step by name."""
        for step in self.steps:
            if step.name == step_name:
                return step
        return None

    def validate(self) -> List[str]:
        """
        Validate the playbook definition.

        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []

        # Check for unique step names
        step_names = [s.name for s in self.steps]
        if len(step_names) != len(set(step_names)):
            errors.append("Duplicate step names found")

        # Check dependencies reference valid steps
        for step in self.steps:
            for dep in step.depends_on:
                if dep not in step_names:
                    errors.append(f"Step '{step.name}' depends on unknown step '{dep}'")

        # Check for circular dependencies
        def has_cycle(step_name: str, visited: set, rec_stack: set) -> bool:
            visited.add(step_name)
            rec_stack.add(step_name)

            step = self.get_step(step_name)
            if step:
                for dep in step.depends_on:
                    if dep not in visited:
                        if has_cycle(dep, visited, rec_stack):
                            return True
                    elif dep in rec_stack:
                        return True

            rec_stack.remove(step_name)
            return False

        visited = set()
        for step in self.steps:
            if step.name not in visited:
                if has_cycle(step.name, visited, set()):
                    errors.append(f"Circular dependency detected involving '{step.name}'")
                    break

        return errors
