#!/usr/bin/env python3
"""
Workflow Engine - Pre-built investigation patterns
Part of SecOps Helper Operationalization (Phase 5)
"""

import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Callable
from pathlib import Path
from datetime import datetime

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.scorer import RiskScorer, Severity
from core.reporter import Reporter


@dataclass
class WorkflowStep:
    """Represents a single step in a workflow"""

    name: str
    description: str
    tool: str  # Tool identifier
    required: bool = True
    depends_on: List[str] = field(default_factory=list)


@dataclass
class StepResult:
    """Result from executing a workflow step"""

    step_name: str
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    duration_ms: int = 0


class WorkflowContext:
    """
    Shared context passed between workflow steps.
    Accumulates data, IOCs, and findings throughout the workflow.
    """

    def __init__(self, input_value: str, input_type: str):
        self.input_value = input_value
        self.input_type = input_type
        self.start_time = datetime.utcnow()

        # Accumulated data
        self.iocs: Dict[str, List[str]] = {"hashes": [], "domains": [], "ips": [], "urls": [], "emails": []}
        self.tool_results: Dict[str, Any] = {}
        self.step_results: List[StepResult] = []
        self.scorer = RiskScorer()

        # Intermediate data for passing between steps
        self.data: Dict[str, Any] = {}

    def add_iocs(self, ioc_type: str, values: List[str]):
        """Add IOCs to context, deduplicating"""
        if ioc_type in self.iocs:
            existing = set(self.iocs[ioc_type])
            existing.update(values)
            self.iocs[ioc_type] = list(existing)

    def add_tool_result(self, tool_name: str, result: Any):
        """Add tool result to context"""
        self.tool_results[tool_name] = result

    def add_step_result(self, result: StepResult):
        """Add step result to history"""
        self.step_results.append(result)

    def get_elapsed_time(self) -> float:
        """Get elapsed time in seconds"""
        return (datetime.utcnow() - self.start_time).total_seconds()


class Workflow(ABC):
    """
    Base class for all workflows.
    Subclasses implement specific investigation patterns.
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.steps: List[WorkflowStep] = []
        self.reporter = Reporter()
        self._define_steps()

    @property
    @abstractmethod
    def name(self) -> str:
        """Workflow name"""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Workflow description"""
        pass

    @abstractmethod
    def _define_steps(self):
        """Define workflow steps. Called during __init__."""
        pass

    @abstractmethod
    def _execute_step(self, step: WorkflowStep, context: WorkflowContext) -> StepResult:
        """Execute a single workflow step"""
        pass

    def _log(self, message: str):
        """Log message if verbose mode enabled"""
        if self.verbose:
            print(f"[*] {message}", file=sys.stderr)

    def _log_step(self, step_num: int, total: int, step: WorkflowStep):
        """Log step progress"""
        if self.verbose:
            print(f"[{step_num}/{total}] {step.description}...", file=sys.stderr)

    def execute(self, input_value: str, input_type: str = "unknown") -> Dict[str, Any]:
        """
        Execute the complete workflow.

        Args:
            input_value: The input to analyze (file path, hash, etc.)
            input_type: Type of input (email, hash, file, etc.)

        Returns:
            Dict with workflow results
        """
        context = WorkflowContext(input_value, input_type)
        total_steps = len(self.steps)

        self._log(f"Starting workflow: {self.name}")
        self._log(f"Input: {input_value} (type: {input_type})")

        for i, step in enumerate(self.steps, 1):
            self._log_step(i, total_steps, step)

            # Check dependencies
            if step.depends_on:
                deps_met = all(any(r.step_name == dep and r.success for r in context.step_results) for dep in step.depends_on)
                if not deps_met:
                    self._log(f"  Skipping: dependencies not met")
                    continue

            # Execute step
            try:
                import time

                start = time.time()
                result = self._execute_step(step, context)
                result.duration_ms = int((time.time() - start) * 1000)
                context.add_step_result(result)

                if not result.success and step.required:
                    self._log(f"  Failed: {result.error}")
                    if step.required:
                        # Continue anyway for non-critical failures
                        pass

            except Exception as e:
                self._log(f"  Error: {e}")
                context.add_step_result(StepResult(step_name=step.name, success=False, error=str(e)))

        self._log(f"Workflow complete in {context.get_elapsed_time():.1f}s")

        return {
            "workflow": self.name,
            "input": input_value,
            "type": input_type,
            "duration_seconds": context.get_elapsed_time(),
            "steps_completed": len([r for r in context.step_results if r.success]),
            "steps_total": total_steps,
            "iocs": context.iocs,
            "tool_results": context.tool_results,
            "scorer": context.scorer,
            "step_results": [
                {"name": r.step_name, "success": r.success, "duration_ms": r.duration_ms, "error": r.error}
                for r in context.step_results
            ],
        }


class WorkflowRegistry:
    """Registry of available workflows"""

    _workflows: Dict[str, type] = {}

    @classmethod
    def register(cls, workflow_class: type):
        """Register a workflow class"""
        # Use the workflow's name property
        instance = workflow_class(verbose=False)
        cls._workflows[instance.name] = workflow_class
        return workflow_class

    @classmethod
    def get(cls, name: str) -> Optional[type]:
        """Get a workflow class by name"""
        return cls._workflows.get(name)

    @classmethod
    def list_all(cls) -> List[Dict[str, str]]:
        """List all registered workflows"""
        result = []
        for name, workflow_class in cls._workflows.items():
            instance = workflow_class(verbose=False)
            result.append({"name": name, "description": instance.description, "steps": len(instance.steps)})
        return result


def workflow(cls):
    """Decorator to register a workflow"""
    WorkflowRegistry.register(cls)
    return cls
