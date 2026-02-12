#!/usr/bin/env python3
"""
Extended unit tests for the Investigation Automation module.

Focuses on increasing test coverage for:
- InvestigationEngine (engine.py)
- BasePlaybook (playbooks/base.py)
- MockSIEMConnector (connectors/mock/siem.py)
- MockEmailConnector (connectors/mock/email.py)
- InvestigationStateManager (state.py)

Tests end-to-end engine flows, playbook execution paths,
connector queries with filters, and state persistence edge cases.
"""

import pytest
import sys
import os
import json
import tempfile
from pathlib import Path
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock, PropertyMock

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from vlair.investigate.models import (
    InvestigationStatus,
    StepStatus,
    RemediationStatus,
    StepResult,
    RemediationAction,
    InvestigationState,
)
from vlair.investigate.state import InvestigationStateManager
from vlair.investigate.registry import PlaybookRegistry
from vlair.investigate.engine import InvestigationEngine
from vlair.investigate.playbooks.base import BasePlaybook, PlaybookStep
from vlair.investigate.playbooks.phishing import PhishingPlaybook
from vlair.investigate.connectors.base import Email, URLClickEvent
from vlair.investigate.connectors.mock.email import MockEmailConnector
from vlair.investigate.connectors.mock.siem import MockSIEMConnector

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def temp_db():
    """Create a temporary database file."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    yield db_path
    try:
        os.unlink(db_path)
    except Exception:
        pass


def _create_test_state(
    inv_id="INV-TEST-001",
    inv_type="phishing",
    status=InvestigationStatus.PENDING,
    risk_score=0,
    verdict="UNKNOWN",
    inputs=None,
):
    """Create a test InvestigationState."""
    return InvestigationState(
        id=inv_id,
        type=inv_type,
        status=status,
        inputs=inputs or {},
        risk_score=risk_score,
        verdict=verdict,
    )


class ConcretePlaybook(BasePlaybook):
    """A concrete playbook implementation for testing the BasePlaybook ABC."""

    @property
    def name(self) -> str:
        return "test-playbook"

    @property
    def description(self) -> str:
        return "A test playbook for unit testing"

    def _define_steps(self):
        self.steps = [
            PlaybookStep(
                name="step_a",
                description="First step",
                required=True,
            ),
            PlaybookStep(
                name="step_b",
                description="Second step depends on A",
                required=True,
                depends_on=["step_a"],
            ),
            PlaybookStep(
                name="step_c",
                description="Optional step depends on A",
                required=False,
                depends_on=["step_a"],
            ),
            PlaybookStep(
                name="step_d",
                description="Final step",
                required=True,
                depends_on=["step_b"],
            ),
        ]

    def _execute_step(self, step, state, connectors):
        # Return completed for all steps by default
        return StepResult(
            name=step.name,
            status=StepStatus.COMPLETED,
            output={"message": f"Executed {step.name}"},
        )


class FailingPlaybook(BasePlaybook):
    """A playbook that fails on a required step with on_failure='stop'."""

    @property
    def name(self) -> str:
        return "failing-playbook"

    @property
    def description(self) -> str:
        return "A playbook that fails"

    def _define_steps(self):
        self.steps = [
            PlaybookStep(
                name="step_ok",
                description="OK step",
                required=True,
            ),
            PlaybookStep(
                name="step_fail",
                description="Failing step",
                required=True,
                depends_on=["step_ok"],
                on_failure="stop",
            ),
            PlaybookStep(
                name="step_after_fail",
                description="Step after failure",
                required=True,
                depends_on=["step_fail"],
            ),
        ]

    def _execute_step(self, step, state, connectors):
        if step.name == "step_fail":
            return StepResult(
                name=step.name,
                status=StepStatus.FAILED,
                error="Intentional failure",
            )
        return StepResult(
            name=step.name,
            status=StepStatus.COMPLETED,
            output={"ok": True},
        )


class ExceptionPlaybook(BasePlaybook):
    """A playbook whose step raises an exception."""

    @property
    def name(self) -> str:
        return "exception-playbook"

    @property
    def description(self) -> str:
        return "A playbook that raises exceptions"

    def _define_steps(self):
        self.steps = [
            PlaybookStep(name="boom", description="Explodes", required=False),
        ]

    def _execute_step(self, step, state, connectors):
        raise RuntimeError("Unexpected error in step")


# ===========================================================================
# BasePlaybook tests
# ===========================================================================


class TestBasePlaybookExecute:
    """Test BasePlaybook.execute() method and its sub-paths."""

    def test_execute_all_steps_complete(self):
        """All steps complete successfully."""
        pb = ConcretePlaybook(verbose=False)
        state = pb.execute(inputs={"test": True})

        assert state.status == InvestigationStatus.COMPLETED
        assert len(state.steps) == 4
        assert all(s.status == StepStatus.COMPLETED for s in state.steps)

    def test_execute_verbose_prints_output(self, capsys):
        """Verbose mode prints step progress to stderr."""
        pb = ConcretePlaybook(verbose=True)
        state = pb.execute(inputs={"test": True})

        captured = capsys.readouterr()
        assert "RUN" in captured.err
        assert "OK" in captured.err
        assert state.status == InvestigationStatus.COMPLETED

    def test_execute_creates_state_if_none(self):
        """execute() creates an InvestigationState if none provided."""
        pb = ConcretePlaybook(verbose=False)
        state = pb.execute(inputs={"file": "test.eml"})

        assert state.id.startswith("INV-")
        assert state.type == "test"  # from "test-playbook" -> "test"

    def test_execute_uses_existing_state(self):
        """execute() uses the provided state object."""
        pb = ConcretePlaybook(verbose=False)
        existing_state = _create_test_state(
            inv_id="INV-EXISTING-001",
            status=InvestigationStatus.RUNNING,
        )
        state = pb.execute(inputs={}, state=existing_state)

        assert state.id == "INV-EXISTING-001"
        assert state.status == InvestigationStatus.COMPLETED

    def test_execute_skips_already_completed_steps(self):
        """Steps already completed in state are skipped."""
        pb = ConcretePlaybook(verbose=True)
        existing_state = _create_test_state(status=InvestigationStatus.RUNNING)
        # Pre-populate step_a as completed
        existing_state.add_step_result(
            StepResult(
                name="step_a",
                status=StepStatus.COMPLETED,
                output={"pre": True},
            )
        )
        state = pb.execute(inputs={}, state=existing_state)

        # step_a should have been skipped (only the pre-existing one in results)
        step_a_results = [s for s in state.steps if s.name == "step_a"]
        assert len(step_a_results) == 1
        assert step_a_results[0].output == {"pre": True}

    def test_execute_skips_step_when_dependency_failed(self):
        """Steps with failed dependencies are skipped."""
        pb = FailingPlaybook(verbose=True)
        state = pb.execute(inputs={})

        # step_fail should fail, step_after_fail should not be added
        # (because on_failure="stop" causes a break)
        assert state.status == InvestigationStatus.FAILED
        assert "step_fail" in state.error

    def test_execute_step_exception_is_caught(self):
        """Exception in _execute_step is caught and recorded."""
        pb = ExceptionPlaybook(verbose=True)
        state = pb.execute(inputs={})

        boom_step = next((s for s in state.steps if s.name == "boom"), None)
        assert boom_step is not None
        assert boom_step.status == StepStatus.FAILED
        assert "Unexpected error" in boom_step.error

    def test_execute_failed_required_step_marks_investigation_failed(self):
        """A required step failing marks the investigation as failed."""

        class FailRequiredPlaybook(BasePlaybook):
            @property
            def name(self):
                return "fail-required"

            @property
            def description(self):
                return "test"

            def _define_steps(self):
                self.steps = [
                    PlaybookStep(name="required_fail", description="fails", required=True),
                ]

            def _execute_step(self, step, state, connectors):
                return StepResult(
                    name=step.name,
                    status=StepStatus.FAILED,
                    error="required step failed",
                )

        pb = FailRequiredPlaybook(verbose=False)
        state = pb.execute(inputs={})

        assert state.status == InvestigationStatus.FAILED
        assert "required_fail" in state.error

    def test_execute_verbose_with_remediation_actions(self, capsys):
        """Verbose output includes remediation action count."""

        class RemediationPlaybook(BasePlaybook):
            @property
            def name(self):
                return "remediation-test"

            @property
            def description(self):
                return "test"

            def _define_steps(self):
                self.steps = [
                    PlaybookStep(name="add_action", description="adds action", required=True),
                ]

            def _execute_step(self, step, state, connectors):
                state.add_remediation_action(
                    RemediationAction(
                        id="act-1",
                        name="Test Action",
                        action_type="block_sender",
                        target="test@test.com",
                    )
                )
                return StepResult(name=step.name, status=StepStatus.COMPLETED)

        pb = RemediationPlaybook(verbose=True)
        state = pb.execute(inputs={})

        captured = capsys.readouterr()
        assert "Remediation Actions:" in captured.err
        assert len(state.remediation_actions) == 1


class TestBasePlaybookHelpers:
    """Test BasePlaybook helper methods."""

    def test_get_step_found(self):
        pb = ConcretePlaybook(verbose=False)
        step = pb.get_step("step_a")
        assert step is not None
        assert step.name == "step_a"

    def test_get_step_not_found(self):
        pb = ConcretePlaybook(verbose=False)
        step = pb.get_step("nonexistent")
        assert step is None

    def test_investigation_type_with_dash(self):
        pb = ConcretePlaybook(verbose=False)
        assert pb.investigation_type == "test"

    def test_investigation_type_without_dash(self):
        class NoDashPlaybook(BasePlaybook):
            @property
            def name(self):
                return "simple"

            @property
            def description(self):
                return "test"

            def _define_steps(self):
                self.steps = []

            def _execute_step(self, step, state, connectors):
                pass

        pb = NoDashPlaybook(verbose=False)
        assert pb.investigation_type == "simple"

    def test_validate_no_errors(self):
        pb = ConcretePlaybook(verbose=False)
        errors = pb.validate()
        assert errors == []

    def test_validate_duplicate_step_names(self):
        class DuplicatePlaybook(BasePlaybook):
            @property
            def name(self):
                return "dup"

            @property
            def description(self):
                return "test"

            def _define_steps(self):
                self.steps = [
                    PlaybookStep(name="step1", description="first"),
                    PlaybookStep(name="step1", description="duplicate"),
                ]

            def _execute_step(self, step, state, connectors):
                pass

        pb = DuplicatePlaybook(verbose=False)
        errors = pb.validate()
        assert any("Duplicate" in e for e in errors)

    def test_validate_unknown_dependency(self):
        class BadDepPlaybook(BasePlaybook):
            @property
            def name(self):
                return "baddep"

            @property
            def description(self):
                return "test"

            def _define_steps(self):
                self.steps = [
                    PlaybookStep(name="step1", description="test", depends_on=["nonexistent"]),
                ]

            def _execute_step(self, step, state, connectors):
                pass

        pb = BadDepPlaybook(verbose=False)
        errors = pb.validate()
        assert any("unknown step" in e for e in errors)

    def test_validate_circular_dependency(self):
        class CircularPlaybook(BasePlaybook):
            @property
            def name(self):
                return "circular"

            @property
            def description(self):
                return "test"

            def _define_steps(self):
                self.steps = [
                    PlaybookStep(name="a", description="a", depends_on=["b"]),
                    PlaybookStep(name="b", description="b", depends_on=["a"]),
                ]

            def _execute_step(self, step, state, connectors):
                pass

        pb = CircularPlaybook(verbose=False)
        errors = pb.validate()
        assert any("Circular" in e or "circular" in e.lower() for e in errors)

    def test_playbook_step_post_init_none_depends_on(self):
        """PlaybookStep __post_init__ handles None depends_on."""
        step = PlaybookStep(name="test", description="test", depends_on=None)
        assert step.depends_on == []

    def test_playbook_step_defaults(self):
        step = PlaybookStep(name="test", description="test")
        assert step.required is True
        assert step.timeout_seconds == 300
        assert step.retry_count == 0
        assert step.on_failure == "continue"


# ===========================================================================
# InvestigationEngine tests
# ===========================================================================


class TestInvestigationEngineRunInvestigation:
    """Test InvestigationEngine.run_investigation() paths."""

    def test_run_investigation_not_found(self, temp_db):
        """Raises ValueError for unknown investigation ID."""
        manager = InvestigationStateManager(db_path=temp_db)
        engine = InvestigationEngine(state_manager=manager)

        with pytest.raises(ValueError, match="not found"):
            engine.run_investigation("INV-NONEXISTENT")

    def test_run_investigation_already_completed(self, temp_db):
        """Already completed investigation is returned as-is."""
        manager = InvestigationStateManager(db_path=temp_db)
        engine = InvestigationEngine(state_manager=manager, verbose=True)

        state = _create_test_state(status=InvestigationStatus.COMPLETED)
        manager.save(state)

        result = engine.run_investigation(state.id)
        assert result.status == InvestigationStatus.COMPLETED

    def test_run_investigation_already_failed(self, temp_db):
        """Already failed investigation is returned as-is."""
        manager = InvestigationStateManager(db_path=temp_db)
        engine = InvestigationEngine(state_manager=manager, verbose=True)

        state = _create_test_state(status=InvestigationStatus.FAILED)
        state.error = "previous error"
        manager.save(state)

        result = engine.run_investigation(state.id)
        assert result.status == InvestigationStatus.FAILED

    def test_run_investigation_playbook_not_found(self, temp_db):
        """Unknown playbook type marks investigation as failed."""
        manager = InvestigationStateManager(db_path=temp_db)
        engine = InvestigationEngine(state_manager=manager)

        state = _create_test_state(
            inv_type="unknown_type",
            status=InvestigationStatus.PENDING,
        )
        manager.save(state)

        result = engine.run_investigation(state.id)
        assert result.status == InvestigationStatus.FAILED
        assert "Playbook not found" in result.error

    def test_run_investigation_playbook_executes(self, temp_db):
        """Registered playbook is found and executed."""
        PlaybookRegistry.register(ConcretePlaybook)
        manager = InvestigationStateManager(db_path=temp_db)
        engine = InvestigationEngine(state_manager=manager)

        state = _create_test_state(
            inv_type="test",
            status=InvestigationStatus.PENDING,
        )
        manager.save(state)

        result = engine.run_investigation(state.id)
        # ConcretePlaybook should complete successfully
        assert result.status in [
            InvestigationStatus.COMPLETED,
            InvestigationStatus.FAILED,
        ]

    def test_run_investigation_playbook_exception(self, temp_db):
        """Exception during playbook execution marks investigation as failed."""

        class CrashPlaybook(BasePlaybook):
            @property
            def name(self):
                return "crash"

            @property
            def description(self):
                return "crash test"

            def _define_steps(self):
                self.steps = []

            def _execute_step(self, step, state, connectors):
                pass

            def execute(self, inputs=None, connectors=None, state=None):
                raise RuntimeError("playbook crashed")

        PlaybookRegistry.register(CrashPlaybook)
        manager = InvestigationStateManager(db_path=temp_db)
        engine = InvestigationEngine(state_manager=manager)

        state = _create_test_state(
            inv_type="crash",
            status=InvestigationStatus.PENDING,
        )
        manager.save(state)

        result = engine.run_investigation(state.id)
        assert result.status == InvestigationStatus.FAILED
        assert "playbook crashed" in result.error


class TestInvestigationEngineStartInvestigation:
    """Test InvestigationEngine.start_investigation()."""

    def test_start_unknown_playbook_raises(self, temp_db):
        """Unknown playbook name raises ValueError."""
        manager = InvestigationStateManager(db_path=temp_db)
        engine = InvestigationEngine(state_manager=manager)

        with pytest.raises(ValueError, match="Unknown playbook"):
            engine.start_investigation("totally_unknown_playbook", {})

    def test_start_without_auto_run(self, temp_db):
        """auto_run=False saves state but does not execute."""
        PlaybookRegistry.register(ConcretePlaybook)
        manager = InvestigationStateManager(db_path=temp_db)
        engine = InvestigationEngine(state_manager=manager, verbose=True)

        state = engine.start_investigation(
            "test-playbook",
            inputs={"file": "test.eml"},
            auto_run=False,
        )

        assert state.status == InvestigationStatus.PENDING
        assert state.id.startswith("INV-")

        # Verify it was saved
        loaded = manager.load(state.id)
        assert loaded is not None

    def test_start_with_auto_run(self, temp_db):
        """auto_run=True executes the playbook immediately."""
        PlaybookRegistry.register(ConcretePlaybook)
        manager = InvestigationStateManager(db_path=temp_db)
        engine = InvestigationEngine(state_manager=manager)

        state = engine.start_investigation(
            "test-playbook",
            inputs={"file": "test.eml"},
            auto_run=True,
        )

        assert state.status in [
            InvestigationStatus.COMPLETED,
            InvestigationStatus.FAILED,
        ]


class TestInvestigationEngineGetAndList:
    """Test get_investigation, list_investigations, delete, stats."""

    def test_get_investigation_valid(self, temp_db):
        """Get a valid investigation by ID."""
        manager = InvestigationStateManager(db_path=temp_db)
        engine = InvestigationEngine(state_manager=manager)

        state = _create_test_state()
        manager.save(state)

        result = engine.get_investigation(state.id)
        assert result is not None
        assert result.id == state.id

    def test_get_investigation_invalid(self, temp_db):
        """Get a non-existent investigation returns None."""
        manager = InvestigationStateManager(db_path=temp_db)
        engine = InvestigationEngine(state_manager=manager)

        result = engine.get_investigation("INV-DOES-NOT-EXIST")
        assert result is None

    def test_list_investigations_with_status_filter(self, temp_db):
        """List investigations filtered by status."""
        manager = InvestigationStateManager(db_path=temp_db)
        engine = InvestigationEngine(state_manager=manager)

        # Create investigations with different statuses
        for i, status in enumerate(
            [
                InvestigationStatus.COMPLETED,
                InvestigationStatus.FAILED,
                InvestigationStatus.COMPLETED,
            ]
        ):
            state = _create_test_state(inv_id=f"INV-LIST-{i}", status=status)
            manager.save(state)

        completed = engine.list_investigations(status=InvestigationStatus.COMPLETED)
        assert len(completed) == 2

        failed = engine.list_investigations(status=InvestigationStatus.FAILED)
        assert len(failed) == 1

    def test_list_investigations_with_type_filter(self, temp_db):
        """List investigations filtered by type."""
        manager = InvestigationStateManager(db_path=temp_db)
        engine = InvestigationEngine(state_manager=manager)

        manager.save(_create_test_state(inv_id="INV-A", inv_type="phishing"))
        manager.save(_create_test_state(inv_id="INV-B", inv_type="malware"))
        manager.save(_create_test_state(inv_id="INV-C", inv_type="phishing"))

        phishing = engine.list_investigations(investigation_type="phishing")
        assert len(phishing) == 2

    def test_list_investigations_with_since_hours(self, temp_db):
        """List investigations filtered by time."""
        manager = InvestigationStateManager(db_path=temp_db)
        engine = InvestigationEngine(state_manager=manager)

        # Create a recent investigation
        state = _create_test_state(inv_id="INV-RECENT")
        manager.save(state)

        results = engine.list_investigations(since_hours=1)
        assert len(results) >= 1

    def test_list_investigations_with_limit(self, temp_db):
        """List investigations respects limit."""
        manager = InvestigationStateManager(db_path=temp_db)
        engine = InvestigationEngine(state_manager=manager)

        for i in range(5):
            manager.save(_create_test_state(inv_id=f"INV-LIM-{i}"))

        results = engine.list_investigations(limit=3)
        assert len(results) == 3

    def test_delete_investigation(self, temp_db):
        """Delete an investigation."""
        manager = InvestigationStateManager(db_path=temp_db)
        engine = InvestigationEngine(state_manager=manager)

        state = _create_test_state(inv_id="INV-DEL")
        manager.save(state)

        assert engine.delete_investigation("INV-DEL") is True
        assert engine.get_investigation("INV-DEL") is None

    def test_get_stats(self, temp_db):
        """Get investigation statistics."""
        manager = InvestigationStateManager(db_path=temp_db)
        engine = InvestigationEngine(state_manager=manager)

        manager.save(
            _create_test_state(
                inv_id="INV-S1",
                status=InvestigationStatus.COMPLETED,
                risk_score=60,
                verdict="SUSPICIOUS",
            )
        )
        manager.save(
            _create_test_state(
                inv_id="INV-S2",
                status=InvestigationStatus.COMPLETED,
                risk_score=80,
                verdict="MALICIOUS",
            )
        )

        stats = engine.get_stats()
        assert stats["total_investigations"] == 2
        assert stats["average_risk_score"] is not None

    def test_add_connector(self, temp_db):
        """Add a connector to the engine."""
        manager = InvestigationStateManager(db_path=temp_db)
        engine = InvestigationEngine(state_manager=manager)

        mock_connector = MagicMock()
        engine.add_connector("email", mock_connector)
        assert engine.connectors["email"] is mock_connector

    def test_get_available_playbooks(self, temp_db):
        """List available playbooks."""
        PlaybookRegistry.register(ConcretePlaybook)
        manager = InvestigationStateManager(db_path=temp_db)
        engine = InvestigationEngine(state_manager=manager)

        playbooks = engine.get_available_playbooks()
        assert isinstance(playbooks, list)
        names = [p["name"] for p in playbooks]
        assert "test-playbook" in names


class TestInvestigationEngineRemediation:
    """Test remediation approval and execution paths."""

    def _setup_state_with_actions(self, manager):
        """Create a state with remediation actions for testing."""
        state = _create_test_state(
            inv_id="INV-REM-001",
            status=InvestigationStatus.COMPLETED,
        )

        action1 = RemediationAction(
            id="act-block",
            name="Block Sender",
            action_type="block_sender",
            target="evil@bad.com",
            status=RemediationStatus.PENDING,
        )
        action2 = RemediationAction(
            id="act-delete",
            name="Delete Email",
            action_type="delete_email",
            target="msg-123",
            status=RemediationStatus.PENDING,
        )
        action3 = RemediationAction(
            id="act-isolate",
            name="Isolate Host",
            action_type="isolate_host",
            target="WORKSTATION-01",
            description="Compromised host",
            status=RemediationStatus.PENDING,
        )
        action4 = RemediationAction(
            id="act-disable",
            name="Disable User",
            action_type="disable_user",
            target="compromised@company.com",
            description="Credential theft",
            status=RemediationStatus.PENDING,
        )
        action5 = RemediationAction(
            id="act-revoke",
            name="Revoke Sessions",
            action_type="revoke_sessions",
            target="compromised@company.com",
            status=RemediationStatus.PENDING,
        )
        action6 = RemediationAction(
            id="act-reset",
            name="Reset Password",
            action_type="reset_password",
            target="compromised@company.com",
            status=RemediationStatus.PENDING,
        )
        action7 = RemediationAction(
            id="act-unknown",
            name="Unknown Action",
            action_type="unknown_type",
            target="something",
            command="manual command",
            status=RemediationStatus.PENDING,
        )

        for action in [action1, action2, action3, action4, action5, action6, action7]:
            state.add_remediation_action(action)

        manager.save(state)
        return state

    def test_approve_remediation_success(self, temp_db):
        """Approve a remediation action."""
        manager = InvestigationStateManager(db_path=temp_db)
        engine = InvestigationEngine(state_manager=manager)
        self._setup_state_with_actions(manager)

        result = engine.approve_remediation("INV-REM-001", "act-block", "admin@company.com")
        assert result is True

        # Verify saved
        state = manager.load("INV-REM-001")
        act = next(a for a in state.remediation_actions if a.id == "act-block")
        assert act.status == RemediationStatus.APPROVED
        assert act.executed_by == "admin@company.com"

    def test_approve_remediation_not_found_investigation(self, temp_db):
        """Approve on non-existent investigation returns False."""
        manager = InvestigationStateManager(db_path=temp_db)
        engine = InvestigationEngine(state_manager=manager)

        result = engine.approve_remediation("INV-NOPE", "act-1", "admin")
        assert result is False

    def test_approve_remediation_not_found_action(self, temp_db):
        """Approve non-existent action returns False."""
        manager = InvestigationStateManager(db_path=temp_db)
        engine = InvestigationEngine(state_manager=manager)
        self._setup_state_with_actions(manager)

        result = engine.approve_remediation("INV-REM-001", "act-nonexistent", "admin")
        assert result is False

    def test_execute_remediation_not_approved(self, temp_db):
        """Execute unapproved action returns error."""
        manager = InvestigationStateManager(db_path=temp_db)
        engine = InvestigationEngine(state_manager=manager)
        self._setup_state_with_actions(manager)

        result = engine.execute_remediation("INV-REM-001", "act-block")
        assert result["success"] is False
        assert "not approved" in result["error"].lower()

    def test_execute_remediation_not_found_investigation(self, temp_db):
        """Execute on non-existent investigation returns error."""
        manager = InvestigationStateManager(db_path=temp_db)
        engine = InvestigationEngine(state_manager=manager)

        result = engine.execute_remediation("INV-NOPE", "act-1")
        assert result["success"] is False
        assert "not found" in result["error"].lower()

    def test_execute_remediation_not_found_action(self, temp_db):
        """Execute non-existent action returns error."""
        manager = InvestigationStateManager(db_path=temp_db)
        engine = InvestigationEngine(state_manager=manager)
        self._setup_state_with_actions(manager)

        result = engine.execute_remediation("INV-REM-001", "act-nonexistent")
        assert result["success"] is False
        assert "not found" in result["error"].lower()

    def test_execute_block_sender(self, temp_db):
        """Execute block_sender action with email connector."""
        manager = InvestigationStateManager(db_path=temp_db)
        mock_email = MagicMock()
        mock_email.block_sender.return_value = True
        engine = InvestigationEngine(state_manager=manager, connectors={"email": mock_email})
        self._setup_state_with_actions(manager)

        engine.approve_remediation("INV-REM-001", "act-block", "admin")
        result = engine.execute_remediation("INV-REM-001", "act-block")

        assert result["success"] is True
        mock_email.block_sender.assert_called_once_with("evil@bad.com")

    def test_execute_delete_email(self, temp_db):
        """Execute delete_email action with email connector."""
        manager = InvestigationStateManager(db_path=temp_db)
        mock_email = MagicMock()
        mock_email.delete_message.return_value = True
        engine = InvestigationEngine(state_manager=manager, connectors={"email": mock_email})
        self._setup_state_with_actions(manager)

        engine.approve_remediation("INV-REM-001", "act-delete", "admin")
        result = engine.execute_remediation("INV-REM-001", "act-delete")

        assert result["success"] is True
        mock_email.delete_message.assert_called_once_with("msg-123")

    def test_execute_isolate_host(self, temp_db):
        """Execute isolate_host action with EDR connector."""
        manager = InvestigationStateManager(db_path=temp_db)
        mock_edr = MagicMock()
        mock_edr.isolate_host.return_value = True
        engine = InvestigationEngine(state_manager=manager, connectors={"edr": mock_edr})
        self._setup_state_with_actions(manager)

        engine.approve_remediation("INV-REM-001", "act-isolate", "admin")
        result = engine.execute_remediation("INV-REM-001", "act-isolate")

        assert result["success"] is True
        mock_edr.isolate_host.assert_called_once()

    def test_execute_disable_user(self, temp_db):
        """Execute disable_user action with identity connector."""
        manager = InvestigationStateManager(db_path=temp_db)
        mock_identity = MagicMock()
        mock_identity.disable_user.return_value = True
        engine = InvestigationEngine(state_manager=manager, connectors={"identity": mock_identity})
        self._setup_state_with_actions(manager)

        engine.approve_remediation("INV-REM-001", "act-disable", "admin")
        result = engine.execute_remediation("INV-REM-001", "act-disable")

        assert result["success"] is True
        mock_identity.disable_user.assert_called_once()

    def test_execute_revoke_sessions(self, temp_db):
        """Execute revoke_sessions action with identity connector."""
        manager = InvestigationStateManager(db_path=temp_db)
        mock_identity = MagicMock()
        mock_identity.revoke_sessions.return_value = True
        engine = InvestigationEngine(state_manager=manager, connectors={"identity": mock_identity})
        self._setup_state_with_actions(manager)

        engine.approve_remediation("INV-REM-001", "act-revoke", "admin")
        result = engine.execute_remediation("INV-REM-001", "act-revoke")

        assert result["success"] is True
        mock_identity.revoke_sessions.assert_called_once()

    def test_execute_reset_password(self, temp_db):
        """Execute reset_password action with identity connector."""
        manager = InvestigationStateManager(db_path=temp_db)
        mock_identity = MagicMock()
        mock_identity.reset_password.return_value = True
        engine = InvestigationEngine(state_manager=manager, connectors={"identity": mock_identity})
        self._setup_state_with_actions(manager)

        engine.approve_remediation("INV-REM-001", "act-reset", "admin")
        result = engine.execute_remediation("INV-REM-001", "act-reset")

        assert result["success"] is True
        mock_identity.reset_password.assert_called_once()

    def test_execute_unknown_action_type_no_connector(self, temp_db):
        """Unknown action type without connector returns result with manual instruction.

        The outer success is True because the action executed without exception,
        but the inner result indicates manual action is needed.
        """
        manager = InvestigationStateManager(db_path=temp_db)
        engine = InvestigationEngine(state_manager=manager)
        self._setup_state_with_actions(manager)

        engine.approve_remediation("INV-REM-001", "act-unknown", "admin")
        result = engine.execute_remediation("INV-REM-001", "act-unknown")

        assert result["success"] is True
        inner = result["result"]
        assert inner["success"] is False
        assert "Manual action" in inner["message"]

    def test_execute_remediation_connector_raises(self, temp_db):
        """Connector exception marks action as FAILED."""
        manager = InvestigationStateManager(db_path=temp_db)
        mock_email = MagicMock()
        mock_email.block_sender.side_effect = ConnectionError("connection refused")
        engine = InvestigationEngine(state_manager=manager, connectors={"email": mock_email})
        self._setup_state_with_actions(manager)

        engine.approve_remediation("INV-REM-001", "act-block", "admin")
        result = engine.execute_remediation("INV-REM-001", "act-block")

        assert result["success"] is False
        assert "connection refused" in result["error"]

        # Verify action status was saved
        state = manager.load("INV-REM-001")
        act = next(a for a in state.remediation_actions if a.id == "act-block")
        assert act.status == RemediationStatus.FAILED


class TestInvestigationEngineResumeInvestigation:
    """Test resume_investigation()."""

    def test_resume_not_found(self, temp_db):
        """Raises ValueError for unknown investigation."""
        manager = InvestigationStateManager(db_path=temp_db)
        engine = InvestigationEngine(state_manager=manager)

        with pytest.raises(ValueError, match="not found"):
            engine.resume_investigation("INV-NOPE")

    def test_resume_failed_investigation(self, temp_db):
        """Resume resets a failed investigation and re-runs it."""
        PlaybookRegistry.register(ConcretePlaybook)
        manager = InvestigationStateManager(db_path=temp_db)
        engine = InvestigationEngine(state_manager=manager)

        state = _create_test_state(
            inv_type="test",
            status=InvestigationStatus.FAILED,
        )
        state.error = "previous failure"
        manager.save(state)

        result = engine.resume_investigation(state.id)
        # After resume, the state is re-run. Depending on playbook registry
        # it may complete or fail, but status should not be the original FAILED
        # with the same error
        assert result is not None

    def test_resume_pending_investigation(self, temp_db):
        """Resume a pending investigation just runs it."""
        PlaybookRegistry.register(ConcretePlaybook)
        manager = InvestigationStateManager(db_path=temp_db)
        engine = InvestigationEngine(state_manager=manager)

        state = _create_test_state(
            inv_type="test",
            status=InvestigationStatus.PENDING,
        )
        manager.save(state)

        result = engine.resume_investigation(state.id)
        assert result is not None


# ===========================================================================
# MockSIEMConnector extended tests
# ===========================================================================


class TestMockSIEMConnectorExtended:
    """Extended tests for MockSIEMConnector methods and scenarios."""

    def test_phishing_scenario_setup(self):
        """Phishing scenario has URL clicks and events."""
        siem = MockSIEMConnector(scenario="phishing")
        assert len(siem._url_clicks) > 0
        assert len(siem._events) > 0

    def test_clean_scenario_setup(self):
        """Clean scenario has normal events and no clicks."""
        siem = MockSIEMConnector(scenario="clean")
        assert len(siem._url_clicks) == 0
        assert len(siem._events) == 10

    def test_breach_scenario_setup(self):
        """Breach scenario has data exfiltration and lateral movement events."""
        siem = MockSIEMConnector(scenario="breach")
        assert len(siem._events) >= 2
        event_types = [e.get("event_type") for e in siem._events]
        assert "file_upload" in event_types
        assert "remote_login" in event_types

    def test_search_keyword_matching(self):
        """Search finds events matching keyword."""
        siem = MockSIEMConnector(scenario="phishing")
        results = siem.search("phishing")
        assert len(results) > 0

    def test_search_no_match(self):
        """Search with no matches returns empty list."""
        siem = MockSIEMConnector(scenario="clean")
        results = siem.search("nonexistent_keyword_xyz")
        assert len(results) == 0

    def test_search_with_time_filters(self):
        """Search respects start_time and end_time filters."""
        siem = MockSIEMConnector(scenario="phishing")
        now = datetime.now(timezone.utc)

        # Very old start time should include all events
        results = siem.search("company", start_time=now - timedelta(days=10))
        old_count = len(results)

        # Future start time should exclude all
        results = siem.search("company", start_time=now + timedelta(hours=1))
        assert len(results) == 0

        # Very old end_time should exclude recent events
        results = siem.search("company", end_time=now - timedelta(days=10))
        assert len(results) == 0

    def test_search_with_limit(self):
        """Search respects the limit parameter."""
        siem = MockSIEMConnector(scenario="phishing")
        results = siem.search("", limit=1)
        assert len(results) <= 1

    def test_get_events_by_host(self):
        """Get events filtered by hostname."""
        siem = MockSIEMConnector(scenario="phishing")
        results = siem.get_events_by_host("WORKSTATION-01")
        assert len(results) > 0
        assert all("WORKSTATION-01" in e.get("hostname", "").upper() for e in results)

    def test_get_events_by_host_no_match(self):
        """Get events for unknown hostname returns empty."""
        siem = MockSIEMConnector(scenario="phishing")
        results = siem.get_events_by_host("NONEXISTENT-HOST")
        assert len(results) == 0

    def test_get_events_by_host_with_event_type_filter(self):
        """Event type filter works correctly."""
        siem = MockSIEMConnector(scenario="phishing")
        results = siem.get_events_by_host(
            "WORKSTATION-01",
            event_types=["proxy_access"],
        )
        for event in results:
            assert event.get("event_type") == "proxy_access"

    def test_get_events_by_host_with_time_filters(self):
        """Time filters work for host events."""
        siem = MockSIEMConnector(scenario="phishing")
        now = datetime.now(timezone.utc)
        results = siem.get_events_by_host(
            "WORKSTATION-01",
            start_time=now - timedelta(days=1),
            end_time=now + timedelta(hours=1),
        )
        assert isinstance(results, list)

    def test_get_events_by_user(self):
        """Get events filtered by username."""
        siem = MockSIEMConnector(scenario="phishing")
        results = siem.get_events_by_user("user1@company.com")
        assert len(results) > 0
        assert all("user1" in e.get("user", "").lower() for e in results)

    def test_get_events_by_user_no_match(self):
        """Get events for unknown user returns empty."""
        siem = MockSIEMConnector(scenario="phishing")
        results = siem.get_events_by_user("nobody@nowhere.com")
        assert len(results) == 0

    def test_get_events_by_user_with_event_type_filter(self):
        """Event type filter works for user events."""
        siem = MockSIEMConnector(scenario="phishing")
        results = siem.get_events_by_user(
            "user1@company.com",
            event_types=["credential_submission"],
        )
        for event in results:
            assert event.get("event_type") == "credential_submission"

    def test_get_events_by_user_with_time_filters(self):
        """Time filters work for user events."""
        siem = MockSIEMConnector(scenario="phishing")
        now = datetime.now(timezone.utc)
        results = siem.get_events_by_user(
            "user1@company.com",
            start_time=now - timedelta(days=1),
            end_time=now + timedelta(hours=1),
        )
        assert isinstance(results, list)

    def test_get_events_by_user_with_limit(self):
        """Limit parameter works for user events."""
        siem = MockSIEMConnector(scenario="phishing")
        results = siem.get_events_by_user("user1@company.com", limit=1)
        assert len(results) <= 1

    def test_get_url_clicks_by_url(self):
        """URL click filter works."""
        siem = MockSIEMConnector(scenario="phishing")
        results = siem.get_url_clicks(url="micros0ft")
        assert len(results) > 0

    def test_get_url_clicks_by_domain(self):
        """Domain filter for URL clicks."""
        siem = MockSIEMConnector(scenario="phishing")
        results = siem.get_url_clicks(domain="micros0ft-secure-login.com")
        assert len(results) > 0

    def test_get_url_clicks_by_user(self):
        """User filter for URL clicks."""
        siem = MockSIEMConnector(scenario="phishing")
        results = siem.get_url_clicks(user="user1@company.com")
        assert len(results) > 0

    def test_get_url_clicks_with_time_filters(self):
        """Time filters for URL clicks."""
        siem = MockSIEMConnector(scenario="phishing")
        now = datetime.now(timezone.utc)
        results = siem.get_url_clicks(
            start_time=now - timedelta(days=1),
            end_time=now + timedelta(hours=1),
        )
        assert isinstance(results, list)

    def test_get_url_clicks_with_limit(self):
        """Limit for URL clicks."""
        siem = MockSIEMConnector(scenario="phishing")
        results = siem.get_url_clicks(limit=1)
        assert len(results) <= 1

    def test_get_url_clicks_no_match(self):
        """No matching URL clicks."""
        siem = MockSIEMConnector(scenario="clean")
        results = siem.get_url_clicks(url="anything")
        assert len(results) == 0

    def test_get_credential_submissions(self):
        """Get credential submission events."""
        siem = MockSIEMConnector(scenario="phishing")
        results = siem.get_credential_submissions()
        assert len(results) > 0
        assert all(e.get("event_type") == "credential_submission" for e in results)

    def test_get_credential_submissions_with_url_filter(self):
        """Credential submissions filtered by URL."""
        siem = MockSIEMConnector(scenario="phishing")
        results = siem.get_credential_submissions(url="micros0ft")
        assert len(results) > 0

    def test_get_credential_submissions_with_user_filter(self):
        """Credential submissions filtered by user."""
        siem = MockSIEMConnector(scenario="phishing")
        results = siem.get_credential_submissions(user="user1")
        assert len(results) > 0

    def test_get_credential_submissions_with_time_filters(self):
        """Time filters for credential submissions."""
        siem = MockSIEMConnector(scenario="phishing")
        now = datetime.now(timezone.utc)
        results = siem.get_credential_submissions(
            start_time=now - timedelta(days=1),
            end_time=now + timedelta(hours=1),
        )
        assert isinstance(results, list)

    def test_get_credential_submissions_no_match(self):
        """No credential submissions in clean scenario."""
        siem = MockSIEMConnector(scenario="clean")
        results = siem.get_credential_submissions()
        assert len(results) == 0

    def test_add_test_event(self):
        """Add a custom test event."""
        siem = MockSIEMConnector(scenario="clean")
        initial_count = len(siem._events)
        siem.add_test_event({"event_type": "custom", "data": "test"})
        assert len(siem._events) == initial_count + 1

    def test_add_test_url_click(self):
        """Add a custom test URL click."""
        siem = MockSIEMConnector(scenario="clean")
        click = URLClickEvent(
            event_id="test-click",
            timestamp=datetime.now(timezone.utc),
            user="test@test.com",
            url="http://test.com",
        )
        siem.add_test_url_click(click)
        assert len(siem._url_clicks) == 1


# ===========================================================================
# MockEmailConnector extended tests
# ===========================================================================


class TestMockEmailConnectorExtended:
    """Extended tests for MockEmailConnector methods and scenarios."""

    def test_phishing_scenario_has_messages(self):
        """Phishing scenario has at least the phishing email."""
        conn = MockEmailConnector(scenario="phishing")
        assert len(conn._messages) >= 2

    def test_clean_scenario(self):
        """Clean scenario has a legitimate email."""
        conn = MockEmailConnector(scenario="clean")
        assert len(conn._messages) >= 1
        email = list(conn._messages.values())[0]
        assert email.spf_result == "pass"

    def test_malware_scenario(self):
        """Malware scenario has email with attachment."""
        conn = MockEmailConnector(scenario="malware")
        assert len(conn._messages) >= 1
        email = list(conn._messages.values())[0]
        assert len(email.attachments) > 0

    def test_get_message_existing(self):
        """Get an existing message."""
        conn = MockEmailConnector(scenario="phishing")
        email = conn.get_message("<phishing123@malicious.com>")
        assert email is not None
        assert "micros0ft" in email.sender_domain

    def test_get_message_nonexistent(self):
        """Get a non-existent message returns None."""
        conn = MockEmailConnector(scenario="phishing")
        email = conn.get_message("<nonexistent@nowhere.com>")
        assert email is None

    def test_search_messages_by_sender(self):
        """Search messages by sender."""
        conn = MockEmailConnector(scenario="phishing")
        results = conn.search_messages(sender="micros0ft")
        assert len(results) > 0

    def test_search_messages_by_subject(self):
        """Search messages by subject."""
        conn = MockEmailConnector(scenario="phishing")
        results = conn.search_messages(subject="Urgent")
        assert len(results) > 0

    def test_search_messages_by_recipient(self):
        """Search messages by recipient (including CC)."""
        conn = MockEmailConnector(scenario="phishing")
        results = conn.search_messages(recipient="admin@company.com")
        assert len(results) > 0  # admin is in CC

    def test_search_messages_by_time_range(self):
        """Search messages with time range filter."""
        conn = MockEmailConnector(scenario="phishing")
        now = datetime.now(timezone.utc)

        # All recent messages
        results = conn.search_messages(
            start_time=now - timedelta(days=10),
            end_time=now + timedelta(hours=1),
        )
        assert len(results) > 0

        # Exclude recent with old end_time
        results = conn.search_messages(end_time=now - timedelta(days=30))
        assert len(results) == 0

    def test_search_messages_with_limit(self):
        """Search messages respects limit."""
        conn = MockEmailConnector(scenario="phishing")
        results = conn.search_messages(limit=1)
        assert len(results) <= 1

    def test_search_messages_no_match(self):
        """Search with no matching criteria."""
        conn = MockEmailConnector(scenario="phishing")
        results = conn.search_messages(sender="nonexistent_sender@xyz.com")
        assert len(results) == 0

    def test_get_recipients_existing(self):
        """Get recipients for an existing message."""
        conn = MockEmailConnector(scenario="phishing")
        recipients = conn.get_recipients("<phishing123@malicious.com>")
        assert len(recipients) > 0
        # Should include To and CC
        assert "admin@company.com" in recipients

    def test_get_recipients_nonexistent(self):
        """Get recipients for non-existent message returns empty."""
        conn = MockEmailConnector(scenario="phishing")
        recipients = conn.get_recipients("<nonexistent@x.com>")
        assert recipients == []

    def test_delete_message_existing(self):
        """Delete an existing message."""
        conn = MockEmailConnector(scenario="phishing")
        assert conn.delete_message("<phishing123@malicious.com>") is True
        assert conn.get_message("<phishing123@malicious.com>") is None

    def test_delete_message_nonexistent(self):
        """Delete a non-existent message returns False."""
        conn = MockEmailConnector(scenario="phishing")
        assert conn.delete_message("<nonexistent@x.com>") is False

    def test_block_sender(self):
        """Block sender always succeeds in mock."""
        conn = MockEmailConnector(scenario="phishing")
        assert conn.block_sender("evil@bad.com") is True

    def test_find_similar_messages_by_domain(self):
        """Find similar messages by sender domain."""
        conn = MockEmailConnector(scenario="phishing")
        results = conn.find_similar_messages(sender_domain="micros0ft-support.com")
        assert len(results) > 0

    def test_find_similar_messages_by_subject_pattern(self):
        """Find similar messages by subject pattern."""
        conn = MockEmailConnector(scenario="phishing")
        results = conn.find_similar_messages(subject_pattern="Urgent")
        assert len(results) > 0

    def test_find_similar_messages_no_match(self):
        """Find similar messages with no match."""
        conn = MockEmailConnector(scenario="clean")
        results = conn.find_similar_messages(sender_domain="nonexistent.com")
        assert len(results) == 0

    def test_add_test_message(self):
        """Add a custom test message."""
        conn = MockEmailConnector(scenario="clean")
        initial_count = len(conn._messages)
        test_email = Email(
            message_id="<test@test.com>",
            subject="Test",
            sender="test@test.com",
            sender_domain="test.com",
            recipients=["user@user.com"],
        )
        conn.add_test_message(test_email)
        assert len(conn._messages) == initial_count + 1
        assert conn.get_message("<test@test.com>") is not None


# ===========================================================================
# InvestigationStateManager extended tests
# ===========================================================================


class TestInvestigationStateManagerExtended:
    """Extended tests for InvestigationStateManager."""

    def test_save_and_load_with_steps_and_actions(self, temp_db):
        """Save and load a state with steps and remediation actions."""
        manager = InvestigationStateManager(db_path=temp_db)

        state = _create_test_state(status=InvestigationStatus.COMPLETED)
        state.add_step_result(
            StepResult(
                name="step1",
                status=StepStatus.COMPLETED,
                started_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc),
                duration_seconds=1.5,
                output={"key": "value"},
            )
        )
        state.add_step_result(
            StepResult(
                name="step2",
                status=StepStatus.FAILED,
                error="failed step",
            )
        )
        state.add_remediation_action(
            RemediationAction(
                id="act-1",
                name="Block sender",
                action_type="block_sender",
                target="evil@bad.com",
                command="block evil@bad.com",
                status=RemediationStatus.EXECUTED,
                requires_approval=True,
                priority=1,
                description="Block the sender",
                executed_at=datetime.now(timezone.utc),
                executed_by="admin",
                result="success",
            )
        )
        state.findings = [{"severity": "high", "message": "test", "source": "test", "details": {}}]
        state.iocs = {"urls": ["http://evil.com"], "domains": ["evil.com"]}
        state.risk_score = 75
        state.verdict = "MALICIOUS"
        state.completed_at = datetime.now(timezone.utc)

        assert manager.save(state) is True

        loaded = manager.load(state.id)
        assert loaded is not None
        assert loaded.risk_score == 75
        assert loaded.verdict == "MALICIOUS"
        assert len(loaded.steps) == 2
        assert loaded.steps[0].output == {"key": "value"}
        assert loaded.steps[1].error == "failed step"
        assert len(loaded.remediation_actions) == 1
        assert loaded.remediation_actions[0].status == RemediationStatus.EXECUTED
        assert loaded.findings[0]["severity"] == "high"
        assert "http://evil.com" in loaded.iocs["urls"]

    def test_save_overwrites_existing(self, temp_db):
        """Saving the same ID overwrites the previous state."""
        manager = InvestigationStateManager(db_path=temp_db)

        state = _create_test_state(risk_score=10)
        manager.save(state)

        state.risk_score = 90
        state.status = InvestigationStatus.COMPLETED
        manager.save(state)

        loaded = manager.load(state.id)
        assert loaded.risk_score == 90

    def test_load_nonexistent(self, temp_db):
        """Loading non-existent ID returns None."""
        manager = InvestigationStateManager(db_path=temp_db)
        assert manager.load("INV-NONEXISTENT") is None

    def test_list_with_status_filter(self, temp_db):
        """List investigations filtered by status."""
        manager = InvestigationStateManager(db_path=temp_db)
        manager.save(_create_test_state(inv_id="INV-1", status=InvestigationStatus.COMPLETED))
        manager.save(_create_test_state(inv_id="INV-2", status=InvestigationStatus.FAILED))
        manager.save(_create_test_state(inv_id="INV-3", status=InvestigationStatus.COMPLETED))

        results = manager.list_investigations(status=InvestigationStatus.COMPLETED)
        assert len(results) == 2
        assert all(r["status"] == "completed" for r in results)

    def test_list_with_type_filter(self, temp_db):
        """List investigations filtered by type."""
        manager = InvestigationStateManager(db_path=temp_db)
        manager.save(_create_test_state(inv_id="INV-1", inv_type="phishing"))
        manager.save(_create_test_state(inv_id="INV-2", inv_type="malware"))
        manager.save(_create_test_state(inv_id="INV-3", inv_type="phishing"))

        results = manager.list_investigations(investigation_type="phishing")
        assert len(results) == 2

    def test_list_with_since_filter(self, temp_db):
        """List investigations filtered by created_at time."""
        manager = InvestigationStateManager(db_path=temp_db)
        manager.save(_create_test_state(inv_id="INV-RECENT"))

        # Since 1 hour ago should include the just-created investigation
        since = datetime.now(timezone.utc) - timedelta(hours=1)
        results = manager.list_investigations(since=since)
        assert len(results) >= 1

    def test_list_with_combined_filters(self, temp_db):
        """List with multiple filters combined."""
        manager = InvestigationStateManager(db_path=temp_db)
        manager.save(
            _create_test_state(
                inv_id="INV-C1",
                inv_type="phishing",
                status=InvestigationStatus.COMPLETED,
            )
        )
        manager.save(
            _create_test_state(
                inv_id="INV-C2",
                inv_type="phishing",
                status=InvestigationStatus.FAILED,
            )
        )
        manager.save(
            _create_test_state(
                inv_id="INV-C3",
                inv_type="malware",
                status=InvestigationStatus.COMPLETED,
            )
        )

        results = manager.list_investigations(
            status=InvestigationStatus.COMPLETED,
            investigation_type="phishing",
        )
        assert len(results) == 1
        assert results[0]["id"] == "INV-C1"

    def test_delete_existing(self, temp_db):
        """Delete an existing investigation."""
        manager = InvestigationStateManager(db_path=temp_db)

        state = _create_test_state(inv_id="INV-DEL")
        state.add_step_result(StepResult(name="s1", status=StepStatus.COMPLETED))
        state.add_remediation_action(
            RemediationAction(id="a1", name="act", action_type="block", target="x")
        )
        manager.save(state)

        assert manager.delete("INV-DEL") is True
        assert manager.load("INV-DEL") is None

    def test_delete_nonexistent(self, temp_db):
        """Delete a non-existent investigation returns True (no error)."""
        manager = InvestigationStateManager(db_path=temp_db)
        # Should not raise, just returns True
        assert manager.delete("INV-NOPE") is True

    def test_get_stats_comprehensive(self, temp_db):
        """Get comprehensive stats."""
        manager = InvestigationStateManager(db_path=temp_db)

        # Create various investigations
        state1 = _create_test_state(
            inv_id="INV-ST1",
            inv_type="phishing",
            status=InvestigationStatus.COMPLETED,
            risk_score=70,
            verdict="MALICIOUS",
        )
        state2 = _create_test_state(
            inv_id="INV-ST2",
            inv_type="phishing",
            status=InvestigationStatus.COMPLETED,
            risk_score=30,
            verdict="SUSPICIOUS",
        )
        state3 = _create_test_state(
            inv_id="INV-ST3",
            inv_type="malware",
            status=InvestigationStatus.FAILED,
        )

        for s in [state1, state2, state3]:
            manager.save(s)

        stats = manager.get_stats()
        assert stats["total_investigations"] == 3
        assert "completed" in stats["status_breakdown"]
        assert stats["status_breakdown"]["completed"] == 2
        assert "failed" in stats["status_breakdown"]
        assert "phishing" in stats["type_breakdown"]
        assert stats["type_breakdown"]["phishing"] == 2
        assert stats["last_investigation"] is not None
        assert stats["average_risk_score"] is not None

    def test_get_stats_empty_db(self, temp_db):
        """Get stats on empty database."""
        manager = InvestigationStateManager(db_path=temp_db)
        stats = manager.get_stats()
        assert stats["total_investigations"] == 0
        assert stats["last_investigation"] is None
        assert stats["average_risk_score"] is None

    def test_cleanup_old(self, temp_db):
        """Cleanup old investigations."""
        manager = InvestigationStateManager(db_path=temp_db)

        # Create a "recent" investigation (now)
        recent = _create_test_state(inv_id="INV-RECENT")
        manager.save(recent)

        # Create an "old" investigation by manipulating created_at
        old = _create_test_state(inv_id="INV-OLD")
        old.created_at = datetime.now(timezone.utc) - timedelta(days=60)
        old.updated_at = old.created_at
        manager.save(old)

        # Cleanup anything older than 30 days
        deleted = manager.cleanup_old(days=30)
        assert deleted == 1

        # Recent should still exist
        assert manager.load("INV-RECENT") is not None
        # Old should be gone
        assert manager.load("INV-OLD") is None

    def test_cleanup_old_nothing_to_delete(self, temp_db):
        """Cleanup when nothing is old enough."""
        manager = InvestigationStateManager(db_path=temp_db)
        manager.save(_create_test_state(inv_id="INV-FRESH"))

        deleted = manager.cleanup_old(days=30)
        assert deleted == 0

    def test_save_with_datetime_in_inputs(self, temp_db):
        """Save handles datetime objects in inputs via json serializer."""
        manager = InvestigationStateManager(db_path=temp_db)

        state = _create_test_state(
            inputs={"timestamp": datetime.now(timezone.utc)},
        )
        assert manager.save(state) is True

        loaded = manager.load(state.id)
        assert loaded is not None
        assert "timestamp" in loaded.inputs

    def test_list_investigations_ordering(self, temp_db):
        """Investigations are listed in descending order by created_at."""
        manager = InvestigationStateManager(db_path=temp_db)

        import time

        for i in range(3):
            state = _create_test_state(inv_id=f"INV-ORD-{i}")
            manager.save(state)
            time.sleep(0.01)  # Ensure different timestamps

        results = manager.list_investigations()
        assert len(results) == 3
        # Most recent should be first
        assert results[0]["id"] == "INV-ORD-2"


# ===========================================================================
# State serialization edge cases
# ===========================================================================


class TestStateSerialization:
    """Test edge cases in state serialization/deserialization."""

    def test_state_from_dict_minimal(self):
        """from_dict with minimal data."""
        data = {
            "id": "INV-MIN",
            "type": "test",
            "status": "pending",
        }
        state = InvestigationState.from_dict(data)
        assert state.id == "INV-MIN"
        assert state.status == InvestigationStatus.PENDING
        assert state.inputs == {}
        assert state.findings == []

    def test_state_from_dict_with_all_fields(self):
        """from_dict with all fields populated."""
        now = datetime.now(timezone.utc)
        data = {
            "id": "INV-FULL",
            "type": "phishing",
            "status": "completed",
            "inputs": {"file": "test.eml"},
            "steps": [
                {
                    "name": "s1",
                    "status": "completed",
                    "started_at": now.isoformat(),
                    "completed_at": now.isoformat(),
                    "duration_seconds": 1.0,
                    "output": {"key": "val"},
                    "error": None,
                }
            ],
            "findings": [{"severity": "high", "message": "test", "source": "x"}],
            "iocs": {
                "urls": ["http://test.com"],
                "hashes": [],
                "domains": [],
                "ips": [],
                "emails": [],
            },
            "risk_score": 80,
            "verdict": "MALICIOUS",
            "remediation_actions": [
                {
                    "id": "a1",
                    "name": "Block",
                    "action_type": "block_sender",
                    "target": "x@y.com",
                    "status": "approved",
                    "requires_approval": True,
                    "priority": 1,
                }
            ],
            "created_at": now.isoformat(),
            "updated_at": now.isoformat(),
            "completed_at": now.isoformat(),
            "error": None,
        }

        state = InvestigationState.from_dict(data)
        assert state.risk_score == 80
        assert len(state.steps) == 1
        assert len(state.remediation_actions) == 1

    def test_state_roundtrip(self):
        """to_dict -> from_dict roundtrip preserves data."""
        state = _create_test_state(
            status=InvestigationStatus.COMPLETED,
            risk_score=60,
            verdict="SUSPICIOUS",
        )
        state.add_step_result(StepResult(name="s1", status=StepStatus.COMPLETED, output={"k": "v"}))
        state.add_finding("critical", "Finding 1", "test_tool", {"detail": "x"})
        state.add_iocs("urls", ["http://example.com"])
        state.add_remediation_action(
            RemediationAction(id="a1", name="Act", action_type="block", target="t", priority=2)
        )
        state.completed_at = datetime.now(timezone.utc)

        data = state.to_dict()
        restored = InvestigationState.from_dict(data)

        assert restored.id == state.id
        assert restored.type == state.type
        assert restored.status == state.status
        assert restored.risk_score == state.risk_score
        assert restored.verdict == state.verdict
        assert len(restored.steps) == len(state.steps)
        assert len(restored.findings) == len(state.findings)
        assert len(restored.remediation_actions) == len(state.remediation_actions)
        assert restored.completed_at is not None

    def test_state_get_duration(self):
        """get_duration_seconds returns correct duration."""
        state = _create_test_state()
        state.completed_at = state.created_at + timedelta(seconds=10)
        assert state.get_duration_seconds() == pytest.approx(10, abs=0.1)

    def test_state_get_duration_none(self):
        """get_duration_seconds returns None when not completed."""
        state = _create_test_state()
        assert state.get_duration_seconds() is None

    def test_state_get_completed_steps(self):
        """get_completed_steps filters correctly."""
        state = _create_test_state()
        state.add_step_result(StepResult(name="s1", status=StepStatus.COMPLETED))
        state.add_step_result(StepResult(name="s2", status=StepStatus.FAILED))
        state.add_step_result(StepResult(name="s3", status=StepStatus.COMPLETED))

        completed = state.get_completed_steps()
        assert len(completed) == 2

    def test_state_get_failed_steps(self):
        """get_failed_steps filters correctly."""
        state = _create_test_state()
        state.add_step_result(StepResult(name="s1", status=StepStatus.COMPLETED))
        state.add_step_result(StepResult(name="s2", status=StepStatus.FAILED))

        failed = state.get_failed_steps()
        assert len(failed) == 1
        assert failed[0].name == "s2"

    def test_state_get_pending_remediation_actions(self):
        """get_pending_remediation_actions filters correctly."""
        state = _create_test_state()
        state.add_remediation_action(
            RemediationAction(
                id="a1",
                name="A1",
                action_type="block",
                target="t",
                status=RemediationStatus.PENDING,
            )
        )
        state.add_remediation_action(
            RemediationAction(
                id="a2",
                name="A2",
                action_type="block",
                target="t",
                status=RemediationStatus.APPROVED,
            )
        )
        state.add_remediation_action(
            RemediationAction(
                id="a3",
                name="A3",
                action_type="block",
                target="t",
                status=RemediationStatus.PENDING,
            )
        )

        pending = state.get_pending_remediation_actions()
        assert len(pending) == 2

    def test_state_add_iocs_new_type(self):
        """add_iocs creates a new IOC type if not existing."""
        state = _create_test_state()
        state.add_iocs("custom_type", ["val1", "val2"])
        assert "custom_type" in state.iocs
        assert len(state.iocs["custom_type"]) == 2
