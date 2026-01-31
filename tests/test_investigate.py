#!/usr/bin/env python3
"""
Unit tests for Investigation Automation module

Tests:
- InvestigationState serialization
- SQLite state persistence
- Phishing playbook with mock connectors
- CLI commands
"""

import pytest
import sys
import os
import json
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

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
from vlair.investigate.connectors.mock import MockEmailConnector, MockSIEMConnector


class TestInvestigationModels:
    """Test investigation model classes"""

    def test_investigation_status_enum(self):
        """Test InvestigationStatus enum values"""
        assert InvestigationStatus.PENDING.value == "pending"
        assert InvestigationStatus.RUNNING.value == "running"
        assert InvestigationStatus.COMPLETED.value == "completed"
        assert InvestigationStatus.FAILED.value == "failed"

    def test_step_status_enum(self):
        """Test StepStatus enum values"""
        assert StepStatus.PENDING.value == "pending"
        assert StepStatus.RUNNING.value == "running"
        assert StepStatus.COMPLETED.value == "completed"
        assert StepStatus.FAILED.value == "failed"
        assert StepStatus.SKIPPED.value == "skipped"

    def test_remediation_status_enum(self):
        """Test RemediationStatus enum values"""
        assert RemediationStatus.PENDING.value == "pending"
        assert RemediationStatus.APPROVED.value == "approved"
        assert RemediationStatus.EXECUTED.value == "executed"
        assert RemediationStatus.FAILED.value == "failed"


class TestStepResult:
    """Test StepResult dataclass"""

    def test_step_result_creation(self):
        """Test creating a step result"""
        result = StepResult(
            name="test_step",
            status=StepStatus.COMPLETED,
            output={"key": "value"},
        )
        assert result.name == "test_step"
        assert result.status == StepStatus.COMPLETED
        assert result.output == {"key": "value"}
        assert result.error is None

    def test_step_result_with_error(self):
        """Test step result with error"""
        result = StepResult(
            name="failed_step",
            status=StepStatus.FAILED,
            error="Something went wrong",
        )
        assert result.status == StepStatus.FAILED
        assert result.error == "Something went wrong"

    def test_step_result_serialization(self):
        """Test step result to_dict and from_dict"""
        now = datetime.now(timezone.utc)
        result = StepResult(
            name="test_step",
            status=StepStatus.COMPLETED,
            started_at=now,
            completed_at=now,
            duration_seconds=1.5,
            output={"data": "test"},
        )

        data = result.to_dict()
        assert data["name"] == "test_step"
        assert data["status"] == "completed"

        restored = StepResult.from_dict(data)
        assert restored.name == result.name
        assert restored.status == result.status


class TestRemediationAction:
    """Test RemediationAction dataclass"""

    def test_action_creation(self):
        """Test creating a remediation action"""
        action = RemediationAction(
            id="act-001",
            name="Block Sender",
            action_type="block_sender",
            target="malicious@example.com",
            requires_approval=True,
        )
        assert action.id == "act-001"
        assert action.action_type == "block_sender"
        assert action.status == RemediationStatus.PENDING
        assert action.requires_approval is True

    def test_action_serialization(self):
        """Test action to_dict and from_dict"""
        action = RemediationAction(
            id="act-001",
            name="Block Sender",
            action_type="block_sender",
            target="malicious@example.com",
            priority=1,
        )

        data = action.to_dict()
        assert data["id"] == "act-001"
        assert data["action_type"] == "block_sender"

        restored = RemediationAction.from_dict(data)
        assert restored.id == action.id
        assert restored.action_type == action.action_type


class TestInvestigationState:
    """Test InvestigationState dataclass"""

    def test_state_creation(self):
        """Test creating investigation state"""
        state = InvestigationState(
            id="INV-2026-01-31-TEST1234",
            type="phishing",
            status=InvestigationStatus.PENDING,
            inputs={"file_path": "/path/to/email.eml"},
        )
        assert state.id == "INV-2026-01-31-TEST1234"
        assert state.type == "phishing"
        assert state.status == InvestigationStatus.PENDING
        assert state.risk_score == 0
        assert state.verdict == "UNKNOWN"

    def test_generate_id(self):
        """Test ID generation"""
        id1 = InvestigationState.generate_id()
        id2 = InvestigationState.generate_id()

        assert id1.startswith("INV-")
        assert id1 != id2  # IDs should be unique

    def test_add_step_result(self):
        """Test adding step results"""
        state = InvestigationState(
            id="INV-TEST",
            type="phishing",
            status=InvestigationStatus.RUNNING,
        )

        result = StepResult(name="step1", status=StepStatus.COMPLETED)
        state.add_step_result(result)

        assert len(state.steps) == 1
        assert state.steps[0].name == "step1"

    def test_add_finding(self):
        """Test adding findings"""
        state = InvestigationState(
            id="INV-TEST",
            type="phishing",
            status=InvestigationStatus.RUNNING,
        )

        state.add_finding("high", "Malicious URL detected", "url_analyzer")

        assert len(state.findings) == 1
        assert state.findings[0]["severity"] == "high"
        assert state.findings[0]["source"] == "url_analyzer"

    def test_add_iocs(self):
        """Test adding IOCs"""
        state = InvestigationState(
            id="INV-TEST",
            type="phishing",
            status=InvestigationStatus.RUNNING,
        )

        state.add_iocs("urls", ["http://malicious.com"])
        state.add_iocs("urls", ["http://malicious.com", "http://evil.com"])

        # Should deduplicate
        assert len(state.iocs["urls"]) == 2

    def test_mark_completed(self):
        """Test marking investigation as completed"""
        state = InvestigationState(
            id="INV-TEST",
            type="phishing",
            status=InvestigationStatus.RUNNING,
        )

        state.mark_completed(risk_score=75, verdict="MALICIOUS")

        assert state.status == InvestigationStatus.COMPLETED
        assert state.risk_score == 75
        assert state.verdict == "MALICIOUS"
        assert state.completed_at is not None

    def test_mark_failed(self):
        """Test marking investigation as failed"""
        state = InvestigationState(
            id="INV-TEST",
            type="phishing",
            status=InvestigationStatus.RUNNING,
        )

        state.mark_failed("Step failed: parse_email")

        assert state.status == InvestigationStatus.FAILED
        assert state.error == "Step failed: parse_email"

    def test_state_serialization(self):
        """Test state to_dict and from_dict"""
        state = InvestigationState(
            id="INV-TEST",
            type="phishing",
            status=InvestigationStatus.COMPLETED,
            inputs={"file_path": "/test.eml"},
            risk_score=65,
            verdict="SUSPICIOUS",
        )

        # Add some data
        state.add_step_result(StepResult(name="step1", status=StepStatus.COMPLETED))
        state.add_finding("high", "Test finding", "test")
        state.add_iocs("urls", ["http://test.com"])

        data = state.to_dict()
        restored = InvestigationState.from_dict(data)

        assert restored.id == state.id
        assert restored.type == state.type
        assert restored.status == state.status
        assert restored.risk_score == state.risk_score
        assert restored.verdict == state.verdict
        assert len(restored.steps) == 1
        assert len(restored.findings) == 1


class TestInvestigationStateManager:
    """Test SQLite state persistence"""

    @pytest.fixture
    def temp_db(self):
        """Create a temporary database file"""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        yield db_path
        # Cleanup
        try:
            os.unlink(db_path)
        except Exception:
            pass

    def test_manager_creation(self, temp_db):
        """Test creating state manager"""
        manager = InvestigationStateManager(db_path=temp_db)
        assert manager.db_path == temp_db

    def test_save_and_load(self, temp_db):
        """Test saving and loading state"""
        manager = InvestigationStateManager(db_path=temp_db)

        state = InvestigationState(
            id="INV-TEST-001",
            type="phishing",
            status=InvestigationStatus.COMPLETED,
            inputs={"file": "test.eml"},
            risk_score=50,
            verdict="SUSPICIOUS",
        )
        state.add_step_result(StepResult(name="step1", status=StepStatus.COMPLETED))
        state.add_finding("medium", "Test finding", "test")
        state.add_iocs("urls", ["http://test.com"])

        # Save
        assert manager.save(state) is True

        # Load
        loaded = manager.load("INV-TEST-001")
        assert loaded is not None
        assert loaded.id == "INV-TEST-001"
        assert loaded.type == "phishing"
        assert loaded.risk_score == 50
        assert len(loaded.steps) == 1
        assert len(loaded.findings) == 1

    def test_list_investigations(self, temp_db):
        """Test listing investigations"""
        manager = InvestigationStateManager(db_path=temp_db)

        # Create multiple investigations
        for i in range(3):
            state = InvestigationState(
                id=f"INV-TEST-{i:03d}",
                type="phishing",
                status=InvestigationStatus.COMPLETED,
                risk_score=i * 30,
            )
            manager.save(state)

        # List
        investigations = manager.list_investigations(limit=10)
        assert len(investigations) == 3

    def test_delete_investigation(self, temp_db):
        """Test deleting investigation"""
        manager = InvestigationStateManager(db_path=temp_db)

        state = InvestigationState(
            id="INV-DELETE-001",
            type="phishing",
            status=InvestigationStatus.COMPLETED,
        )
        manager.save(state)

        # Verify exists
        assert manager.load("INV-DELETE-001") is not None

        # Delete
        assert manager.delete("INV-DELETE-001") is True

        # Verify deleted
        assert manager.load("INV-DELETE-001") is None

    def test_get_stats(self, temp_db):
        """Test getting statistics"""
        manager = InvestigationStateManager(db_path=temp_db)

        # Create investigations with different statuses
        for i, status in enumerate([
            InvestigationStatus.COMPLETED,
            InvestigationStatus.COMPLETED,
            InvestigationStatus.FAILED,
        ]):
            state = InvestigationState(
                id=f"INV-STATS-{i:03d}",
                type="phishing",
                status=status,
                risk_score=50 if status == InvestigationStatus.COMPLETED else 0,
                verdict="SUSPICIOUS" if status == InvestigationStatus.COMPLETED else "UNKNOWN",
            )
            manager.save(state)

        stats = manager.get_stats()
        assert stats["total_investigations"] == 3
        assert "completed" in stats["status_breakdown"]


class TestMockConnectors:
    """Test mock connectors"""

    def test_mock_email_connector_phishing(self):
        """Test mock email connector with phishing scenario"""
        connector = MockEmailConnector(scenario="phishing")

        # Get message
        email = connector.get_message("<phishing123@malicious.com>")
        assert email is not None
        assert "micros0ft" in email.sender_domain.lower()
        assert email.spf_result == "fail"

    def test_mock_email_connector_search(self):
        """Test searching emails"""
        connector = MockEmailConnector(scenario="phishing")

        emails = connector.search_messages(sender="micros0ft")
        assert len(emails) > 0

    def test_mock_email_connector_recipients(self):
        """Test getting recipients"""
        connector = MockEmailConnector(scenario="phishing")

        recipients = connector.get_recipients("<phishing123@malicious.com>")
        assert len(recipients) > 0

    def test_mock_siem_connector_phishing(self):
        """Test mock SIEM connector with phishing scenario"""
        connector = MockSIEMConnector(scenario="phishing")

        clicks = connector.get_url_clicks(url="micros0ft")
        assert len(clicks) > 0

    def test_mock_siem_connector_search(self):
        """Test SIEM search"""
        connector = MockSIEMConnector(scenario="phishing")

        events = connector.search("phishing")
        assert len(events) > 0

    def test_mock_siem_connector_events_by_user(self):
        """Test getting events by user"""
        connector = MockSIEMConnector(scenario="phishing")

        events = connector.get_events_by_user("user1@company.com")
        assert len(events) > 0


class TestPlaybookBase:
    """Test playbook base class"""

    def test_playbook_step_creation(self):
        """Test creating a playbook step"""
        step = PlaybookStep(
            name="test_step",
            description="Test step description",
            required=True,
            depends_on=["other_step"],
        )
        assert step.name == "test_step"
        assert step.required is True
        assert "other_step" in step.depends_on

    def test_playbook_step_defaults(self):
        """Test playbook step defaults"""
        step = PlaybookStep(
            name="test_step",
            description="Test step",
        )
        assert step.required is True
        assert step.depends_on == []
        assert step.timeout_seconds == 300


class TestPhishingPlaybook:
    """Test phishing investigation playbook"""

    def test_playbook_properties(self):
        """Test playbook name and description"""
        playbook = PhishingPlaybook(verbose=False)
        assert playbook.name == "phishing"
        assert "phishing" in playbook.description.lower()

    def test_playbook_has_steps(self):
        """Test that playbook has defined steps"""
        playbook = PhishingPlaybook(verbose=False)
        assert len(playbook.steps) == 10  # 10-step playbook

    def test_playbook_step_names(self):
        """Test expected step names exist"""
        playbook = PhishingPlaybook(verbose=False)
        step_names = [s.name for s in playbook.steps]

        assert "parse_email" in step_names
        assert "validate_authentication" in step_names
        assert "extract_iocs" in step_names
        assert "check_sender_domain" in step_names
        assert "analyze_urls" in step_names
        assert "calculate_verdict" in step_names
        assert "prepare_remediation" in step_names

    def test_playbook_validation(self):
        """Test playbook validation"""
        playbook = PhishingPlaybook(verbose=False)
        errors = playbook.validate()
        assert len(errors) == 0  # No validation errors

    def test_playbook_with_email_file(self):
        """Test playbook execution with email file"""
        # Create a test email file
        with tempfile.NamedTemporaryFile(suffix=".eml", delete=False, mode="w") as f:
            f.write("From: attacker@evil.com\n")
            f.write("To: victim@company.com\n")
            f.write("Subject: Urgent! Click Now!\n")
            f.write("Received-SPF: fail\n")
            f.write("Authentication-Results: spf=fail; dkim=fail; dmarc=fail\n\n")
            f.write("Click here: http://malicious.com/payload\n")
            temp_path = f.name

        try:
            playbook = PhishingPlaybook(verbose=False)
            state = playbook.execute(
                inputs={"file_path": temp_path},
                connectors={},
            )

            assert state.type == "phishing"
            assert state.status in [InvestigationStatus.COMPLETED, InvestigationStatus.FAILED]
            assert len(state.steps) > 0

        finally:
            os.unlink(temp_path)

    def test_playbook_with_mock_connectors(self):
        """Test playbook with mock connectors"""
        # Create a test email file
        with tempfile.NamedTemporaryFile(suffix=".eml", delete=False, mode="w") as f:
            f.write("From: attacker@micros0ft-support.com\n")
            f.write("To: victim@company.com\n")
            f.write("Subject: Account Compromised!\n")
            f.write("Received-SPF: fail\n\n")
            f.write("Click: http://micros0ft-secure-login.com/verify\n")
            temp_path = f.name

        try:
            playbook = PhishingPlaybook(verbose=False)

            # Use mock connectors
            connectors = {
                "email": MockEmailConnector(scenario="phishing"),
                "siem": MockSIEMConnector(scenario="phishing"),
            }

            state = playbook.execute(
                inputs={"file_path": temp_path},
                connectors=connectors,
            )

            assert state.type == "phishing"
            # Should have executed steps (may complete or fail depending on tool availability)
            assert len(state.steps) > 0

        finally:
            os.unlink(temp_path)


class TestInvestigationEngine:
    """Test investigation engine"""

    @pytest.fixture
    def temp_db(self):
        """Create a temporary database file"""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        yield db_path
        try:
            os.unlink(db_path)
        except Exception:
            pass

    def test_engine_creation(self, temp_db):
        """Test creating investigation engine"""
        manager = InvestigationStateManager(db_path=temp_db)
        engine = InvestigationEngine(state_manager=manager, verbose=False)
        assert engine is not None

    def test_get_available_playbooks(self, temp_db):
        """Test listing available playbooks"""
        # Register the phishing playbook
        PlaybookRegistry.register(PhishingPlaybook)

        manager = InvestigationStateManager(db_path=temp_db)
        engine = InvestigationEngine(state_manager=manager, verbose=False)

        playbooks = engine.get_available_playbooks()
        names = [p["name"] for p in playbooks]
        assert "phishing" in names

    def test_start_investigation(self, temp_db):
        """Test starting an investigation"""
        # Register playbook
        PlaybookRegistry.register(PhishingPlaybook)

        # Create test email
        with tempfile.NamedTemporaryFile(suffix=".eml", delete=False, mode="w") as f:
            f.write("From: test@test.com\n")
            f.write("To: victim@company.com\n")
            f.write("Subject: Test\n\n")
            f.write("Test content\n")
            temp_path = f.name

        try:
            manager = InvestigationStateManager(db_path=temp_db)
            engine = InvestigationEngine(state_manager=manager, verbose=False)

            state = engine.start_investigation(
                playbook_name="phishing",
                inputs={"file_path": temp_path},
                auto_run=True,
            )

            assert state is not None
            assert state.id.startswith("INV-")
            assert state.type == "phishing"

        finally:
            os.unlink(temp_path)

    def test_get_investigation(self, temp_db):
        """Test getting an investigation"""
        PlaybookRegistry.register(PhishingPlaybook)

        with tempfile.NamedTemporaryFile(suffix=".eml", delete=False, mode="w") as f:
            f.write("From: test@test.com\nTo: v@c.com\nSubject: Test\n\nTest\n")
            temp_path = f.name

        try:
            manager = InvestigationStateManager(db_path=temp_db)
            engine = InvestigationEngine(state_manager=manager, verbose=False)

            state = engine.start_investigation(
                playbook_name="phishing",
                inputs={"file_path": temp_path},
                auto_run=True,
            )

            # Retrieve it
            retrieved = engine.get_investigation(state.id)
            assert retrieved is not None
            assert retrieved.id == state.id

        finally:
            os.unlink(temp_path)

    def test_list_investigations(self, temp_db):
        """Test listing investigations"""
        PlaybookRegistry.register(PhishingPlaybook)

        with tempfile.NamedTemporaryFile(suffix=".eml", delete=False, mode="w") as f:
            f.write("From: test@test.com\nTo: v@c.com\nSubject: Test\n\nTest\n")
            temp_path = f.name

        try:
            manager = InvestigationStateManager(db_path=temp_db)
            engine = InvestigationEngine(state_manager=manager, verbose=False)

            # Create a few investigations
            for _ in range(3):
                engine.start_investigation(
                    playbook_name="phishing",
                    inputs={"file_path": temp_path},
                    auto_run=True,
                )

            investigations = engine.list_investigations()
            assert len(investigations) == 3

        finally:
            os.unlink(temp_path)


class TestPlaybookRegistry:
    """Test playbook registry"""

    def test_register_playbook(self):
        """Test registering a playbook"""
        PlaybookRegistry.register(PhishingPlaybook)
        assert PlaybookRegistry.get("phishing") == PhishingPlaybook

    def test_get_nonexistent_playbook(self):
        """Test getting a playbook that doesn't exist"""
        result = PlaybookRegistry.get("nonexistent-playbook")
        assert result is None

    def test_list_all_playbooks(self):
        """Test listing all playbooks"""
        PlaybookRegistry.register(PhishingPlaybook)
        playbooks = PlaybookRegistry.list_all()
        assert isinstance(playbooks, list)
        assert len(playbooks) > 0
