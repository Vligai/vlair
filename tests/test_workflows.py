#!/usr/bin/env python3
"""
Unit tests for Workflow Engine and Individual Workflows
Tests workflow execution, step chaining, and result aggregation
"""

import pytest
import sys
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from secops_helper.core.workflow import (
    Workflow,
    WorkflowStep,
    StepResult,
    WorkflowContext,
    WorkflowRegistry,
    workflow,
)
from secops_helper.core.scorer import Severity


class TestWorkflowStep:
    """Test WorkflowStep dataclass"""

    def test_step_creation(self):
        """Test creating a workflow step"""
        step = WorkflowStep(name="test_step", description="Test step description", tool="test_tool")
        assert step.name == "test_step"
        assert step.description == "Test step description"
        assert step.tool == "test_tool"
        assert step.required is True
        assert step.depends_on == []

    def test_step_with_dependencies(self):
        """Test step with dependencies"""
        step = WorkflowStep(
            name="dependent_step",
            description="Depends on others",
            tool="tool",
            depends_on=["step1", "step2"],
        )
        assert step.depends_on == ["step1", "step2"]

    def test_optional_step(self):
        """Test optional step"""
        step = WorkflowStep(
            name="optional", description="Optional step", tool="tool", required=False
        )
        assert step.required is False


class TestStepResult:
    """Test StepResult dataclass"""

    def test_successful_result(self):
        """Test successful step result"""
        result = StepResult(step_name="test", success=True, data={"key": "value"})
        assert result.success is True
        assert result.data == {"key": "value"}
        assert result.error is None

    def test_failed_result(self):
        """Test failed step result"""
        result = StepResult(step_name="test", success=False, error="Something went wrong")
        assert result.success is False
        assert result.error == "Something went wrong"


class TestWorkflowContext:
    """Test WorkflowContext"""

    def test_context_creation(self):
        """Test creating a workflow context"""
        context = WorkflowContext("test_input", "email")
        assert context.input_value == "test_input"
        assert context.input_type == "email"
        assert context.iocs == {"hashes": [], "domains": [], "ips": [], "urls": [], "emails": []}

    def test_add_iocs(self):
        """Test adding IOCs to context"""
        context = WorkflowContext("test", "file")
        context.add_iocs("hashes", ["abc123", "def456"])
        context.add_iocs("hashes", ["abc123", "ghi789"])  # Duplicate should be ignored

        assert len(context.iocs["hashes"]) == 3
        assert "abc123" in context.iocs["hashes"]

    def test_add_tool_result(self):
        """Test adding tool results"""
        context = WorkflowContext("test", "file")
        context.add_tool_result("hash_lookup", {"verdict": "clean"})

        assert "hash_lookup" in context.tool_results
        assert context.tool_results["hash_lookup"]["verdict"] == "clean"

    def test_add_step_result(self):
        """Test adding step results"""
        context = WorkflowContext("test", "file")
        result = StepResult(step_name="step1", success=True)
        context.add_step_result(result)

        assert len(context.step_results) == 1
        assert context.step_results[0].step_name == "step1"

    def test_elapsed_time(self):
        """Test elapsed time calculation"""
        context = WorkflowContext("test", "file")
        import time

        time.sleep(0.1)
        elapsed = context.get_elapsed_time()
        assert elapsed >= 0.1


class TestWorkflowRegistry:
    """Test WorkflowRegistry"""

    def test_register_workflow(self):
        """Test registering a workflow"""

        # Create a test workflow
        class TestWorkflow(Workflow):
            @property
            def name(self):
                return "test-workflow"

            @property
            def description(self):
                return "Test workflow"

            def _define_steps(self):
                self.steps = []

            def _execute_step(self, step, context):
                return StepResult(step_name=step.name, success=True)

        WorkflowRegistry.register(TestWorkflow)
        assert WorkflowRegistry.get("test-workflow") == TestWorkflow

    def test_get_nonexistent_workflow(self):
        """Test getting a workflow that doesn't exist"""
        result = WorkflowRegistry.get("nonexistent-workflow")
        assert result is None

    def test_list_workflows(self):
        """Test listing all workflows"""
        workflows = WorkflowRegistry.list_all()
        assert isinstance(workflows, list)


class TestPhishingEmailWorkflow:
    """Test Phishing Email Workflow"""

    def test_workflow_properties(self):
        """Test workflow name and description"""
        from secops_helper.workflows.phishing_email import PhishingEmailWorkflow

        wf = PhishingEmailWorkflow(verbose=False)
        assert wf.name == "phishing-email"
        assert "phishing" in wf.description.lower()

    def test_workflow_has_steps(self):
        """Test that workflow has defined steps"""
        from secops_helper.workflows.phishing_email import PhishingEmailWorkflow

        wf = PhishingEmailWorkflow(verbose=False)
        assert len(wf.steps) > 0

    def test_workflow_step_names(self):
        """Test expected step names exist"""
        from secops_helper.workflows.phishing_email import PhishingEmailWorkflow

        wf = PhishingEmailWorkflow(verbose=False)
        step_names = [s.name for s in wf.steps]

        assert "parse_email" in step_names
        assert "extract_iocs" in step_names
        assert "calculate_score" in step_names

    def test_workflow_with_email_file(self):
        """Test workflow execution with email file"""
        from secops_helper.workflows.phishing_email import PhishingEmailWorkflow

        # Create a test email file
        with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as f:
            f.write(b"From: attacker@evil.com\n")
            f.write(b"To: victim@company.com\n")
            f.write(b"Subject: Urgent!\n\n")
            f.write(b"Click here: http://malicious.com/payload\n")
            temp_path = f.name

        try:
            wf = PhishingEmailWorkflow(verbose=False)
            result = wf.execute(temp_path, "email")

            assert "workflow" in result
            assert result["workflow"] == "phishing-email"
            assert "scorer" in result
            assert "iocs" in result
        finally:
            os.unlink(temp_path)


class TestMalwareTriageWorkflow:
    """Test Malware Triage Workflow"""

    def test_workflow_properties(self):
        """Test workflow name and description"""
        from secops_helper.workflows.malware_triage import MalwareTriageWorkflow

        wf = MalwareTriageWorkflow(verbose=False)
        assert wf.name == "malware-triage"
        assert "malware" in wf.description.lower()

    def test_workflow_has_steps(self):
        """Test that workflow has defined steps"""
        from secops_helper.workflows.malware_triage import MalwareTriageWorkflow

        wf = MalwareTriageWorkflow(verbose=False)
        assert len(wf.steps) > 0

    def test_workflow_step_names(self):
        """Test expected step names exist"""
        from secops_helper.workflows.malware_triage import MalwareTriageWorkflow

        wf = MalwareTriageWorkflow(verbose=False)
        step_names = [s.name for s in wf.steps]

        assert "calculate_hashes" in step_names
        assert "check_hashes" in step_names
        assert "calculate_score" in step_names

    def test_workflow_with_file(self):
        """Test workflow execution with a file"""
        from secops_helper.workflows.malware_triage import MalwareTriageWorkflow

        # Create a test file
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"MZ\x90\x00\x03\x00\x00\x00")  # Fake PE header
            temp_path = f.name

        try:
            wf = MalwareTriageWorkflow(verbose=False)
            result = wf.execute(temp_path, "file")

            assert result["workflow"] == "malware-triage"
            # Should have calculated hashes
            assert len(result["iocs"]["hashes"]) > 0
        finally:
            os.unlink(temp_path)


class TestIOCHuntWorkflow:
    """Test IOC Hunt Workflow"""

    def test_workflow_properties(self):
        """Test workflow name and description"""
        from secops_helper.workflows.ioc_hunt import IOCHuntWorkflow

        wf = IOCHuntWorkflow(verbose=False)
        assert wf.name == "ioc-hunt"

    def test_workflow_with_ioc_file(self):
        """Test workflow execution with IOC list"""
        from secops_helper.workflows.ioc_hunt import IOCHuntWorkflow

        # Create a test IOC file
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as f:
            f.write("44d88612fea8a8f36de82e1278abb02f\n")
            f.write("malicious.com\n")
            f.write("192.168.1.100\n")
            temp_path = f.name

        try:
            wf = IOCHuntWorkflow(verbose=False)
            result = wf.execute(temp_path, "ioc_list")

            assert result["workflow"] == "ioc-hunt"
            # Should have extracted IOCs
            total_iocs = sum(len(v) for v in result["iocs"].values())
            assert total_iocs > 0
        finally:
            os.unlink(temp_path)


class TestNetworkForensicsWorkflow:
    """Test Network Forensics Workflow"""

    def test_workflow_properties(self):
        """Test workflow name and description"""
        from secops_helper.workflows.network_forensics import NetworkForensicsWorkflow

        wf = NetworkForensicsWorkflow(verbose=False)
        assert wf.name == "network-forensics"

    def test_workflow_has_steps(self):
        """Test that workflow has defined steps"""
        from secops_helper.workflows.network_forensics import NetworkForensicsWorkflow

        wf = NetworkForensicsWorkflow(verbose=False)
        step_names = [s.name for s in wf.steps]

        assert "parse_pcap" in step_names
        assert "detect_scans" in step_names
        assert "analyze_dns" in step_names


class TestLogInvestigationWorkflow:
    """Test Log Investigation Workflow"""

    def test_workflow_properties(self):
        """Test workflow name and description"""
        from secops_helper.workflows.log_investigation import LogInvestigationWorkflow

        wf = LogInvestigationWorkflow(verbose=False)
        assert wf.name == "log-investigation"

    def test_workflow_has_steps(self):
        """Test that workflow has defined steps"""
        from secops_helper.workflows.log_investigation import LogInvestigationWorkflow

        wf = LogInvestigationWorkflow(verbose=False)
        step_names = [s.name for s in wf.steps]

        assert "parse_logs" in step_names
        assert "detect_attacks" in step_names
        assert "detect_bruteforce" in step_names

    def test_workflow_with_log_file(self):
        """Test workflow execution with log file"""
        from secops_helper.workflows.log_investigation import LogInvestigationWorkflow

        # Create a test log file
        with tempfile.NamedTemporaryFile(suffix=".log", delete=False, mode="w") as f:
            f.write(
                '192.168.1.100 - - [01/Jan/2025:00:00:00 +0000] "GET /admin HTTP/1.1" 200 1234\n'
            )
            f.write(
                '192.168.1.100 - - [01/Jan/2025:00:00:01 +0000] "GET /login HTTP/1.1" 200 1234\n'
            )
            temp_path = f.name

        try:
            wf = LogInvestigationWorkflow(verbose=False)
            result = wf.execute(temp_path, "log")

            assert result["workflow"] == "log-investigation"
        finally:
            os.unlink(temp_path)


class TestWorkflowResultStructure:
    """Test that workflow results have correct structure"""

    def test_result_has_required_fields(self):
        """Test result structure"""
        from secops_helper.workflows.malware_triage import MalwareTriageWorkflow

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"test content")
            temp_path = f.name

        try:
            wf = MalwareTriageWorkflow(verbose=False)
            result = wf.execute(temp_path, "file")

            assert "workflow" in result
            assert "input" in result
            assert "type" in result
            assert "duration_seconds" in result
            assert "steps_completed" in result
            assert "steps_total" in result
            assert "iocs" in result
            assert "tool_results" in result
            assert "scorer" in result
            assert "step_results" in result
        finally:
            os.unlink(temp_path)

    def test_step_results_structure(self):
        """Test step results structure"""
        from secops_helper.workflows.malware_triage import MalwareTriageWorkflow

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"test content")
            temp_path = f.name

        try:
            wf = MalwareTriageWorkflow(verbose=False)
            result = wf.execute(temp_path, "file")

            for step_result in result["step_results"]:
                assert "name" in step_result
                assert "success" in step_result
                assert "duration_ms" in step_result
        finally:
            os.unlink(temp_path)


class TestWorkflowDependencies:
    """Test workflow step dependencies"""

    def test_steps_with_dependencies_wait(self):
        """Test that dependent steps wait for prerequisites"""
        from secops_helper.workflows.phishing_email import PhishingEmailWorkflow

        wf = PhishingEmailWorkflow(verbose=False)

        # Find a step with dependencies
        dependent_step = None
        for step in wf.steps:
            if step.depends_on:
                dependent_step = step
                break

        assert dependent_step is not None
        # The dependent step should have at least one prerequisite
        assert len(dependent_step.depends_on) > 0


class TestWorkflowVerboseMode:
    """Test verbose mode in workflows"""

    def test_verbose_execution(self):
        """Test workflow in verbose mode"""
        from secops_helper.workflows.malware_triage import MalwareTriageWorkflow

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"test")
            temp_path = f.name

        try:
            wf = MalwareTriageWorkflow(verbose=True)
            result = wf.execute(temp_path, "file")
            # Should complete without errors
            assert result is not None
        finally:
            os.unlink(temp_path)


class TestWorkflowErrorHandling:
    """Test workflow error handling"""

    def test_nonexistent_file(self):
        """Test workflow with nonexistent file"""
        from secops_helper.workflows.malware_triage import MalwareTriageWorkflow

        wf = MalwareTriageWorkflow(verbose=False)
        result = wf.execute("/nonexistent/path/file.exe", "file")

        # Should handle gracefully - some steps may fail
        assert result is not None
        # First step should have failed
        first_step = result["step_results"][0]
        assert first_step["success"] is False
