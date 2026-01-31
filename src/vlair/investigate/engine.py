#!/usr/bin/env python3
"""
Investigation Engine - Main orchestrator for automated investigations

Coordinates playbook execution, state management, and connector integration.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Type
import sys

from .models import (
    InvestigationState,
    InvestigationStatus,
    RemediationAction,
    RemediationStatus,
)
from .state import InvestigationStateManager
from .registry import PlaybookRegistry


class InvestigationEngine:
    """
    Main orchestrator for automated investigations.

    Manages:
    - Playbook execution
    - State persistence
    - Connector integration
    - Remediation action tracking
    """

    def __init__(
        self,
        state_manager: Optional[InvestigationStateManager] = None,
        connectors: Optional[Dict[str, Any]] = None,
        verbose: bool = False,
    ):
        """
        Initialize the investigation engine.

        Args:
            state_manager: Optional custom state manager
            connectors: Optional dictionary of connectors
            verbose: If True, print detailed progress
        """
        self.state_manager = state_manager or InvestigationStateManager()
        self.connectors = connectors or {}
        self.verbose = verbose

    def start_investigation(
        self,
        playbook_name: str,
        inputs: Dict[str, Any],
        auto_run: bool = True,
    ) -> InvestigationState:
        """
        Start a new investigation using a playbook.

        Args:
            playbook_name: Name of the playbook to use
            inputs: Input parameters for the investigation
            auto_run: If True, immediately run the investigation

        Returns:
            The investigation state

        Raises:
            ValueError: If playbook not found
        """
        # Get playbook
        playbook_class = PlaybookRegistry.get(playbook_name)
        if not playbook_class:
            raise ValueError(f"Unknown playbook: {playbook_name}")

        # Create playbook instance
        playbook = playbook_class(verbose=self.verbose)

        # Create initial state
        state = InvestigationState(
            id=InvestigationState.generate_id(),
            type=playbook.investigation_type,
            status=InvestigationStatus.PENDING,
            inputs=inputs,
        )

        # Save initial state
        self.state_manager.save(state)

        if self.verbose:
            print(f"Investigation created: {state.id}", file=sys.stderr)

        if auto_run:
            state = self.run_investigation(state.id)

        return state

    def run_investigation(self, investigation_id: str) -> InvestigationState:
        """
        Run or continue an investigation.

        Args:
            investigation_id: The investigation ID

        Returns:
            The updated investigation state

        Raises:
            ValueError: If investigation not found
        """
        # Load state
        state = self.state_manager.load(investigation_id)
        if not state:
            raise ValueError(f"Investigation not found: {investigation_id}")

        # Check if already completed
        if state.status in [InvestigationStatus.COMPLETED, InvestigationStatus.FAILED]:
            if self.verbose:
                print(
                    f"Investigation {investigation_id} already {state.status.value}",
                    file=sys.stderr
                )
            return state

        # Get playbook
        playbook_class = PlaybookRegistry.get(f"{state.type}-investigation")
        if not playbook_class:
            # Try without -investigation suffix
            playbook_class = PlaybookRegistry.get(state.type)

        if not playbook_class:
            state.mark_failed(f"Playbook not found for type: {state.type}")
            self.state_manager.save(state)
            return state

        # Create playbook and execute
        playbook = playbook_class(verbose=self.verbose)

        # Mark as running
        state.status = InvestigationStatus.RUNNING
        self.state_manager.save(state)

        # Execute playbook
        try:
            state = playbook.execute(
                inputs=state.inputs,
                connectors=self.connectors,
                state=state,
            )
        except Exception as e:
            state.mark_failed(str(e))

        # Save final state
        self.state_manager.save(state)

        return state

    def resume_investigation(self, investigation_id: str) -> InvestigationState:
        """
        Resume a paused or failed investigation.

        Args:
            investigation_id: The investigation ID

        Returns:
            The updated investigation state
        """
        state = self.state_manager.load(investigation_id)
        if not state:
            raise ValueError(f"Investigation not found: {investigation_id}")

        # Reset status to allow re-running
        if state.status == InvestigationStatus.FAILED:
            state.status = InvestigationStatus.RUNNING
            state.error = None
            self.state_manager.save(state)

        return self.run_investigation(investigation_id)

    def get_investigation(self, investigation_id: str) -> Optional[InvestigationState]:
        """
        Get an investigation by ID.

        Args:
            investigation_id: The investigation ID

        Returns:
            The investigation state if found, None otherwise
        """
        return self.state_manager.load(investigation_id)

    def list_investigations(
        self,
        status: Optional[InvestigationStatus] = None,
        investigation_type: Optional[str] = None,
        limit: int = 50,
        since_hours: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        List investigations with optional filters.

        Args:
            status: Filter by status
            investigation_type: Filter by type
            limit: Maximum number of results
            since_hours: Only include investigations from last N hours

        Returns:
            List of investigation summaries
        """
        since = None
        if since_hours:
            since = datetime.now(timezone.utc) - timedelta(hours=since_hours)

        return self.state_manager.list_investigations(
            status=status,
            investigation_type=investigation_type,
            limit=limit,
            since=since,
        )

    def delete_investigation(self, investigation_id: str) -> bool:
        """
        Delete an investigation.

        Args:
            investigation_id: The investigation ID

        Returns:
            True if successful, False otherwise
        """
        return self.state_manager.delete(investigation_id)

    def approve_remediation(
        self,
        investigation_id: str,
        action_id: str,
        approved_by: str,
    ) -> bool:
        """
        Approve a remediation action.

        Args:
            investigation_id: The investigation ID
            action_id: The remediation action ID
            approved_by: Who approved the action

        Returns:
            True if successful, False otherwise
        """
        state = self.state_manager.load(investigation_id)
        if not state:
            return False

        for action in state.remediation_actions:
            if action.id == action_id:
                action.status = RemediationStatus.APPROVED
                action.executed_by = approved_by
                self.state_manager.save(state)
                return True

        return False

    def execute_remediation(
        self,
        investigation_id: str,
        action_id: str,
    ) -> Dict[str, Any]:
        """
        Execute an approved remediation action.

        Args:
            investigation_id: The investigation ID
            action_id: The remediation action ID

        Returns:
            Result of the execution
        """
        state = self.state_manager.load(investigation_id)
        if not state:
            return {"success": False, "error": "Investigation not found"}

        for action in state.remediation_actions:
            if action.id == action_id:
                if action.status != RemediationStatus.APPROVED:
                    return {
                        "success": False,
                        "error": f"Action not approved (status: {action.status.value})"
                    }

                # Execute based on action type
                try:
                    result = self._execute_remediation_action(action)
                    action.status = RemediationStatus.EXECUTED
                    action.executed_at = datetime.now(timezone.utc)
                    action.result = result.get("message", "Executed successfully")
                    self.state_manager.save(state)
                    return {"success": True, "result": result}

                except Exception as e:
                    action.status = RemediationStatus.FAILED
                    action.result = str(e)
                    self.state_manager.save(state)
                    return {"success": False, "error": str(e)}

        return {"success": False, "error": "Action not found"}

    def _execute_remediation_action(self, action: RemediationAction) -> Dict[str, Any]:
        """
        Execute a remediation action using available connectors.

        Args:
            action: The remediation action to execute

        Returns:
            Result dictionary
        """
        # Get connector based on action type
        if action.action_type == "block_sender":
            connector = self.connectors.get("email")
            if connector:
                success = connector.block_sender(action.target)
                return {"success": success, "message": f"Blocked sender: {action.target}"}

        elif action.action_type == "delete_email":
            connector = self.connectors.get("email")
            if connector:
                success = connector.delete_message(action.target)
                return {"success": success, "message": f"Deleted message: {action.target}"}

        elif action.action_type == "isolate_host":
            connector = self.connectors.get("edr")
            if connector:
                success = connector.isolate_host(action.target, action.description or "Investigation")
                return {"success": success, "message": f"Isolated host: {action.target}"}

        elif action.action_type == "disable_user":
            connector = self.connectors.get("identity")
            if connector:
                success = connector.disable_user(action.target, action.description or "Investigation")
                return {"success": success, "message": f"Disabled user: {action.target}"}

        elif action.action_type == "revoke_sessions":
            connector = self.connectors.get("identity")
            if connector:
                success = connector.revoke_sessions(action.target)
                return {"success": success, "message": f"Revoked sessions for: {action.target}"}

        elif action.action_type == "reset_password":
            connector = self.connectors.get("identity")
            if connector:
                success = connector.reset_password(action.target, force_change=True)
                return {"success": success, "message": f"Reset password for: {action.target}"}

        # If no connector available, return manual instruction
        return {
            "success": False,
            "message": f"Manual action required: {action.name}",
            "command": action.command,
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get investigation statistics."""
        return self.state_manager.get_stats()

    def add_connector(self, name: str, connector: Any):
        """
        Add a connector to the engine.

        Args:
            name: Connector name (e.g., "email", "siem", "edr", "identity")
            connector: The connector instance
        """
        self.connectors[name] = connector

    def get_available_playbooks(self) -> List[Dict[str, str]]:
        """Get list of available playbooks."""
        return PlaybookRegistry.list_all()
