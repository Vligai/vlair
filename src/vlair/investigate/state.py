#!/usr/bin/env python3
"""
Investigation State Manager - SQLite-based persistence for investigations

Stores and retrieves investigation state from a SQLite database.
Following the pattern from vlair.core.history.
"""

import sqlite3
import os
import json
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone, timedelta


def _json_serializer(obj):
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


from .models import (
    InvestigationState,
    InvestigationStatus,
    StepResult,
    RemediationAction,
)


class InvestigationStateManager:
    """
    SQLite-based investigation state persistence.

    Stores investigation state, steps, and remediation actions
    in a local SQLite database at ~/.vlair/investigations.db
    """

    DEFAULT_DB_PATH = os.path.join(str(Path.home()), ".vlair", "investigations.db")

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or self.DEFAULT_DB_PATH

        # Ensure directory exists
        db_dir = os.path.dirname(self.db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)

        self._init_db()

    def _init_db(self):
        """Initialize the SQLite database with required tables."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Main investigations table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS investigations (
                    id TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    inputs TEXT,
                    findings TEXT,
                    iocs TEXT,
                    risk_score INTEGER DEFAULT 0,
                    verdict TEXT DEFAULT 'UNKNOWN',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    completed_at TEXT,
                    error TEXT
                )
            """)

            # Investigation steps table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS investigation_steps (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    investigation_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    duration_seconds REAL,
                    output TEXT,
                    error TEXT,
                    step_order INTEGER NOT NULL,
                    FOREIGN KEY (investigation_id) REFERENCES investigations(id)
                )
            """)

            # Remediation actions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS remediation_actions (
                    id TEXT PRIMARY KEY,
                    investigation_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    command TEXT,
                    status TEXT NOT NULL,
                    requires_approval INTEGER DEFAULT 1,
                    priority INTEGER DEFAULT 0,
                    description TEXT,
                    executed_at TEXT,
                    executed_by TEXT,
                    result TEXT,
                    FOREIGN KEY (investigation_id) REFERENCES investigations(id)
                )
            """)

            # Create indexes for common queries
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_investigations_status
                ON investigations(status)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_investigations_created
                ON investigations(created_at)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_steps_investigation
                ON investigation_steps(investigation_id)
            """)
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_remediation_investigation
                ON remediation_actions(investigation_id)
            """)

            conn.commit()
            conn.close()
        except Exception as e:
            # If we can't create the DB, state persistence won't work
            # but we shouldn't crash
            pass

    def save(self, state: InvestigationState) -> bool:
        """
        Save an investigation state to the database.

        Args:
            state: The InvestigationState to save

        Returns:
            True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Serialize JSON fields
            inputs_json = json.dumps(state.inputs, default=_json_serializer)
            findings_json = json.dumps(state.findings, default=_json_serializer)
            iocs_json = json.dumps(state.iocs, default=_json_serializer)

            # Upsert investigation record
            cursor.execute(
                """
                INSERT OR REPLACE INTO investigations
                (id, type, status, inputs, findings, iocs, risk_score, verdict,
                 created_at, updated_at, completed_at, error)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    state.id,
                    state.type,
                    state.status.value,
                    inputs_json,
                    findings_json,
                    iocs_json,
                    state.risk_score,
                    state.verdict,
                    state.created_at.isoformat(),
                    state.updated_at.isoformat(),
                    state.completed_at.isoformat() if state.completed_at else None,
                    state.error,
                ),
            )

            # Delete existing steps and remediation actions (for update)
            cursor.execute(
                "DELETE FROM investigation_steps WHERE investigation_id = ?", (state.id,)
            )
            cursor.execute(
                "DELETE FROM remediation_actions WHERE investigation_id = ?", (state.id,)
            )

            # Insert steps
            for i, step in enumerate(state.steps):
                cursor.execute(
                    """
                    INSERT INTO investigation_steps
                    (investigation_id, name, status, started_at, completed_at,
                     duration_seconds, output, error, step_order)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        state.id,
                        step.name,
                        step.status.value,
                        step.started_at.isoformat() if step.started_at else None,
                        step.completed_at.isoformat() if step.completed_at else None,
                        step.duration_seconds,
                        json.dumps(step.output, default=_json_serializer) if step.output else None,
                        step.error,
                        i,
                    ),
                )

            # Insert remediation actions
            for action in state.remediation_actions:
                cursor.execute(
                    """
                    INSERT INTO remediation_actions
                    (id, investigation_id, name, action_type, target, command,
                     status, requires_approval, priority, description,
                     executed_at, executed_by, result)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        action.id,
                        state.id,
                        action.name,
                        action.action_type,
                        action.target,
                        action.command,
                        action.status.value,
                        1 if action.requires_approval else 0,
                        action.priority,
                        action.description,
                        action.executed_at.isoformat() if action.executed_at else None,
                        action.executed_by,
                        action.result,
                    ),
                )

            conn.commit()
            conn.close()
            return True

        except Exception as e:
            return False

    def load(self, investigation_id: str) -> Optional[InvestigationState]:
        """
        Load an investigation state from the database.

        Args:
            investigation_id: The ID of the investigation to load

        Returns:
            The InvestigationState if found, None otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            # Load investigation
            cursor.execute("SELECT * FROM investigations WHERE id = ?", (investigation_id,))
            row = cursor.fetchone()

            if not row:
                conn.close()
                return None

            # Build state dict
            data = {
                "id": row["id"],
                "type": row["type"],
                "status": row["status"],
                "inputs": json.loads(row["inputs"]) if row["inputs"] else {},
                "findings": json.loads(row["findings"]) if row["findings"] else [],
                "iocs": json.loads(row["iocs"]) if row["iocs"] else {},
                "risk_score": row["risk_score"],
                "verdict": row["verdict"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
                "completed_at": row["completed_at"],
                "error": row["error"],
            }

            # Load steps
            cursor.execute(
                """
                SELECT * FROM investigation_steps
                WHERE investigation_id = ?
                ORDER BY step_order
            """,
                (investigation_id,),
            )

            steps = []
            for step_row in cursor.fetchall():
                steps.append(
                    {
                        "name": step_row["name"],
                        "status": step_row["status"],
                        "started_at": step_row["started_at"],
                        "completed_at": step_row["completed_at"],
                        "duration_seconds": step_row["duration_seconds"],
                        "output": json.loads(step_row["output"]) if step_row["output"] else None,
                        "error": step_row["error"],
                    }
                )
            data["steps"] = steps

            # Load remediation actions
            cursor.execute(
                "SELECT * FROM remediation_actions WHERE investigation_id = ?", (investigation_id,)
            )

            actions = []
            for action_row in cursor.fetchall():
                actions.append(
                    {
                        "id": action_row["id"],
                        "name": action_row["name"],
                        "action_type": action_row["action_type"],
                        "target": action_row["target"],
                        "command": action_row["command"],
                        "status": action_row["status"],
                        "requires_approval": bool(action_row["requires_approval"]),
                        "priority": action_row["priority"],
                        "description": action_row["description"],
                        "executed_at": action_row["executed_at"],
                        "executed_by": action_row["executed_by"],
                        "result": action_row["result"],
                    }
                )
            data["remediation_actions"] = actions

            conn.close()

            return InvestigationState.from_dict(data)

        except Exception as e:
            return None

    def list_investigations(
        self,
        status: Optional[InvestigationStatus] = None,
        investigation_type: Optional[str] = None,
        limit: int = 50,
        since: Optional[datetime] = None,
    ) -> List[Dict[str, Any]]:
        """
        List investigations with optional filters.

        Args:
            status: Filter by status
            investigation_type: Filter by type (e.g., "phishing")
            limit: Maximum number of results
            since: Only include investigations created since this time

        Returns:
            List of investigation summary dictionaries
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            query = "SELECT id, type, status, risk_score, verdict, created_at, completed_at FROM investigations"
            conditions = []
            params = []

            if status:
                conditions.append("status = ?")
                params.append(status.value)

            if investigation_type:
                conditions.append("type = ?")
                params.append(investigation_type)

            if since:
                conditions.append("created_at >= ?")
                params.append(since.isoformat())

            if conditions:
                query += " WHERE " + " AND ".join(conditions)

            query += " ORDER BY created_at DESC LIMIT ?"
            params.append(limit)

            cursor.execute(query, params)
            rows = cursor.fetchall()
            conn.close()

            return [dict(row) for row in rows]

        except Exception:
            return []

    def delete(self, investigation_id: str) -> bool:
        """
        Delete an investigation and all related data.

        Args:
            investigation_id: The ID of the investigation to delete

        Returns:
            True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Delete in correct order for foreign keys
            cursor.execute(
                "DELETE FROM remediation_actions WHERE investigation_id = ?", (investigation_id,)
            )
            cursor.execute(
                "DELETE FROM investigation_steps WHERE investigation_id = ?", (investigation_id,)
            )
            cursor.execute("DELETE FROM investigations WHERE id = ?", (investigation_id,))

            conn.commit()
            conn.close()
            return True

        except Exception:
            return False

    def get_stats(self) -> Dict[str, Any]:
        """
        Get summary statistics about investigations.

        Returns:
            Dictionary with statistics
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Total count
            cursor.execute("SELECT COUNT(*) FROM investigations")
            total = cursor.fetchone()[0]

            # Status breakdown
            cursor.execute("""
                SELECT status, COUNT(*) as count
                FROM investigations
                GROUP BY status
            """)
            status_counts = {row[0]: row[1] for row in cursor.fetchall()}

            # Type breakdown
            cursor.execute("""
                SELECT type, COUNT(*) as count
                FROM investigations
                GROUP BY type
                ORDER BY count DESC
            """)
            type_counts = {row[0]: row[1] for row in cursor.fetchall()}

            # Verdict breakdown
            cursor.execute("""
                SELECT verdict, COUNT(*) as count
                FROM investigations
                WHERE status = 'completed'
                GROUP BY verdict
            """)
            verdict_counts = {row[0]: row[1] for row in cursor.fetchall()}

            # Last investigation
            cursor.execute("""
                SELECT id, created_at FROM investigations
                ORDER BY created_at DESC LIMIT 1
            """)
            last_row = cursor.fetchone()
            last_investigation = (
                {"id": last_row[0], "created_at": last_row[1]} if last_row else None
            )

            # Average risk score for completed investigations
            cursor.execute("""
                SELECT AVG(risk_score) FROM investigations
                WHERE status = 'completed' AND risk_score > 0
            """)
            avg_risk = cursor.fetchone()[0]

            conn.close()

            return {
                "total_investigations": total,
                "status_breakdown": status_counts,
                "type_breakdown": type_counts,
                "verdict_breakdown": verdict_counts,
                "last_investigation": last_investigation,
                "average_risk_score": round(avg_risk, 1) if avg_risk else None,
            }

        except Exception:
            return {
                "total_investigations": 0,
                "status_breakdown": {},
                "type_breakdown": {},
                "verdict_breakdown": {},
                "last_investigation": None,
                "average_risk_score": None,
            }

    def cleanup_old(self, days: int = 30) -> int:
        """
        Delete investigations older than the specified number of days.

        Args:
            days: Number of days to keep investigations

        Returns:
            Number of investigations deleted
        """
        try:
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            cutoff_str = cutoff.isoformat()

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Get IDs of old investigations
            cursor.execute("SELECT id FROM investigations WHERE created_at < ?", (cutoff_str,))
            old_ids = [row[0] for row in cursor.fetchall()]

            if not old_ids:
                conn.close()
                return 0

            # Delete related records
            placeholders = ",".join("?" * len(old_ids))
            cursor.execute(
                f"DELETE FROM remediation_actions WHERE investigation_id IN ({placeholders})",
                old_ids,
            )
            cursor.execute(
                f"DELETE FROM investigation_steps WHERE investigation_id IN ({placeholders})",
                old_ids,
            )
            cursor.execute(f"DELETE FROM investigations WHERE id IN ({placeholders})", old_ids)

            conn.commit()
            conn.close()
            return len(old_ids)

        except Exception:
            return 0
