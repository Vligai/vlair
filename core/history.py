#!/usr/bin/env python3
"""
Analysis History Tracker - Records analysis runs for status dashboard
Part of SecOps Helper Operationalization (Phase 5)
"""

import sqlite3
import os
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone


class AnalysisHistory:
    """
    SQLite-based analysis history tracker.
    Records analysis runs with input, type, verdict, risk score, and timestamp.
    """

    DEFAULT_DB_PATH = os.path.join(str(Path.home()), '.secops_history.db')

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or self.DEFAULT_DB_PATH
        self._init_db()

    def _init_db(self):
        """Initialize the SQLite database with the history table."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS analysis_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    input_value TEXT NOT NULL,
                    input_type TEXT NOT NULL,
                    verdict TEXT,
                    risk_score INTEGER,
                    command TEXT NOT NULL,
                    duration_seconds REAL
                )
            ''')
            conn.commit()
            conn.close()
        except Exception:
            # If we can't create the DB, history just won't be recorded
            pass

    def record(self, input_value: str, input_type: str, verdict: str = None,
               risk_score: int = None, command: str = 'analyze',
               duration_seconds: float = None):
        """Record an analysis run."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO analysis_history
                    (timestamp, input_value, input_type, verdict, risk_score, command, duration_seconds)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                input_value,
                input_type,
                verdict,
                risk_score,
                command,
                duration_seconds
            ))
            conn.commit()
            conn.close()
        except Exception:
            pass

    def get_recent(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get the most recent analysis runs."""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('''
                SELECT timestamp, input_value, input_type, verdict, risk_score, command
                FROM analysis_history
                ORDER BY id DESC
                LIMIT ?
            ''', (limit,))
            rows = cursor.fetchall()
            conn.close()
            return [dict(row) for row in rows]
        except Exception:
            return []

    def get_stats(self) -> Dict[str, Any]:
        """Get summary statistics about analysis history."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Total count
            cursor.execute('SELECT COUNT(*) FROM analysis_history')
            total = cursor.fetchone()[0]

            # Verdicts breakdown
            cursor.execute('''
                SELECT verdict, COUNT(*) as count
                FROM analysis_history
                WHERE verdict IS NOT NULL
                GROUP BY verdict
            ''')
            verdicts = {row[0]: row[1] for row in cursor.fetchall()}

            # Types breakdown
            cursor.execute('''
                SELECT input_type, COUNT(*) as count
                FROM analysis_history
                GROUP BY input_type
                ORDER BY count DESC
            ''')
            types = {row[0]: row[1] for row in cursor.fetchall()}

            # Last analysis timestamp
            cursor.execute('''
                SELECT timestamp FROM analysis_history
                ORDER BY id DESC LIMIT 1
            ''')
            last_row = cursor.fetchone()
            last_analysis = last_row[0] if last_row else None

            conn.close()

            return {
                'total_analyses': total,
                'verdicts': verdicts,
                'types': types,
                'last_analysis': last_analysis
            }
        except Exception:
            return {
                'total_analyses': 0,
                'verdicts': {},
                'types': {},
                'last_analysis': None
            }

    def clear(self):
        """Clear all history."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM analysis_history')
            conn.commit()
            conn.close()
        except Exception:
            pass
