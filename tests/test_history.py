#!/usr/bin/env python3
"""
Unit tests for AnalysisHistory
Tests the SQLite-based analysis history tracker
"""

import pytest
import sys
import os
import tempfile
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from secops_helper.core.history import AnalysisHistory


class TestHistoryInit:
    """Test AnalysisHistory initialization"""

    def test_create_history_with_temp_db(self):
        """Test creating history with a temporary database"""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            history = AnalysisHistory(db_path=db_path)
            assert history is not None
            assert history.db_path == db_path
        finally:
            os.unlink(db_path)

    def test_default_db_path(self):
        """Test that default DB path is in home directory"""
        history = AnalysisHistory.__new__(AnalysisHistory)
        assert ".secops_history.db" in AnalysisHistory.DEFAULT_DB_PATH

    def test_init_creates_table(self):
        """Test that initialization creates the history table"""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            history = AnalysisHistory(db_path=db_path)
            import sqlite3

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            conn.close()
            assert "analysis_history" in tables
        finally:
            os.unlink(db_path)


class TestHistoryRecord:
    """Test recording analysis runs"""

    def setup_method(self):
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.temp_file.name
        self.temp_file.close()
        self.history = AnalysisHistory(db_path=self.db_path)

    def teardown_method(self):
        try:
            os.unlink(self.db_path)
        except Exception:
            pass

    def test_record_basic(self):
        """Test recording a basic analysis"""
        self.history.record(
            input_value="test.eml",
            input_type="email",
            verdict="CLEAN",
            risk_score=10,
            command="analyze",
        )
        recent = self.history.get_recent(1)
        assert len(recent) == 1
        assert recent[0]["input_value"] == "test.eml"
        assert recent[0]["input_type"] == "email"
        assert recent[0]["verdict"] == "CLEAN"
        assert recent[0]["risk_score"] == 10

    def test_record_hash_check(self):
        """Test recording a hash check"""
        self.history.record(
            input_value="44d88612fea8a8f36de82e1278abb02f",
            input_type="hash",
            verdict="MALICIOUS",
            risk_score=95,
            command="check",
            duration_seconds=1.5,
        )
        recent = self.history.get_recent(1)
        assert recent[0]["verdict"] == "MALICIOUS"
        assert recent[0]["command"] == "check"

    def test_record_without_verdict(self):
        """Test recording without verdict (unknown result)"""
        self.history.record(input_value="unknown.bin", input_type="file", command="analyze")
        recent = self.history.get_recent(1)
        assert recent[0]["verdict"] is None
        assert recent[0]["risk_score"] is None

    def test_record_multiple(self):
        """Test recording multiple analyses"""
        for i in range(5):
            self.history.record(
                input_value=f"test_{i}",
                input_type="hash",
                verdict="SUSPICIOUS",
                risk_score=50 + i,
                command="check",
            )
        recent = self.history.get_recent(10)
        assert len(recent) == 5

    def test_record_timestamp_format(self):
        """Test that timestamp is in ISO format with Z suffix"""
        self.history.record(input_value="test", input_type="domain", command="check")
        recent = self.history.get_recent(1)
        assert recent[0]["timestamp"].endswith("Z")
        assert "T" in recent[0]["timestamp"]


class TestHistoryGetRecent:
    """Test retrieving recent analyses"""

    def setup_method(self):
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.temp_file.name
        self.temp_file.close()
        self.history = AnalysisHistory(db_path=self.db_path)

    def teardown_method(self):
        try:
            os.unlink(self.db_path)
        except Exception:
            pass

    def test_get_recent_empty(self):
        """Test getting recent when no history exists"""
        recent = self.history.get_recent()
        assert recent == []

    def test_get_recent_limit(self):
        """Test that limit parameter works"""
        for i in range(10):
            self.history.record(input_value=f"item_{i}", input_type="hash", command="check")
        recent = self.history.get_recent(3)
        assert len(recent) == 3

    def test_get_recent_order(self):
        """Test that most recent comes first"""
        self.history.record(input_value="first", input_type="hash", command="check")
        self.history.record(input_value="second", input_type="domain", command="check")
        self.history.record(input_value="third", input_type="ip", command="check")

        recent = self.history.get_recent(3)
        assert recent[0]["input_value"] == "third"
        assert recent[1]["input_value"] == "second"
        assert recent[2]["input_value"] == "first"

    def test_get_recent_default_limit(self):
        """Test default limit of 10"""
        for i in range(15):
            self.history.record(input_value=f"item_{i}", input_type="hash", command="check")
        recent = self.history.get_recent()
        assert len(recent) == 10


class TestHistoryGetStats:
    """Test history statistics"""

    def setup_method(self):
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.temp_file.name
        self.temp_file.close()
        self.history = AnalysisHistory(db_path=self.db_path)

    def teardown_method(self):
        try:
            os.unlink(self.db_path)
        except Exception:
            pass

    def test_stats_empty(self):
        """Test stats with no history"""
        stats = self.history.get_stats()
        assert stats["total_analyses"] == 0
        assert stats["verdicts"] == {}
        assert stats["types"] == {}
        assert stats["last_analysis"] is None

    def test_stats_total_count(self):
        """Test total analysis count"""
        for i in range(7):
            self.history.record(input_value=f"item_{i}", input_type="hash", command="check")
        stats = self.history.get_stats()
        assert stats["total_analyses"] == 7

    def test_stats_verdict_breakdown(self):
        """Test verdict breakdown in stats"""
        self.history.record(
            input_value="a", input_type="hash", verdict="MALICIOUS", command="check"
        )
        self.history.record(
            input_value="b", input_type="hash", verdict="MALICIOUS", command="check"
        )
        self.history.record(input_value="c", input_type="hash", verdict="CLEAN", command="check")
        self.history.record(
            input_value="d", input_type="hash", verdict="SUSPICIOUS", command="check"
        )

        stats = self.history.get_stats()
        assert stats["verdicts"]["MALICIOUS"] == 2
        assert stats["verdicts"]["CLEAN"] == 1
        assert stats["verdicts"]["SUSPICIOUS"] == 1

    def test_stats_type_breakdown(self):
        """Test input type breakdown in stats"""
        self.history.record(input_value="a", input_type="hash", command="check")
        self.history.record(input_value="b", input_type="hash", command="check")
        self.history.record(input_value="c", input_type="domain", command="check")
        self.history.record(input_value="d", input_type="ip", command="check")

        stats = self.history.get_stats()
        assert stats["types"]["hash"] == 2
        assert stats["types"]["domain"] == 1
        assert stats["types"]["ip"] == 1

    def test_stats_last_analysis(self):
        """Test last analysis timestamp"""
        self.history.record(input_value="test", input_type="hash", command="check")
        stats = self.history.get_stats()
        assert stats["last_analysis"] is not None
        assert stats["last_analysis"].endswith("Z")


class TestHistoryClear:
    """Test clearing history"""

    def setup_method(self):
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.temp_file.name
        self.temp_file.close()
        self.history = AnalysisHistory(db_path=self.db_path)

    def teardown_method(self):
        try:
            os.unlink(self.db_path)
        except Exception:
            pass

    def test_clear_removes_all(self):
        """Test that clear removes all entries"""
        for i in range(5):
            self.history.record(input_value=f"item_{i}", input_type="hash", command="check")
        assert self.history.get_stats()["total_analyses"] == 5

        self.history.clear()
        assert self.history.get_stats()["total_analyses"] == 0
        assert self.history.get_recent() == []

    def test_clear_empty_db(self):
        """Test clearing an already empty database"""
        self.history.clear()  # Should not raise
        assert self.history.get_stats()["total_analyses"] == 0


class TestHistoryErrorHandling:
    """Test error handling and resilience"""

    def test_invalid_db_path_graceful(self):
        """Test that invalid DB path doesn't crash"""
        # Use a path that can't be created
        history = AnalysisHistory(db_path="/nonexistent/path/db.sqlite")
        # Operations should fail silently
        history.record(input_value="test", input_type="hash", command="check")
        assert history.get_recent() == []

    def test_record_with_special_characters(self):
        """Test recording with special characters in input"""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name
        try:
            history = AnalysisHistory(db_path=db_path)
            history.record(
                input_value="test'value\"with;special<chars>",
                input_type="url",
                verdict="SUSPICIOUS",
                command="check",
            )
            recent = history.get_recent(1)
            assert recent[0]["input_value"] == "test'value\"with;special<chars>"
        finally:
            os.unlink(db_path)
