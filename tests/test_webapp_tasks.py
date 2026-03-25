#!/usr/bin/env python3
"""
Tests for the background task queue (tasks.py) and task API endpoints.
"""

import os
import sys
import time
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

flask = pytest.importorskip("flask", reason="Flask not installed")


# ---------------------------------------------------------------------------
# Unit tests for BackgroundTaskManager
# ---------------------------------------------------------------------------


class TestBackgroundTaskManager:
    """Tests for the in-memory task manager (no Flask needed)."""

    def _make_manager(self, **kwargs):
        from vlair.webapp.tasks import BackgroundTaskManager

        return BackgroundTaskManager(max_workers=2, result_ttl=3600, **kwargs)

    def test_submit_and_complete(self):
        """A trivial callable completes successfully."""
        mgr = self._make_manager()
        task_id = mgr.submit("test", lambda: {"ok": True})

        # Poll until done (should be nearly instant)
        for _ in range(50):
            status = mgr.get_status(task_id)
            if status and status["status"] in ("completed", "failed"):
                break
            time.sleep(0.05)

        status = mgr.get_status(task_id)
        assert status is not None
        assert status["status"] == "completed"
        assert status["result"] == {"ok": True}
        assert status["tool"] == "test"

    def test_submit_failing_task(self):
        """A callable that raises is recorded as failed."""
        mgr = self._make_manager()

        def _boom():
            raise RuntimeError("kaboom")

        task_id = mgr.submit("test", _boom)

        for _ in range(50):
            status = mgr.get_status(task_id)
            if status and status["status"] in ("completed", "failed"):
                break
            time.sleep(0.05)

        status = mgr.get_status(task_id)
        assert status is not None
        assert status["status"] == "failed"
        assert "kaboom" in status["error"]

    def test_unknown_task_id(self):
        """Querying a non-existent task_id returns None."""
        mgr = self._make_manager()
        assert mgr.get_status("no-such-id") is None

    def test_concurrent_tasks(self):
        """Three tasks submitted concurrently all complete."""
        mgr = self._make_manager()
        ids = [mgr.submit("t", lambda i=i: i * 10) for i in range(3)]

        for _ in range(100):
            statuses = [mgr.get_status(tid) for tid in ids]
            if all(s and s["status"] == "completed" for s in statuses):
                break
            time.sleep(0.05)

        for tid in ids:
            s = mgr.get_status(tid)
            assert s["status"] == "completed"


# ---------------------------------------------------------------------------
# Flask endpoint tests
# ---------------------------------------------------------------------------


class _FlaskTaskTestBase:
    """Shared setup for Flask task-endpoint tests."""

    def setup_method(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        os.environ["VLAIR_WEBAPP_DB"] = self.temp_db.name

        # Reset the module-level singleton so each test gets a fresh manager
        import vlair.webapp.tasks as _tasks_mod

        _tasks_mod._manager = None

        from vlair.webapp.app import create_app
        from vlair.webapp.auth.models import create_user

        self.app = create_app()
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

        self.user = create_user("taskuser", "task@example.com", "password123")

    def teardown_method(self):
        if hasattr(self, "temp_db"):
            try:
                os.unlink(self.temp_db.name)
            except Exception:
                pass

    def _token(self):
        resp = self.client.post(
            "/api/auth/login",
            json={"username": "taskuser", "password": "password123"},
        )
        return resp.get_json()["access_token"]


class TestSubmitInvalidTool(_FlaskTaskTestBase):
    """POST /api/tasks/<tool> with unsupported tool name."""

    def test_submit_invalid_tool(self):
        token = self._token()
        resp = self.client.post(
            "/api/tasks/nope",
            headers={"Authorization": f"Bearer {token}"},
            json={},
        )
        assert resp.status_code == 400
        assert "Unsupported tool" in resp.get_json()["error"]


class TestGetNonexistentTask(_FlaskTaskTestBase):
    """GET /api/tasks/<task_id> with unknown id."""

    def test_get_nonexistent_task(self):
        token = self._token()
        resp = self.client.get(
            "/api/tasks/00000000-0000-0000-0000-000000000000",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 404
        assert "not found" in resp.get_json()["error"].lower()


class TestYaraTaskEndpoint(_FlaskTaskTestBase):
    """Submit + poll a YARA background task (mocked scanner)."""

    @patch("vlair.tools.yara_scanner.YaraScanner")
    def test_submit_yara_and_poll(self, MockScanner):
        mock_instance = MagicMock()
        mock_instance.scan_file.return_value = {
            "matches": [{"rule": "test_rule"}],
            "rules_loaded": 1,
        }
        MockScanner.return_value = mock_instance

        token = self._token()

        # Create a tiny temp file to upload
        tmp = tempfile.NamedTemporaryFile(suffix=".bin", delete=False)
        tmp.write(b"MZtest")
        tmp.close()

        import io

        with open(tmp.name, "rb") as f:
            data = f.read()
        os.unlink(tmp.name)

        resp = self.client.post(
            "/api/tasks/yara",
            headers={"Authorization": f"Bearer {token}"},
            data={"file": (io.BytesIO(data), "sample.bin")},
            content_type="multipart/form-data",
        )
        assert resp.status_code == 202
        body = resp.get_json()
        assert "task_id" in body
        assert body["status"] == "pending"
        assert "poll_url" in body

        task_id = body["task_id"]

        # Poll until done
        for _ in range(50):
            poll = self.client.get(
                f"/api/tasks/{task_id}",
                headers={"Authorization": f"Bearer {token}"},
            )
            pdata = poll.get_json()
            if pdata.get("status") in ("completed", "failed"):
                break
            time.sleep(0.05)

        assert pdata["status"] == "completed"


class TestPcapTaskEndpoint(_FlaskTaskTestBase):
    """Submit + poll a PCAP background task (mocked analyzer)."""

    @patch("vlair.tools.pcap_analyzer.PCAPAnalyzer")
    def test_submit_pcap_and_poll(self, MockPCAP):
        mock_instance = MagicMock()
        mock_instance.analyze.return_value = {
            "statistics": {"packets": 42},
            "alerts": [],
        }
        MockPCAP.return_value = mock_instance

        token = self._token()

        import io

        resp = self.client.post(
            "/api/tasks/pcap",
            headers={"Authorization": f"Bearer {token}"},
            data={"file": (io.BytesIO(b"\xd4\xc3\xb2\xa1fake"), "capture.pcap")},
            content_type="multipart/form-data",
        )
        assert resp.status_code == 202
        body = resp.get_json()
        task_id = body["task_id"]

        for _ in range(50):
            poll = self.client.get(
                f"/api/tasks/{task_id}",
                headers={"Authorization": f"Bearer {token}"},
            )
            pdata = poll.get_json()
            if pdata.get("status") in ("completed", "failed"):
                break
            time.sleep(0.05)

        assert pdata["status"] == "completed"


class TestTaskRequiresAuth(_FlaskTaskTestBase):
    """Endpoints reject unauthenticated requests."""

    def test_submit_requires_auth(self):
        resp = self.client.post("/api/tasks/yara", json={})
        assert resp.status_code == 401

    def test_poll_requires_auth(self):
        resp = self.client.get("/api/tasks/some-id")
        assert resp.status_code == 401
