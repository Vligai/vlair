"""
Background task queue for long-running vlair tool operations.

Uses ``concurrent.futures.ThreadPoolExecutor`` so no external broker
(Redis, Celery, etc.) is required.  Completed results are kept in memory
for *result_ttl* seconds and then garbage-collected by a daemon thread.

Usage::

    from vlair.webapp.tasks import get_task_manager

    mgr = get_task_manager()
    task_id = mgr.submit("yara", run_yara_scan, path, rules)
    status  = mgr.get_status(task_id)
"""

import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional


@dataclass
class TaskRecord:
    """In-memory record for a submitted background task."""

    task_id: str
    tool: str
    status: str = "pending"  # pending | running | completed | failed
    created_at: str = ""
    completed_at: Optional[str] = None
    result: Optional[Any] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


class BackgroundTaskManager:
    """Thread-pool backed task queue with automatic result expiry."""

    def __init__(self, max_workers: int = 4, result_ttl: int = 3600):
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        self._tasks: Dict[str, TaskRecord] = {}
        self._lock = threading.Lock()
        self._result_ttl = result_ttl

        # Daemon cleanup thread
        self._cleaner = threading.Thread(target=self._cleanup_loop, daemon=True)
        self._cleaner.start()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def submit(self, tool: str, fn: Callable, *args: Any, **kwargs: Any) -> str:
        """Submit *fn* for background execution and return a task_id."""
        task_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        record = TaskRecord(task_id=task_id, tool=tool, created_at=now)

        with self._lock:
            self._tasks[task_id] = record

        future = self._executor.submit(self._run, task_id, fn, *args, **kwargs)
        future.add_done_callback(lambda f: self._on_done(task_id, f))

        return task_id

    def get_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Return a JSON-serialisable status dict, or *None* if unknown."""
        with self._lock:
            record = self._tasks.get(task_id)
            if record is None:
                return None
            return record.to_dict()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run(self, task_id: str, fn: Callable, *args: Any, **kwargs: Any) -> Any:
        with self._lock:
            rec = self._tasks.get(task_id)
            if rec:
                rec.status = "running"
        return fn(*args, **kwargs)

    def _on_done(self, task_id: str, future) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            rec = self._tasks.get(task_id)
            if rec is None:
                return
            rec.completed_at = now
            exc = future.exception()
            if exc is not None:
                rec.status = "failed"
                rec.error = str(exc)
            else:
                rec.status = "completed"
                rec.result = future.result()

    def _cleanup_loop(self) -> None:
        """Periodically remove expired completed/failed tasks."""
        while True:
            time.sleep(60)
            cutoff = time.time() - self._result_ttl
            with self._lock:
                to_delete = []
                for tid, rec in self._tasks.items():
                    if rec.status in ("completed", "failed") and rec.completed_at:
                        try:
                            completed_ts = datetime.fromisoformat(rec.completed_at).timestamp()
                            if completed_ts < cutoff:
                                to_delete.append(tid)
                        except (ValueError, TypeError):
                            pass
                for tid in to_delete:
                    del self._tasks[tid]


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_manager: Optional[BackgroundTaskManager] = None
_manager_lock = threading.Lock()


def get_task_manager() -> BackgroundTaskManager:
    """Return (and lazily create) the process-wide BackgroundTaskManager."""
    global _manager
    if _manager is None:
        with _manager_lock:
            if _manager is None:
                _manager = BackgroundTaskManager()
    return _manager
