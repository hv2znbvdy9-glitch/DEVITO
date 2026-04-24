"""AVA V2 database pool.

Thread-safe async facade over SQLite with optional Redis caching.
The public API stays small and test-friendly while the internals are ready for
concurrent callers.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import threading
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class TaskModel:
    """Persisted task representation."""

    id: str
    name: str
    description: Optional[str] = None
    completed: bool = False

    @classmethod
    def from_mapping(cls, task: Dict[str, Any]) -> "TaskModel":
        return cls(
            id=str(task["id"]),
            name=str(task.get("name", task["id"])),
            description=task.get("description"),
            completed=bool(task.get("completed", False)),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "completed": self.completed,
        }


class DatabasePool:
    """Async, thread-safe SQLite task store with optional Redis cache.

    Args:
        database_url: ``sqlite:///:memory:``, ``sqlite:///<path>``, or a raw
            SQLite path.
        redis_url: Optional Redis URL. If Redis is unavailable, AVA keeps
            working with SQLite only.
    """

    def __init__(self, database_url: str = "sqlite:///:memory:", redis_url: Optional[str] = None) -> None:
        self.database_url = database_url
        self.redis_url = redis_url
        self._connection: Optional[sqlite3.Connection] = None
        self._lock = threading.RLock()
        self._redis: Any = None

    def _sqlite_path(self) -> str:
        if self.database_url == "sqlite:///:memory:":
            return ":memory:"
        if self.database_url.startswith("sqlite:///"):
            return self.database_url.removeprefix("sqlite:///")
        if "://" in self.database_url:
            raise ValueError(f"Unsupported database URL: {self.database_url}")
        return self.database_url

    def initialize(self) -> None:
        """Open local storage and prepare optional Redis cache."""
        with self._lock:
            if self._connection is None:
                self._connection = sqlite3.connect(
                    self._sqlite_path(),
                    check_same_thread=False,
                )
                self._connection.row_factory = sqlite3.Row

            self._connection.execute(
                """
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    completed INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            self._connection.commit()

            if self.redis_url and self._redis is None:
                try:
                    from redis import Redis

                    self._redis = Redis.from_url(self.redis_url, decode_responses=True)
                    self._redis.ping()
                except Exception:
                    self._redis = None

    @property
    def connection(self) -> sqlite3.Connection:
        if self._connection is None:
            self.initialize()
        assert self._connection is not None
        return self._connection

    async def save_task(self, task: Dict[str, Any] | TaskModel) -> TaskModel:
        """Insert or update a task without blocking the event loop."""
        model = task if isinstance(task, TaskModel) else TaskModel.from_mapping(task)
        await asyncio.to_thread(self._save_task_sync, model)
        return model

    def _save_task_sync(self, model: TaskModel) -> None:
        with self._lock:
            self.connection.execute(
                """
                INSERT INTO tasks (id, name, description, completed)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    description = excluded.description,
                    completed = excluded.completed
                """,
                (model.id, model.name, model.description, int(model.completed)),
            )
            self.connection.commit()
            if self._redis is not None:
                self._redis.set(f"ava:task:{model.id}", json.dumps(model.to_dict()))

    async def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a task by id without blocking the event loop."""
        return await asyncio.to_thread(self._get_task_sync, task_id)

    def _get_task_sync(self, task_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            if self._redis is not None:
                cached = self._redis.get(f"ava:task:{task_id}")
                if cached:
                    return json.loads(cached)

            row = self.connection.execute(
                "SELECT id, name, description, completed FROM tasks WHERE id = ?",
                (task_id,),
            ).fetchone()
            if row is None:
                return None
            return {
                "id": row["id"],
                "name": row["name"],
                "description": row["description"],
                "completed": bool(row["completed"]),
            }

    async def close_async(self) -> None:
        await asyncio.to_thread(self.close)

    def close(self) -> None:
        """Close all open resources."""
        with self._lock:
            if self._redis is not None:
                try:
                    self._redis.close()
                except Exception:
                    pass
                self._redis = None
            if self._connection is not None:
                self._connection.close()
                self._connection = None
