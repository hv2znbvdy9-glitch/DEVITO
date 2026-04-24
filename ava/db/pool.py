"""Lightweight database pool used by AVA tests and local storage.

The implementation intentionally supports an in-memory SQLite database for
fast tests while keeping the public async methods simple for callers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional
import sqlite3


@dataclass
class TaskModel:
    """Persisted task representation."""

    id: str
    name: str
    description: Optional[str] = None
    completed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Return the task as a plain dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "completed": self.completed,
        }


class DatabasePool:
    """Small SQLite-backed task store.

    Args:
        database_url: Supports ``sqlite:///:memory:``, ``sqlite:///<path>``, or
            a raw SQLite path. Other URL types are rejected clearly.
    """

    def __init__(self, database_url: str = "sqlite:///:memory:") -> None:
        self.database_url = database_url
        self._connection: Optional[sqlite3.Connection] = None

    def _sqlite_path(self) -> str:
        if self.database_url == "sqlite:///:memory:":
            return ":memory:"
        if self.database_url.startswith("sqlite:///"):
            return self.database_url.removeprefix("sqlite:///")
        if "://" in self.database_url:
            raise ValueError(f"Unsupported database URL: {self.database_url}")
        return self.database_url

    def initialize(self) -> None:
        """Open the database connection and create required tables."""
        if self._connection is None:
            self._connection = sqlite3.connect(self._sqlite_path())
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

    @property
    def connection(self) -> sqlite3.Connection:
        """Return an initialized connection."""
        if self._connection is None:
            self.initialize()
        assert self._connection is not None
        return self._connection

    async def save_task(self, task: Dict[str, Any] | TaskModel) -> TaskModel:
        """Insert or update a task."""
        model = task if isinstance(task, TaskModel) else TaskModel(
            id=str(task["id"]),
            name=str(task.get("name", task["id"])),
            description=task.get("description"),
            completed=bool(task.get("completed", False)),
        )
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
        return model

    async def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a task by id."""
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

    def close(self) -> None:
        """Close the database connection."""
        if self._connection is not None:
            self._connection.close()
            self._connection = None
