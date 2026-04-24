"""AVA V3 database core with SQLAlchemy async storage."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Optional

from sqlalchemy import Boolean, Column, MetaData, String, Table, insert, select
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine


metadata = MetaData()

tasks_table = Table(
    "tasks",
    metadata,
    Column("id", String, primary_key=True),
    Column("name", String, nullable=False),
    Column("description", String, nullable=True),
    Column("completed", Boolean, nullable=False, default=False),
)


@dataclass
class TaskModel:
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
    """Async task store with optional Redis cache."""

    def __init__(self, database_url: str = "sqlite+aiosqlite:///:memory:", redis_url: Optional[str] = None) -> None:
        self.database_url = self._normalize_database_url(database_url)
        self.redis_url = redis_url
        self.engine: Optional[AsyncEngine] = None
        self._redis: Any = None

    @staticmethod
    def _normalize_database_url(database_url: str) -> str:
        if database_url == "sqlite:///:memory:":
            return "sqlite+aiosqlite:///:memory:"
        if database_url.startswith("sqlite:///"):
            return database_url.replace("sqlite:///", "sqlite+aiosqlite:///", 1)
        return database_url

    def initialize(self) -> None:
        import asyncio

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            asyncio.run(self.initialize_async())
            return

        if loop.is_running() and self.engine is None:
            self.engine = create_async_engine(self.database_url, future=True)

    async def initialize_async(self) -> None:
        if self.engine is None:
            self.engine = create_async_engine(self.database_url, future=True)

        async with self.engine.begin() as conn:
            await conn.run_sync(metadata.create_all)

        if self.redis_url and self._redis is None:
            try:
                from redis.asyncio import Redis

                self._redis = Redis.from_url(self.redis_url, decode_responses=True)
                await self._redis.ping()
            except Exception:
                self._redis = None

    async def _ensure_ready(self) -> None:
        if self.engine is None:
            await self.initialize_async()

    async def save_task(self, task: Dict[str, Any] | TaskModel) -> TaskModel:
        await self._ensure_ready()
        model = task if isinstance(task, TaskModel) else TaskModel.from_mapping(task)
        assert self.engine is not None

        stmt = insert(tasks_table).values(**model.to_dict())
        if self.engine.dialect.name == "sqlite":
            stmt = stmt.prefix_with("OR REPLACE")

        async with self.engine.begin() as conn:
            await conn.execute(stmt)

        if self._redis is not None:
            await self._redis.set(f"ava:task:{model.id}", json.dumps(model.to_dict()))

        return model

    async def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        await self._ensure_ready()
        assert self.engine is not None

        if self._redis is not None:
            cached = await self._redis.get(f"ava:task:{task_id}")
            if cached:
                return json.loads(cached)

        async with self.engine.connect() as conn:
            result = await conn.execute(select(tasks_table).where(tasks_table.c.id == task_id))
            row = result.mappings().first()

        if row is None:
            return None

        return {
            "id": row["id"],
            "name": row["name"],
            "description": row["description"],
            "completed": bool(row["completed"]),
        }

    async def close_async(self) -> None:
        if self._redis is not None:
            await self._redis.close()
            self._redis = None
        if self.engine is not None:
            await self.engine.dispose()
            self.engine = None

    def close(self) -> None:
        import asyncio

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            asyncio.run(self.close_async())
            return

        if not loop.is_running():
            loop.run_until_complete(self.close_async())
