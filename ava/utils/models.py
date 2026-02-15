"""Data models for AVA."""

from dataclasses import dataclass
from typing import Optional
from datetime import datetime


@dataclass
class Task:
    """Represents a task."""

    id: str
    name: str
    description: Optional[str] = None
    completed: bool = False
    created_at: Optional[datetime] = None

    def __post_init__(self) -> None:
        """Initialize data model fields."""
        if self.created_at is None:
            self.created_at = datetime.now()

    def complete(self) -> None:
        """Mark task as completed."""
        self.completed = True

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        created_str = (
            self.created_at.isoformat()
            if self.created_at
            else None
        )
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "completed": self.completed,
            "created_at": created_str,
        }
