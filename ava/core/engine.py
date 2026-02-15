"""Core application engine."""

from typing import List, Dict, Optional
from ava.utils.models import Task
from ava.utils.exceptions import ValidationError
from ava.core.logging import logger
import uuid


class Engine:
    """Main AVA engine for processing tasks."""

    def __init__(self) -> None:
        """Initialize the engine."""
        self.tasks: Dict[str, Task] = {}
        logger.info("Engine initialized")

    def add_task(self, name: str, description: Optional[str] = None) -> Task:
        """Add a new task."""
        if not name:
            raise ValidationError("Task name cannot be empty")

        task_id = str(uuid.uuid4())
        task = Task(id=task_id, name=name, description=description)
        self.tasks[task_id] = task
        logger.info(f"Task added: {task_id} - {name}")
        return task

    def get_task(self, task_id: str) -> Optional[Task]:
        """Get a task by ID."""
        return self.tasks.get(task_id)

    def list_tasks(self, completed: Optional[bool] = None) -> List[Task]:
        """List all tasks or filter by completion status."""
        tasks = list(self.tasks.values())
        if completed is not None:
            tasks = [t for t in tasks if t.completed == completed]
        return tasks

    def complete_task(self, task_id: str) -> bool:
        """Mark a task as completed."""
        task = self.get_task(task_id)
        if task is None:
            logger.warning(f"Task not found: {task_id}")
            return False
        task.complete()
        logger.info(f"Task completed: {task_id}")
        return True

    def get_stats(self) -> Dict[str, int]:
        """Get engine statistics."""
        total = len(self.tasks)
        completed = sum(1 for t in self.tasks.values() if t.completed)
        pending = total - completed
        return {
            "total_tasks": total,
            "completed_tasks": completed,
            "pending_tasks": pending,
        }
