"""Background task system for AVA."""

from typing import Callable, Any, Optional, Dict, List
import asyncio
from datetime import datetime, timedelta
from enum import Enum
from ava.core.logging import logger

class TaskStatus(str, Enum):
    """Task status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class BackgroundTask:
    """Represents a background task."""

    def __init__(
        self, 
        task_id: str, 
        func: Callable, 
        args: tuple = (),
        kwargs: dict = None,
        retry_count: int = 3
    ):
        """Initialize background task."""
        self.task_id = task_id
        self.func = func
        self.args = args
        self.kwargs = kwargs or {}
        self.retry_count = retry_count
        self.status = TaskStatus.PENDING
        self.created_at = datetime.now()
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.result: Optional[Any] = None
        self.error: Optional[str] = None

    async def execute(self) -> Any:
        """Execute the background task."""
        self.status = TaskStatus.RUNNING
        self.started_at = datetime.now()
        
        for attempt in range(self.retry_count):
            try:
                logger.info(f"Executing task {self.task_id} (attempt {attempt + 1})")
                
                if asyncio.iscoroutinefunction(self.func):
                    self.result = await self.func(*self.args, **self.kwargs)
                else:
                    self.result = self.func(*self.args, **self.kwargs)
                
                self.status = TaskStatus.COMPLETED
                self.completed_at = datetime.now()
                logger.info(f"Task {self.task_id} completed successfully")
                return self.result
                
            except Exception as e:
                self.error = str(e)
                logger.error(f"Task {self.task_id} attempt {attempt + 1} failed: {e}")
                
                if attempt < self.retry_count - 1:
                    await asyncio.sleep(2 ** attempt)

        self.status = TaskStatus.FAILED
        self.completed_at = datetime.now()
        return None

class TaskScheduler:
    """Schedule and manage background tasks."""

    def __init__(self):
        """Initialize task scheduler."""
        self.tasks: Dict[str, BackgroundTask] = {}
        self.scheduled_tasks: List[asyncio.Task] = []

    async def submit_task(self, task: BackgroundTask) -> str:
        """Submit a task to the scheduler."""
        self.tasks[task.task_id] = task
        logger.info(f"Task submitted: {task.task_id}")
        
        # Create async task
        async_task = asyncio.create_task(task.execute())
        self.scheduled_tasks.append(async_task)
        
        return task.task_id

    async def schedule_periodic(
        self, 
        task_id: str, 
        func: Callable, 
        interval_seconds: int,
        args: tuple = (),
        kwargs: dict = None
    ) -> None:
        """Schedule a periodic task."""
        kwargs = kwargs or {}
        
        while True:
            try:
                logger.debug(f"Running periodic task: {task_id}")
                
                if asyncio.iscoroutinefunction(func):
                    await func(*args, **kwargs)
                else:
                    func(*args, **kwargs)
                    
            except Exception as e:
                logger.error(f"Periodic task error ({task_id}): {e}")
            
            await asyncio.sleep(interval_seconds)

    def get_task_status(self, task_id: str) -> Optional[TaskStatus]:
        """Get task status."""
        task = self.tasks.get(task_id)
        return task.status if task else None

    def get_all_tasks(self) -> Dict[str, BackgroundTask]:
        """Get all tasks."""
        return self.tasks.copy()
