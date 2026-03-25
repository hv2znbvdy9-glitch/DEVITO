"""Core application engine."""

from typing import List, Dict, Optional
import subprocess
import asyncio
import shlex
from ava.utils.models import Task
from ava.utils.exceptions import ValidationError
from ava.core.logging import logger
import uuid


class Engine:
    """Main AVA engine for processing tasks."""

    def __init__(self) -> None:
        """Initialize the engine."""
        self.tasks: Dict[str, Task] = {}
        self.background_tasks: Dict[str, asyncio.Task] = {}
        logger.info("Engine initialized")

    def _validate_command(self, command: str) -> None:
        """Validate command for basic safety checks.
        
        Note: This provides basic validation but does not guarantee complete
        security. Commands should only come from trusted sources.
        """
        if not command or not command.strip():
            raise ValidationError("Command cannot be empty")
        
        # Check for potentially dangerous patterns
        dangerous_patterns = [
            '; rm -rf',
            '| rm -rf',
            '&& rm -rf',
            '; dd ',
            '| dd ',
            '&& dd ',
            ':/dev/',
            '> /dev/sd',
            '| /dev/sd',
        ]
        
        command_lower = command.lower()
        for pattern in dangerous_patterns:
            if pattern in command_lower:
                raise ValidationError(f"Command contains potentially dangerous pattern: {pattern}")
        
        # Verify command is valid shell syntax
        try:
            # This doesn't execute, just validates syntax
            shlex.split(command)
        except ValueError as e:
            raise ValidationError(f"Invalid command syntax: {e}")

    def add_task(self, name: str, description: Optional[str] = None, command: Optional[str] = None) -> Task:
        """Add a new task."""
        if not name:
            raise ValidationError("Task name cannot be empty")
        
        # Validate command if provided
        if command:
            self._validate_command(command)

        task_id = str(uuid.uuid4())
        task = Task(id=task_id, name=name, description=description, command=command)
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

    def run_task(self, task_id: str, background: bool = False) -> bool:
        """Run a task by executing its command.
        
        Security Note: Commands are executed with shell=True for flexibility,
        but this means commands should only come from trusted sources. Basic
        validation is performed, but complete security cannot be guaranteed.
        
        Args:
            task_id: The ID of the task to run
            background: If True, run asynchronously in the background
            
        Returns:
            bool: True if task started successfully (or completed for sync tasks)
        """
        task = self.get_task(task_id)
        if task is None:
            logger.warning(f"Task not found: {task_id}")
            return False
        
        if not task.command:
            logger.warning(f"Task {task_id} has no command to execute")
            return False
        
        if task.running:
            logger.warning(f"Task {task_id} is already running")
            return False
        
        task.running = True
        logger.info(f"Running task: {task_id} - {task.name}")
        
        if background:
            # Run in background using asyncio
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
            
            async_task = loop.create_task(self._run_task_async(task))
            self.background_tasks[task_id] = async_task
            logger.info(f"Task {task_id} started in background")
            return True
        else:
            # Run synchronously
            return self._run_task_sync(task)
    
    def _run_task_sync(self, task: Task) -> bool:
        """Execute task synchronously."""
        try:
            result = subprocess.run(
                task.command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            task.result = result.stdout if result.returncode == 0 else result.stderr
            task.running = False
            
            if result.returncode == 0:
                task.complete()
                logger.info(f"Task {task.id} completed successfully")
                return True
            else:
                logger.error(f"Task {task.id} failed with return code {result.returncode}")
                return False
                
        except subprocess.TimeoutExpired:
            task.result = "Task execution timed out"
            task.running = False
            logger.error(f"Task {task.id} timed out")
            return False
        except Exception as e:
            task.result = f"Error: {str(e)}"
            task.running = False
            logger.error(f"Task {task.id} failed: {e}")
            return False
    
    async def _run_task_async(self, task: Task) -> None:
        """Execute task asynchronously."""
        try:
            # Add timeout for background tasks (5 minutes, same as sync)
            async with asyncio.timeout(300):
                process = await asyncio.create_subprocess_shell(
                    task.command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await process.communicate()
                
                task.result = stdout.decode() if process.returncode == 0 else stderr.decode()
                task.running = False
                
                if process.returncode == 0:
                    task.complete()
                    logger.info(f"Background task {task.id} completed successfully")
                else:
                    logger.error(f"Background task {task.id} failed with return code {process.returncode}")
                    
        except asyncio.TimeoutError:
            task.result = "Task execution timed out"
            task.running = False
            logger.error(f"Background task {task.id} timed out")
        except Exception as e:
            task.result = f"Error: {str(e)}"
            task.running = False
            logger.error(f"Background task {task.id} failed: {e}")
        finally:
            # Clean up completed background task from tracking dict
            if task.id in self.background_tasks:
                del self.background_tasks[task.id]
