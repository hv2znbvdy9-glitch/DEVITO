"""Enhanced database pool with PostgreSQL and migration support."""

from typing import Optional, List, Dict, Any
from datetime import datetime
from sqlalchemy import create_engine, Column, String, Boolean, DateTime, Integer, JSON, Text
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from sqlalchemy.pool import NullPool, QueuePool
import os
from ava.core.logging import logger

Base = declarative_base()


class TaskModel(Base):
    """SQLAlchemy Task model with enhanced fields."""
    __tablename__ = "tasks"
    
    id = Column(String, primary_key=True)
    name = Column(String, nullable=False, index=True)
    description = Column(String, nullable=True)
    completed = Column(Boolean, default=False, index=True)
    created_at = Column(DateTime, default=datetime.now, index=True)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    priority = Column(Integer, default=0)
    task_metadata = Column(JSON, nullable=True)
    instance_id = Column(String, nullable=True, index=True)


class DatabasePool:
    """Enhanced database connection pool manager with PostgreSQL support."""

    def __init__(self, database_url: Optional[str] = None):
        """Initialize database pool.
        
        Args:
            database_url: Database URL (uses env var or SQLite default)
        """
        self.database_url = database_url or os.getenv(
            'AVA_DATABASE_URL',
            'sqlite:///ava.db'
        )
        self.engine = None
        self.SessionLocal = None
        self._pool_size = 20
        self._max_overflow = 40

    def initialize(self) -> None:
        """Initialize database with connection pooling."""
        try:
            pool_config = {}
            if self.database_url.startswith('postgresql'):
                pool_config = {
                    'poolclass': QueuePool,
                    'pool_size': self._pool_size,
                    'max_overflow': self._max_overflow,
                    'pool_pre_ping': True,
                    'pool_recycle': 3600
                }
            else:
                pool_config = {'poolclass': NullPool}
            
            self.engine = create_engine(
                self.database_url,
                echo=False,
                **pool_config
            )
            
            self.SessionLocal = sessionmaker(
                autocommit=False,
                autoflush=False,
                bind=self.engine
            )
            
            Base.metadata.create_all(bind=self.engine)
            logger.info(f"Database initialized: {self.database_url}")
        except Exception as e:
            logger.error(f"Database initialization error: {e}")
            raise

    def get_session(self) -> Session:
        """Get database session."""
        if not self.SessionLocal:
            raise RuntimeError("Database not initialized")
        return self.SessionLocal()

    async def save_task(self, task: Dict[str, Any], instance_id: Optional[str] = None) -> bool:
        """Save task to database."""
        try:
            session = self.get_session()
            db_task = TaskModel(
                id=task["id"],
                name=task["name"],
                description=task.get("description"),
                completed=task.get("completed", False),
                priority=task.get("priority", 0),
                task_metadata=task.get("metadata"),
                instance_id=instance_id,
                created_at=task.get("created_at", datetime.now()),
                updated_at=datetime.now()
            )
            session.add(db_task)
            session.commit()
            session.close()
            logger.debug(f"Task saved: {task['id']}")
            return True
        except Exception as e:
            logger.error(f"Error saving task: {e}")
            return False

    async def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve task from database."""
        try:
            session = self.get_session()
            db_task = session.query(TaskModel).filter(TaskModel.id == task_id).first()
            session.close()
            
            if not db_task:
                return None
            
            return {
                "id": db_task.id,
                "name": db_task.name,
                "description": db_task.description,
                "completed": db_task.completed,
                "priority": db_task.priority,
                "metadata": db_task.task_metadata,
                "created_at": db_task.created_at,
                "updated_at": db_task.updated_at,
                "instance_id": db_task.instance_id
            }
        except Exception as e:
            logger.error(f"Error getting task: {e}")
            return None

    async def list_tasks(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """List tasks from database."""
        try:
            session = self.get_session()
            db_tasks = session.query(TaskModel).offset(offset).limit(limit).all()
            session.close()
            
            return [
                {
                    "id": t.id,
                    "name": t.name,
                    "description": t.description,
                    "completed": t.completed,
                    "priority": t.priority,
                    "created_at": t.created_at,
                    "instance_id": t.instance_id
                }
                for t in db_tasks
            ]
        except Exception as e:
            logger.error(f"Error listing tasks: {e}")
            return []

    async def update_task(self, task_id: str, updates: Dict[str, Any]) -> bool:
        """Update task in database."""
        try:
            session = self.get_session()
            db_task = session.query(TaskModel).filter(TaskModel.id == task_id).first()
            
            if not db_task:
                return False
            
            for key, value in updates.items():
                if hasattr(db_task, key):
                    setattr(db_task, key, value)
            
            db_task.updated_at = datetime.now()
            session.commit()
            session.close()
            logger.debug(f"Task updated: {task_id}")
            return True
        except Exception as e:
            logger.error(f"Error updating task: {e}")
            return False

    async def delete_task(self, task_id: str) -> bool:
        """Delete task from database."""
        try:
            session = self.get_session()
            session.query(TaskModel).filter(TaskModel.id == task_id).delete()
            session.commit()
            session.close()
            logger.debug(f"Task deleted: {task_id}")
            return True
        except Exception as e:
            logger.error(f"Error deleting task: {e}")
            return False

    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        try:
            session = self.get_session()
            total = session.query(TaskModel).count()
            completed = session.query(TaskModel).filter(TaskModel.completed == True).count()
            session.close()
            
            return {
                "total_tasks": total,
                "completed_tasks": completed,
                "pending_tasks": total - completed,
                "completion_rate": (completed / total * 100) if total > 0 else 0
            }
        except Exception as e:
            logger.error(f"Error getting stats: {e}")
            return {}
