"""Database layer for AVA."""

from typing import Optional, List, Dict, Any
from dataclasses import dataclass
from datetime import datetime
from sqlalchemy import create_engine, Column, String, Boolean, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from ava.core.logging import logger

Base = declarative_base()

class TaskModel(Base):
    """SQLAlchemy Task model."""
    __tablename__ = "tasks"
    
    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    description = Column(String, nullable=True)
    completed = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.now)

class DatabasePool:
    """Database connection pool manager."""

    def __init__(self, database_url: str = "sqlite:///ava.db"):
        """Initialize database pool."""
        self.database_url = database_url
        self.engine = None
        self.SessionLocal = None

    def initialize(self) -> None:
        """Initialize database."""
        try:
            self.engine = create_engine(self.database_url, echo=False)
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

    async def save_task(self, task: Dict[str, Any]) -> bool:
        """Save task to database."""
        try:
            session = self.get_session()
            db_task = TaskModel(
                id=task["id"],
                name=task["name"],
                description=task.get("description"),
                completed=task.get("completed", False),
                created_at=task.get("created_at", datetime.now())
            )
            session.add(db_task)
            session.commit()
            session.close()
            logger.debug(f"Task saved to database: {task['id']}")
            return True
        except Exception as e:
            logger.error(f"Error saving task: {e}")
            return False

    async def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve task from database."""
        try:
            session = self.get_session()
            db_task = session.query(TaskModel).filter(
                TaskModel.id == task_id
            ).first()
            session.close()
            
            if db_task:
                return {
                    "id": db_task.id,
                    "name": db_task.name,
                    "description": db_task.description,
                    "completed": db_task.completed,
                    "created_at": db_task.created_at
                }
            return None
        except Exception as e:
            logger.error(f"Error retrieving task: {e}")
            return None

    async def list_tasks(self) -> List[Dict[str, Any]]:
        """List all tasks from database."""
        try:
            session = self.get_session()
            db_tasks = session.query(TaskModel).all()
            session.close()
            
            return [
                {
                    "id": t.id,
                    "name": t.name,
                    "description": t.description,
                    "completed": t.completed,
                    "created_at": t.created_at
                }
                for t in db_tasks
            ]
        except Exception as e:
            logger.error(f"Error listing tasks: {e}")
            return []
