"""Tests for the core engine."""

import pytest
from ava.core.engine import Engine
from ava.utils.exceptions import ValidationError


@pytest.fixture
def engine():
    """Create a fresh engine for each test."""
    return Engine()


def test_add_task(engine):
    """Test adding a task."""
    task = engine.add_task("Test Task")
    assert task.name == "Test Task"
    assert not task.completed
    assert task.id in engine.tasks


def test_add_task_with_description(engine):
    """Test adding a task with description."""
    task = engine.add_task("Task", "This is a test task")
    assert task.description == "This is a test task"


def test_add_empty_task_raises_error(engine):
    """Test that adding empty task raises error."""
    with pytest.raises(ValidationError):
        engine.add_task("")


def test_get_task(engine):
    """Test getting a task."""
    task = engine.add_task("Test")
    retrieved = engine.get_task(task.id)
    assert retrieved == task


def test_get_nonexistent_task(engine):
    """Test getting non-existent task returns None."""
    assert engine.get_task("nonexistent") is None


def test_complete_task(engine):
    """Test completing a task."""
    task = engine.add_task("Test")
    assert engine.complete_task(task.id)
    assert task.completed


def test_complete_nonexistent_task(engine):
    """Test completing non-existent task returns False."""
    assert not engine.complete_task("nonexistent")


def test_list_tasks(engine):
    """Test listing all tasks."""
    engine.add_task("Task 1")
    engine.add_task("Task 2")
    tasks = engine.list_tasks()
    assert len(tasks) == 2


def test_list_tasks_filter_completed(engine):
    """Test filtering tasks by completion status."""
    engine.add_task("Task 1")
    task2_id = engine.add_task("Task 2").id
    engine.complete_task(task2_id)

    pending = engine.list_tasks(completed=False)
    completed = engine.list_tasks(completed=True)

    assert len(pending) == 1
    assert len(completed) == 1


def test_get_stats(engine):
    """Test getting statistics."""
    engine.add_task("Task 1")
    task2 = engine.add_task("Task 2")
    engine.complete_task(task2.id)

    stats = engine.get_stats()
    assert stats["total_tasks"] == 2
    assert stats["completed_tasks"] == 1
    assert stats["pending_tasks"] == 1
