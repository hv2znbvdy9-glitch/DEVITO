"""Tests for the approve-all feature (engine method and CLI command)."""

import pytest
from typer.testing import CliRunner

from ava.cli.main import app
from ava.core.engine import Engine


# ---------------------------------------------------------------------------
# Engine tests
# ---------------------------------------------------------------------------


@pytest.fixture
def engine():
    """Create a fresh engine for each test."""
    return Engine()


def test_approve_all_returns_count_of_approved_tasks(engine):
    """approve_all returns the number of tasks that were pending."""
    engine.add_task("Task 1")
    engine.add_task("Task 2")
    count = engine.approve_all()
    assert count == 2


def test_approve_all_marks_all_tasks_completed(engine):
    """approve_all marks every task as completed."""
    engine.add_task("Task A")
    engine.add_task("Task B")
    engine.approve_all()
    assert all(t.completed for t in engine.tasks.values())


def test_approve_all_skips_already_completed_tasks(engine):
    """approve_all returns 0 when all tasks are already completed."""
    task = engine.add_task("Already done")
    engine.complete_task(task.id)
    count = engine.approve_all()
    assert count == 0


def test_approve_all_only_approves_pending_tasks(engine):
    """approve_all approves only pending tasks and ignores completed ones."""
    task1 = engine.add_task("Done")
    engine.complete_task(task1.id)
    engine.add_task("Pending")
    count = engine.approve_all()
    assert count == 1


def test_approve_all_empty_engine_returns_zero(engine):
    """approve_all on an empty engine returns 0."""
    count = engine.approve_all()
    assert count == 0


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------


@pytest.fixture
def runner():
    """Return a Typer CLI test runner."""
    return CliRunner()


def test_approve_all_cli_exits_with_code_0(runner):
    """approve-all exits with code 0."""
    result = runner.invoke(app, ["approve-all"])
    assert result.exit_code == 0


def test_approve_all_cli_no_tasks_prints_info(runner):
    """approve-all prints an info message when there are no pending tasks."""
    result = runner.invoke(app, ["approve-all"])
    assert "No pending tasks" in result.output


def test_approve_all_cli_prints_approved_count(runner, monkeypatch):
    """approve-all prints the number of approved tasks."""
    import ava.cli.main as cli_module

    fresh_engine = Engine()
    fresh_engine.add_task("Task 1")
    fresh_engine.add_task("Task 2")
    monkeypatch.setattr(cli_module, "engine", fresh_engine)

    result = runner.invoke(app, ["approve-all"])
    assert result.exit_code == 0
    assert "2" in result.output
    assert "Approved" in result.output
