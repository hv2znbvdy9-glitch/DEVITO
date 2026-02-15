"""CLI module for AVA."""

import typer
from typing import Optional
from ava.core.engine import Engine
from ava.core.logging import LoggerConfig, logger
from ava.config.settings import get_config
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="AVA - Advanced Virtual Assistant")
console = Console()

# Global engine instance
engine = Engine()


@app.command()
def add(name: str, description: Optional[str] = None) -> None:
    """Add a new task."""
    try:
        task = engine.add_task(name, description)
        console.print(f"✅ Task added: {task.id}")
        console.print(f"   Name: {task.name}")
        if description:
            console.print(f"   Description: {description}")
    except Exception as e:
        console.print(f"❌ Error: {e}", style="red")
        logger.error(f"Error adding task: {e}")


@app.command()
def list_all(show_completed: bool = False) -> None:
    """List all tasks."""
    completed_filter = True if show_completed else None
    tasks = engine.list_tasks(completed=completed_filter)

    table = Table(title="AVA Tasks")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Name", style="magenta")
    table.add_column("Status", style="green")
    table.add_column("Created", style="yellow")

    for task in tasks:
        status = "✅ Completed" if task.completed else "⏳ Pending"
        created_str = (
            task.created_at.strftime("%Y-%m-%d %H:%M")
            if task.created_at
            else "Unknown"
        )
        table.add_row(
            task.id[:8], task.name, status, created_str
        )

    console.print(table)


@app.command()
def complete(task_id: str) -> None:
    """Mark a task as completed."""
    if engine.complete_task(task_id):
        console.print("✅ Task completed!", style="green")
    else:
        console.print("❌ Task not found", style="red")


@app.command()
def stats() -> None:
    """Show task statistics."""
    stats = engine.get_stats()
    console.print("\n[bold cyan]📊 Task Statistics[/bold cyan]")
    console.print(f"  Total Tasks:     {stats['total_tasks']}")
    console.print(f"  Completed:       {stats['completed_tasks']}")
    console.print(f"  Pending:         {stats['pending_tasks']}")
    if stats["total_tasks"] > 0:
        percentage = (
            stats["completed_tasks"] / stats["total_tasks"] * 100
        )
        console.print(f"  Progress:        {percentage:.1f}%")
    console.print()


@app.callback()
def main(debug: bool = False) -> None:
    """Configure AVA application."""
    config = get_config()
    config.debug = debug
    level = "DEBUG" if debug else "INFO"
    LoggerConfig.setup("ava", level=getattr(LoggerConfig, level))
