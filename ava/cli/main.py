"""CLI module for AVA."""

import json
import typer
from typing import Optional
from ava.clients.isc_client import ISCClient
from ava.core.engine import Engine
from ava.core.logging import LoggerConfig, logger
from ava.config.settings import get_config
from ava.utils.exceptions import ValidationError
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="AVA - Advanced Virtual Assistant")
console = Console()

# Global engine instance
engine = Engine()


@app.command()
def start(
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Print the start banner only without launching the server.",
    )
) -> None:
    """Start the AVA API server and print the START - JETZT! banner."""
    console.print("START - JETZT!")
    if dry_run:
        console.print("Dry run enabled; server not started.")
        return

    # Lazy import keeps CLI commands lightweight unless the server is started.
    from ava.__main__ import main as start_main

    start_main()


@app.command()
def add(name: str, description: Optional[str] = None, command: Optional[str] = None) -> None:
    """Add a new task."""
    try:
        task = engine.add_task(name, description, command)
        console.print(f"✅ Task added: {task.id}")
        console.print(f"   Name: {task.name}")
        if description:
            console.print(f"   Description: {description}")
        if command:
            console.print(f"   Command: {command}")
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
def run(task_id: str, background: bool = False) -> None:
    """Run a task by executing its command.
    
    Args:
        task_id: The ID of the task to run
        background: Run the task in the background (async)
    """
    task = engine.get_task(task_id)
    if task is None:
        console.print(f"❌ Task not found: {task_id}", style="red")
        return
    
    if not task.command:
        console.print(f"❌ Task has no command to execute", style="red")
        return
    
    console.print(f"🚀 Running task: {task.name}")
    console.print(f"   Command: {task.command}")
    
    if background:
        console.print("   Mode: Background")
    
    success = engine.run_task(task_id, background=background)
    
    if background:
        console.print("✅ Task started in background", style="green")
    elif success:
        console.print("✅ Task completed successfully", style="green")
        if task.result:
            console.print("\n📄 Output:")
            console.print(task.result)
    else:
        console.print("❌ Task failed", style="red")
        if task.result:
            console.print("\n📄 Error:")
            console.print(task.result)


@app.command("approve-all")
def approve_all() -> None:
    """Mark all pending tasks as approved/completed."""
    count = engine.approve_all()
    if count == 0:
        console.print("ℹ️  No pending tasks to approve.", style="cyan")
    else:
        console.print(f"✅ Approved {count} task(s).", style="green")


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


@app.command("run-workflow")
def run_workflow(
    workflow_id: str = typer.Argument(..., help="ID of the workflow to test-execute"),
    tenant: str = typer.Option("", "--tenant", help="ISC tenant identifier"),
    payload: Optional[str] = typer.Option(
        None, "--payload", help="Optional JSON object passed as the workflow input payload"
    ),
) -> None:
    """Test-execute an ISC workflow and preview the result."""
    client = ISCClient(tenant=tenant)

    if payload is not None:
        try:
            json.loads(payload)
        except json.JSONDecodeError as exc:
            console.print(f"❌ Invalid JSON payload: {exc}", style="red")
            raise typer.Exit(code=1)

    console.print(f"⏳ Running workflow [cyan]{workflow_id}[/cyan]…")

    try:
        result = client.testWorkflow(workflow_id, payload=payload)
    except ValidationError as exc:
        console.print(f"❌ {exc}", style="red")
        raise typer.Exit(code=1)

    if result.succeeded:
        console.print("✅ Workflow executed successfully", style="green")
    else:
        console.print(f"⚠️  Workflow finished with status: {result.status}", style="yellow")

    console.print("\n[bold]Result preview:[/bold]")
    console.print_json(json.dumps(result.to_dict()))


@app.callback()
def main(debug: bool = False) -> None:
    """Configure AVA application."""
    config = get_config()
    config.debug = debug
    level = "DEBUG" if debug else "INFO"
    LoggerConfig.setup("ava", level=getattr(LoggerConfig, level))
