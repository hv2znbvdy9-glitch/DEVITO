"""CLI tests for AVA start command."""

from typer.testing import CliRunner

from ava.cli.main import app


def test_start_dry_run_outputs_banner() -> None:
    """Ensure the start command prints the start banner in dry-run mode."""
    runner = CliRunner()

    result = runner.invoke(app, ["start", "--dry-run"])

    assert result.exit_code == 0
    assert "START - JETZT!" in result.output
    assert "Dry run" in result.output
