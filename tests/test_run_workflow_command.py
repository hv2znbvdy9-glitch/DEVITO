"""Tests for the run-workflow CLI command."""

import json

import pytest
from typer.testing import CliRunner

from ava.cli.main import app


@pytest.fixture
def runner() -> CliRunner:
    """Return a Typer CLI test runner."""
    return CliRunner()


# ---------------------------------------------------------------------------
# Successful executions
# ---------------------------------------------------------------------------


def test_run_workflow_success_exit_code(runner: CliRunner) -> None:
    """run-workflow exits with code 0 on a valid workflow ID."""
    result = runner.invoke(app, ["run-workflow", "wf-001"])
    assert result.exit_code == 0


def test_run_workflow_prints_running_message(runner: CliRunner) -> None:
    """run-workflow prints a progress message before executing."""
    result = runner.invoke(app, ["run-workflow", "wf-001"])
    assert "wf-001" in result.output


def test_run_workflow_prints_success_message(runner: CliRunner) -> None:
    """run-workflow prints a success confirmation on completion."""
    result = runner.invoke(app, ["run-workflow", "wf-001"])
    assert "successfully" in result.output.lower()


def test_run_workflow_prints_result_preview(runner: CliRunner) -> None:
    """run-workflow prints a JSON result preview section."""
    result = runner.invoke(app, ["run-workflow", "wf-001"])
    assert "Result preview" in result.output


def test_run_workflow_result_preview_is_valid_json(runner: CliRunner) -> None:
    """The result preview printed by run-workflow is valid JSON."""
    result = runner.invoke(app, ["run-workflow", "wf-preview"])
    # Extract the JSON block from the output (everything after "Result preview:")
    output = result.output
    json_start = output.find("{")
    assert json_start != -1, "No JSON object found in output"
    json_str = output[json_start:]
    parsed = json.loads(json_str)
    assert parsed["workflow_id"] == "wf-preview"
    assert parsed["status"] == "completed"


def test_run_workflow_with_valid_payload(runner: CliRunner) -> None:
    """run-workflow accepts a valid JSON object payload via --payload."""
    payload = json.dumps({"env": "test"})
    result = runner.invoke(app, ["run-workflow", "wf-002", "--payload", payload])
    assert result.exit_code == 0
    assert "successfully" in result.output.lower()


def test_run_workflow_with_tenant_option(runner: CliRunner) -> None:
    """run-workflow accepts a --tenant option without error."""
    result = runner.invoke(app, ["run-workflow", "wf-003", "--tenant", "acme-corp"])
    assert result.exit_code == 0


def test_run_workflow_payload_reflected_in_output(runner: CliRunner) -> None:
    """The workflow input payload is echoed back in the result preview."""
    payload = json.dumps({"greeting": "hello"})
    result = runner.invoke(app, ["run-workflow", "wf-echo", "--payload", payload])
    assert result.exit_code == 0
    assert "greeting" in result.output
    assert "hello" in result.output


# ---------------------------------------------------------------------------
# Validation error paths
# ---------------------------------------------------------------------------


def test_run_workflow_invalid_json_payload_exits_1(runner: CliRunner) -> None:
    """run-workflow exits with code 1 when --payload is not valid JSON."""
    result = runner.invoke(app, ["run-workflow", "wf-bad", "--payload", "not-json"])
    assert result.exit_code == 1


def test_run_workflow_invalid_json_payload_prints_error(runner: CliRunner) -> None:
    """run-workflow prints an error message for an invalid JSON payload."""
    result = runner.invoke(app, ["run-workflow", "wf-bad", "--payload", "not-json"])
    assert "Invalid JSON" in result.output


def test_run_workflow_json_array_payload_exits_1(runner: CliRunner) -> None:
    """run-workflow exits with code 1 when payload is a JSON array."""
    result = runner.invoke(app, ["run-workflow", "wf-bad", "--payload", "[1,2]"])
    assert result.exit_code == 1
