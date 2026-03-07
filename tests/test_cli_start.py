"""CLI tests for AVA start command."""

import sys
import types

import pytest
from typer.testing import CliRunner

from ava.cli.main import app


def test_start_dry_run_outputs_banner() -> None:
    """Ensure the start command prints the start banner in dry-run mode."""
    runner = CliRunner()

    result = runner.invoke(app, ["start", "--dry-run"])

    assert result.exit_code == 0
    assert "START - JETZT!" in result.output
    assert "Dry run enabled; server not started." in result.output


def test_start_invokes_main_in_normal_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure the start command invokes the AVA main entrypoint."""
    calls = {"count": 0}

    mock_ava_main_module = types.ModuleType("ava.__main__")

    def fake_main() -> None:
        calls["count"] += 1

    mock_ava_main_module.main = fake_main
    monkeypatch.setitem(sys.modules, "ava.__main__", mock_ava_main_module)

    runner = CliRunner()
    result = runner.invoke(app, ["start"])

    assert result.exit_code == 0
    assert calls["count"] == 1
