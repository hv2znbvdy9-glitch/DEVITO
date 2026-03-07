"""CLI tests for AVA start command."""

import sys
import types

from typer.testing import CliRunner

from ava.cli.main import app


def test_start_dry_run_outputs_banner() -> None:
    """Ensure the start command prints the start banner in dry-run mode."""
    runner = CliRunner()

    result = runner.invoke(app, ["start", "--dry-run"])

    assert result.exit_code == 0
    assert "START - JETZT!" in result.output
    assert "Dry run" in result.output


def test_start_calls_main_when_not_dry_run(monkeypatch) -> None:
    """Ensure the start command invokes the AVA main entrypoint."""
    calls = {"count": 0}

    dummy_module = types.ModuleType("ava.__main__")

    def fake_main() -> None:
        calls["count"] += 1

    dummy_module.main = fake_main
    monkeypatch.setitem(sys.modules, "ava.__main__", dummy_module)

    runner = CliRunner()
    result = runner.invoke(app, ["start"])

    assert result.exit_code == 0
    assert calls["count"] == 1
