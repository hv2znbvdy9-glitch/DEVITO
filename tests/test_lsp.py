"""Tests for LSP lifecycle."""

import subprocess
import sys


def test_module_is_importable():
    import ava.lsp.__main__  # noqa: F401


def test_main_clean_shutdown_exits_zero():
    """A proper shutdown sequence should not trigger restarts."""

    msgs = _build_lsp_bytes([
        _make_request("initialize", 1, {"capabilities": {}}),
        _make_notification("initialized"),
        _make_request("shutdown", 2),
        _make_notification("exit"),
    ])

    result = subprocess.run(
        [sys.executable, "-m", "ava.lsp"],
        input=msgs,
        capture_output=True,
        timeout=10,
    )

    assert result.returncode == 0, (
        f"Expected exit 0, got {result.returncode}\n"
        f"stderr: {result.stderr.decode()}"
    )


def _make_request(method, _id, params=None):
    return {
        "jsonrpc": "2.0",
        "id": _id,
        "method": method,
        "params": params or {},
    }


def _make_notification(method, params=None):
    return {
        "jsonrpc": "2.0",
        "method": method,
        "params": params or {},
    }


def _build_lsp_bytes(messages):
    """Encode a list of JSON-RPC messages into LSP wire format."""
    import json

    parts = []
    for msg in messages:
        body = json.dumps(msg).encode("utf-8")
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        parts.append(header + body)
    return b"".join(parts)
