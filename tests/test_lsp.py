"""Tests for AVA LSP module."""

import json


def _make_request(method: str, req_id: int, params: dict | None = None) -> dict:
    """Build a JSON-RPC request message."""
    msg: dict = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        msg["params"] = params
    return msg


def _make_notification(method: str) -> dict:
    """Build a JSON-RPC notification (no id)."""
    return {"jsonrpc": "2.0", "method": method}


class TestLSPModule:
    def test_module_is_importable(self):
        import ava.lsp.__main__  # noqa: F401

    def test_main_clean_shutdown_exits_zero(self):
        """A proper shutdown sequence should not trigger restarts."""
        import subprocess
        import sys

        # Build a proper LSP shutdown sequence
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


def _build_lsp_bytes(messages):
    """Encode a list of JSON-RPC messages into LSP wire format."""
    parts = []
    for msg in messages:
        body = json.dumps(msg).encode("utf-8")
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        parts.append(header + body)
    return b"".join(parts)

