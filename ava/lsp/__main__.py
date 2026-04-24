"""AVA LSP server entry point.

Reads JSON-RPC messages from stdin and handles the standard LSP lifecycle
(initialize → initialized → shutdown → exit).
"""

import json
import sys


def _read_message() -> dict | None:
    """Read one LSP message from stdin.  Returns None on EOF."""
    header = b""
    while True:
        ch = sys.stdin.buffer.read(1)
        if not ch:
            return None
        header += ch
        if header.endswith(b"\r\n\r\n"):
            break

    content_length = 0
    for line in header.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            content_length = int(line.split(b":", 1)[1].strip())
            break

    if content_length == 0:
        return None

    body = sys.stdin.buffer.read(content_length)
    return json.loads(body.decode("utf-8"))


def _send_message(msg: dict) -> None:
    body = json.dumps(msg).encode("utf-8")
    header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
    sys.stdout.buffer.write(header + body)
    sys.stdout.buffer.flush()


def main() -> None:
    """Run the minimal LSP lifecycle loop."""
    initialized = False
    shutdown_requested = False

    while True:
        msg = _read_message()
        if msg is None:
            break

        method = msg.get("method", "")
        msg_id = msg.get("id")

        if method == "initialize":
            _send_message(
                {"jsonrpc": "2.0", "id": msg_id, "result": {"capabilities": {}}}
            )
            initialized = True
        elif method == "initialized":
            pass  # notification – no response needed
        elif method == "shutdown":
            shutdown_requested = True
            _send_message({"jsonrpc": "2.0", "id": msg_id, "result": None})
        elif method == "exit":
            sys.exit(0 if shutdown_requested else 1)


if __name__ == "__main__":
    main()
