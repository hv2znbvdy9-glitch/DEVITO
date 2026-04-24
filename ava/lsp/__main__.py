"""Minimal LSP server entrypoint used for tests.

Implements a tiny loop that reads LSP messages from stdin and exits cleanly
when it receives a shutdown + exit sequence.
"""

from __future__ import annotations

import sys


def _read_message(stream):
    """Read a single LSP message from a stream."""
    headers = {}
    while True:
        line = stream.readline()
        if not line:
            return None
        if line == b"\r\n":
            break
        key, value = line.decode().split(":", 1)
        headers[key.strip().lower()] = value.strip()

    length = int(headers.get("content-length", 0))
    if length <= 0:
        return None
    return stream.read(length)


def main() -> None:
    """Run a minimal LSP loop."""
    shutdown_requested = False

    while True:
        msg = _read_message(sys.stdin.buffer)
        if msg is None:
            break

        text = msg.decode("utf-8", errors="ignore")

        if "\"method\": \"shutdown\"" in text:
            shutdown_requested = True

        if "\"method\": \"exit\"" in text:
            sys.exit(0 if shutdown_requested else 1)


if __name__ == "__main__":
    main()
