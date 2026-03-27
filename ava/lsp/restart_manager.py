"""Restart manager with exponential back-off for the BERK Language Server.

Prevents the infinite-restart loop described in the issue by tracking
consecutive failures and increasing the delay between attempts.
"""

import logging
import time
from typing import Optional

logger = logging.getLogger("ava.lsp")

# Defaults
_DEFAULT_MAX_RETRIES = 5
_DEFAULT_BASE_DELAY = 1.0     # seconds
_DEFAULT_MAX_DELAY = 30.0     # seconds
_DEFAULT_BACKOFF_FACTOR = 2.0


class RestartManager:
    """Track restart attempts and enforce exponential back-off.

    Usage::

        mgr = RestartManager()
        while mgr.should_restart():
            mgr.wait()
            launch_server()
            mgr.record_failure()
    """

    def __init__(self,
        max_retries: int = _DEFAULT_MAX_RETRIES,
        base_delay: float = _DEFAULT_BASE_DELAY,
        max_delay: float = _DEFAULT_MAX_DELAY,
        backoff_factor: float = _DEFAULT_BACKOFF_FACTOR,
    ):
        if max_retries < 0:
            raise ValueError("max_retries must be >= 0")
        if base_delay < 0:
            raise ValueError("base_delay must be >= 0")
        if max_delay < base_delay:
            raise ValueError("max_delay must be >= base_delay")
        if backoff_factor < 1:
            raise ValueError("backoff_factor must be >= 1")

        self.max_retries = max_retries
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.backoff_factor = backoff_factor

        self._failures = 0
        self._last_failure_time: Optional[float] = None

    # -- public API -------------------------------------------------------------

    @property
    def failures(self) -> int:
        """Number of consecutive failures so far."""
        return self._failures

    def should_restart(self) -> bool:
        """Return True if another restart attempt is allowed."""
        return self._failures < self.max_retries

    def next_delay(self) -> float:
        """Compute the delay (seconds) before the next restart attempt."""
        delay = self.base_delay * (self.backoff_factor ** self._failures)
        return min(delay, self.max_delay)

    def wait(self) -> float:
        """Sleep for the back-off delay.  Returns the time slept."""
        delay = self.next_delay()
        if delay > 0:
            logger.info(
                "LSP: waiting %.1fs before restart attempt %d/%d",
                delay,
                self._failures + 1,
                self.max_retries,
            )
            time.sleep(delay)
        return delay

    def record_failure(self) -> None:
        """Record a failed restart attempt."""
        self._failures += 1
        self._last_failure_time = time.monotonic()
        logger.warning(
            "LSP: restart failure %d/%d",
            self._failures,
            self.max_retries,
        )

    def record_success(self) -> None:
        """Reset failure counter after a successful start."""
        if self._failures > 0:
            logger.info(
                "LSP: server started successfully after %d failure(s)",
                self._failures,
            )
        self._failures = 0
        self._last_failure_time = None

    def reset(self) -> None:
        """Fully reset the manager (e.g. after a long healthy period)."""
        self._failures = 0
        self._last_failure_time = None
