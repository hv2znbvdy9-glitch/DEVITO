"""Simple in-memory monitoring utilities for AVA tests."""

from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Callable, Dict, Any, List
import asyncio


class PerformanceMonitor:
    """Collect timing metrics for code blocks."""

    def __init__(self) -> None:
        self._data: Dict[str, List[float]] = {}

    @contextmanager
    def measure(self, name: str):
        start = time.time()
        try:
            yield
        finally:
            elapsed_ms = (time.time() - start) * 1000
            self._data.setdefault(name, []).append(elapsed_ms)

    def get_statistics(self, name: str) -> Dict[str, float] | None:
        values = self._data.get(name)
        if not values:
            return None
        total = sum(values)
        return {
            "count": len(values),
            "total_ms": total,
            "mean_ms": total / len(values),
            "min_ms": min(values),
            "max_ms": max(values),
        }


class MetricsCollector:
    """Basic counter collector."""

    def __init__(self) -> None:
        self._counters: Dict[str, int] = {}

    def increment_counter(self, name: str, labels: Dict[str, Any] | None = None) -> None:
        key = name
        if labels:
            suffix = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
            key = f"{name}|{suffix}"
        self._counters[key] = self._counters.get(key, 0) + 1

    def get(self, name: str) -> int:
        return self._counters.get(name, 0)


class HealthChecker:
    """Run async health checks."""

    def __init__(self) -> None:
        self._checks: Dict[str, Callable[[], Any]] = {}

    def register_check(self, name: str, func: Callable[[], Any]) -> None:
        self._checks[name] = func

    async def run_checks(self) -> Dict[str, bool]:
        results: Dict[str, bool] = {}

        async def _run(name: str, fn: Callable[[], Any]):
            try:
                res = fn()
                if asyncio.iscoroutine(res):
                    res = await res
                results[name] = bool(res)
            except Exception:
                results[name] = False

        await asyncio.gather(*[_run(name, fn) for name, fn in self._checks.items()])
        return results
