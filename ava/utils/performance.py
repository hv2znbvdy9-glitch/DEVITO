"""Performance monitoring utilities."""

import time
from functools import wraps
from typing import Any, Callable, TypeVar
from ava.core.logging import logger

T = TypeVar("T")


def measure_performance(func: Callable[..., T]) -> Callable[..., T]:
    """Decorator to measure function execution time."""

    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> T:
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            elapsed = time.time() - start_time
            logger.info(f"{func.__name__} executed in {elapsed:.4f} seconds")
            return result
        except Exception as e:
            elapsed = time.time() - start_time
            logger.error(f"{func.__name__} failed after {elapsed:.4f} seconds: {e}")
            raise

    return wrapper


class PerformanceMonitor:
    """Monitor and report performance metrics."""

    def __init__(self) -> None:
        """Initialize performance monitor."""
        self.metrics: dict = {}

    def record(self, name: str, duration: float) -> None:
        """Record a metric."""
        if name not in self.metrics:
            self.metrics[name] = []
        self.metrics[name].append(duration)

    def get_stats(self, name: str) -> dict:
        """Get statistics for a metric."""
        if name not in self.metrics or not self.metrics[name]:
            return {}

        values = self.metrics[name]
        return {
            "count": len(values),
            "min": min(values),
            "max": max(values),
            "avg": sum(values) / len(values),
        }
