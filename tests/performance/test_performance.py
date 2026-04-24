"""Performance tests for AVA."""

import pytest
import asyncio
import time
from ava.core.engine import Engine
from ava.db.pool import DatabasePool
from ava.monitoring.metrics import PerformanceMonitor, MetricsCollector


@pytest.mark.asyncio
async def test_task_creation_performance():
    """Test creation performance."""
    engine = Engine()
    monitor = PerformanceMonitor()

    with monitor.measure("create_task"):
        for i in range(100):
            engine.add_task(f"Task {i}", f"Description {i}")

    stats = monitor.get_statistics("create_task")
    assert stats is not None
    assert stats["mean_ms"] < 100  # Should complete 100 tasks in < 100ms total
    print(f"✓ Task creation: {stats}")


@pytest.mark.asyncio
async def test_database_pool_performance():
    """Test database operations performance."""
    db = DatabasePool("sqlite:///:memory:")
    db.initialize()
    monitor = PerformanceMonitor()

    # Test save performance
    with monitor.measure("save_task"):
        for i in range(100):
            task = {"id": f"task_{i}", "name": f"Task {i}", "description": f"Desc {i}"}
            await db.save_task(task)

    save_stats = monitor.get_statistics("save_task")
    assert save_stats is not None
    print(f"Database save: {save_stats}")

    # Test retrieve performance
    with monitor.measure("get_task"):
        for i in range(100):
            await db.get_task(f"task_{i}")

    get_stats = monitor.get_statistics("get_task")
    assert get_stats is not None
    print(f"Database get: {get_stats}")


@pytest.mark.asyncio
async def test_metrics_collector_performance():
    """Test metrics collection performance."""
    collector = MetricsCollector()

    start = time.time()

    # Record 10,000 metrics
    for i in range(10000):
        collector.increment_counter("test_counter", labels={"instance": f"i{i % 10}"})

    elapsed = time.time() - start

    # Should handle 10k metrics in < 1 second
    assert elapsed < 1.0
    print(f"Metrics collection: 10k in {elapsed:.3f}s")


@pytest.mark.asyncio
async def test_concurrent_operations():
    """Test concurrent operation performance."""
    engine = Engine()
    monitor = PerformanceMonitor()

    async def create_tasks(count: int):
        for i in range(count):
            engine.add_task(f"Concurrent {i}", "Desc")

    with monitor.measure("concurrent_create"):
        tasks = [create_tasks(25), create_tasks(25), create_tasks(25), create_tasks(25)]
        await asyncio.gather(*tasks)

    stats = monitor.get_statistics("concurrent_create")
    print(f"Concurrent operations: {stats}")


@pytest.mark.asyncio
async def test_throughput_benchmark():
    """Benchmark throughput (tasks per second)."""
    engine = Engine()
    monitor = PerformanceMonitor()

    with monitor.measure("throughput"):
        for i in range(1000):
            engine.add_task(f"Task {i}", "Description")

    stats = monitor.get_statistics("throughput")
    throughput = (1000 / (stats["total_ms"] / 1000)) if stats["total_ms"] > 0 else 0

    print(f"✓ Throughput: {throughput:.0f} tasks/sec ({stats['total_ms']:.1f}ms for 1000 tasks)")
    assert throughput > 100  # Reasonable performance target


def test_memory_efficiency():
    """Test memory efficiency of task storage."""
    import sys

    engine = Engine()

    for i in range(1000):
        engine.add_task(f"Task {i}", f"Description for task {i}")

    # Get size of engine
    size_bytes = sys.getsizeof(engine.tasks)
    size_kb = size_bytes / 1024

    # Should be reasonably efficient
    print(f"Memory: {size_kb:.2f} KB for 1000 tasks")
    assert size_kb < 1024  # Should be less than 1 MB


@pytest.mark.asyncio
async def test_health_check_performance():
    """Test health check performance."""
    from ava.monitoring.metrics import HealthChecker

    checker = HealthChecker()

    async def dummy_check():
        await asyncio.sleep(0.001)
        return True

    for i in range(10):
        checker.register_check(f"check_{i}", dummy_check)

    monitor = PerformanceMonitor()

    with monitor.measure("health_checks"):
        await checker.run_checks()

    stats = monitor.get_statistics("health_checks")
    print(f"Health checks (10 checks): {stats}")


if __name__ == "__main__":
    # For local benchmarking
    print("Run with: pytest tests/performance/test_performance.py -v -s")
