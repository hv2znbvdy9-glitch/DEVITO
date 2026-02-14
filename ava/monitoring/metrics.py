"""Monitoring and metrics for AVA."""

import time
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from enum import Enum
from ava.core.logging import logger


class MetricType(Enum):
    """Types of metrics."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"


@dataclass
class Metric:
    """Individual metric."""
    name: str
    metric_type: MetricType
    value: float = 0.0
    unit: str = ""
    labels: Dict[str, str] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "type": self.metric_type.value,
            "value": self.value,
            "unit": self.unit,
            "labels": self.labels,
            "timestamp": self.timestamp.isoformat()
        }


class MetricsCollector:
    """Collect and aggregate metrics."""
    
    def __init__(self):
        """Initialize metrics collector."""
        self.metrics: Dict[str, Metric] = {}
        self.history: Dict[str, list] = {}
        self.start_time = datetime.now()
        logger.info("Metrics collector initialized")
    
    def increment_counter(self, name: str, value: float = 1.0, labels: Dict[str, str] = None) -> None:
        """Increment a counter metric.
        
        Args:
            name: Metric name
            value: Increment value
            labels: Optional labels
        """
        labels = labels or {}
        key = f"{name}:{':'.join(f'{k}={v}' for k, v in labels.items())}"
        
        if key not in self.metrics:
            self.metrics[key] = Metric(
                name=name,
                metric_type=MetricType.COUNTER,
                labels=labels
            )
        
        self.metrics[key].value += value
        self._record_history(key, self.metrics[key])
    
    def set_gauge(self, name: str, value: float, labels: Dict[str, str] = None) -> None:
        """Set a gauge metric.
        
        Args:
            name: Metric name
            value: Gauge value
            labels: Optional labels
        """
        labels = labels or {}
        key = f"{name}:{':'.join(f'{k}={v}' for k, v in labels.items())}"
        
        if key not in self.metrics:
            self.metrics[key] = Metric(
                name=name,
                metric_type=MetricType.GAUGE,
                labels=labels
            )
        
        self.metrics[key].value = value
        self._record_history(key, self.metrics[key])
    
    def record_histogram(self, name: str, value: float, labels: Dict[str, str] = None) -> None:
        """Record a histogram value.
        
        Args:
            name: Metric name
            value: Value to record
            labels: Optional labels
        """
        labels = labels or {}
        key = f"{name}:{':'.join(f'{k}={v}' for k, v in labels.items())}"
        
        if key not in self.metrics:
            self.metrics[key] = Metric(
                name=name,
                metric_type=MetricType.HISTOGRAM,
                labels=labels
            )
        
        self.metrics[key].value = value
        self._record_history(key, self.metrics[key])
    
    def _record_history(self, key: str, metric: Metric) -> None:
        """Record metric in history."""
        if key not in self.history:
            self.history[key] = []
        
        # Keep only last 1000 values
        self.history[key].append({
            "value": metric.value,
            "timestamp": metric.timestamp.isoformat()
        })
        
        if len(self.history[key]) > 1000:
            self.history[key] = self.history[key][-1000:]
    
    def get_metric(self, name: str) -> Optional[Dict[str, Any]]:
        """Get current metric value.
        
        Args:
            name: Metric name
            
        Returns:
            Metric data or None
        """
        for key, metric in self.metrics.items():
            if metric.name == name:
                return metric.to_dict()
        return None
    
    def get_all_metrics(self) -> Dict[str, Any]:
        """Get all metrics.
        
        Returns:
            All metrics
        """
        return {
            key: metric.to_dict()
            for key, metric in self.metrics.items()
        }
    
    def get_health_metrics(self) -> Dict[str, Any]:
        """Get health metrics summary."""
        uptime = (datetime.now() - self.start_time).total_seconds()
        
        return {
            "uptime_seconds": uptime,
            "total_metrics": len(self.metrics),
            "metrics": self.get_all_metrics()
        }


class HealthChecker:
    """Health check system for AVA services."""
    
    def __init__(self):
        """Initialize health checker."""
        self.checks: Dict[str, callable] = {}
        self.last_check_time: Dict[str, datetime] = {}
        self.check_results: Dict[str, bool] = {}
        logger.info("Health checker initialized")
    
    def register_check(self, name: str, check_fn: callable) -> None:
        """Register a health check.
        
        Args:
            name: Check name
            check_fn: Async check function
        """
        self.checks[name] = check_fn
        logger.info(f"Health check registered: {name}")
    
    async def run_checks(self) -> Dict[str, Any]:
        """Run all health checks.
        
        Returns:
            Health check results
        """
        results = {
            "timestamp": datetime.now().isoformat(),
            "checks": {}
        }
        
        for name, check_fn in self.checks.items():
            try:
                result = await check_fn()
                self.check_results[name] = result
                self.last_check_time[name] = datetime.now()
                
                results["checks"][name] = {
                    "status": "healthy" if result else "unhealthy",
                    "last_check": self.last_check_time[name].isoformat()
                }
            except Exception as e:
                logger.error(f"Health check failed ({name}): {e}")
                self.check_results[name] = False
                results["checks"][name] = {
                    "status": "error",
                    "error": str(e),
                    "last_check": self.last_check_time.get(name, "never").isoformat() if isinstance(self.last_check_time.get(name), datetime) else "never"
                }
        
        # Overall health
        all_healthy = all(self.check_results.values())
        results["overall_status"] = "healthy" if all_healthy else "degraded"
        
        return results
    
    def get_status(self) -> str:
        """Get overall health status.
        
        Returns:
            Status string
        """
        if not self.check_results:
            return "unknown"
        
        if all(self.check_results.values()):
            return "healthy"
        elif any(self.check_results.values()):
            return "degraded"
        else:
            return "unhealthy"


class PerformanceMonitor:
    """Monitor and track performance metrics."""
    
    def __init__(self):
        """Initialize performance monitor."""
        self.timings: Dict[str, list] = {}
        self.metrics_collector = MetricsCollector()
    
    class MeasureContext:
        """Context manager for measuring execution time."""
        def __init__(self, monitor: 'PerformanceMonitor', name: str):
            self.monitor = monitor
            self.name = name
            self.start_time = None
        
        def __enter__(self):
            self.start_time = time.time()
            return self
        
        def __exit__(self, exc_type, exc_val, exc_tb):
            elapsed = time.time() - self.start_time
            
            if self.name not in self.monitor.timings:
                self.monitor.timings[self.name] = []
            
            self.monitor.timings[self.name].append(elapsed)
            self.monitor.metrics_collector.record_histogram(
                "execution_time_ms",
                elapsed * 1000,
                labels={"operation": self.name}
            )
    
    def measure(self, name: str):
        """Context manager for measuring execution time.
        
        Example:
            with monitor.measure("task_processing"):
                # code to measure
        """
        return self.MeasureContext(self, name)
    
    def get_statistics(self, name: str) -> Optional[Dict[str, float]]:
        """Get statistics for a timed operation.
        
        Args:
            name: Operation name
            
        Returns:
            Statistics or None
        """
        if name not in self.timings or not self.timings[name]:
            return None
        
        times = self.timings[name]
        return {
            "count": len(times),
            "mean_ms": (sum(times) / len(times)) * 1000,
            "min_ms": min(times) * 1000,
            "max_ms": max(times) * 1000,
            "total_ms": sum(times) * 1000
        }
