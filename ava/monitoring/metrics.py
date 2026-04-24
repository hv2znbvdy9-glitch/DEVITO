"""Monitoring and metrics for AVA."""

import time
from typing import Dict, Any, Optional
from datetime import datetime
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
            "timestamp": self.timestamp.isoformat(),
        }


class MetricsCollector:
    """Collect and aggregate metrics."""

    def __init__(self):
        """Initialize metrics collector."""
        self.metrics: Dict[str, Metric] = {}
        self.history: Dict[str, list] = {}
        self.start_time = datetime.now()
        logger.info("Metrics collector initialized")

    def increment_counter(
        self, name: str, value: float = 1.0, labels: Dict[str, str] = None
    ) -> None:
        """Increment a counter metric.

        Args:
            name: Metric name
            value: Increment value
            labels: Optional labels
        """
        labels = labels or {}
        key = f"{name}:{':'.join(f'{k}={v}' for k, v in labels.items())}"

        if key not in self.metrics:
            self.metrics[key] = Metric(name=name, metric_type=MetricType.COUNTER, labels=labels)

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
            self.metrics[key] = Metric(name=name, metric_type=MetricType.GAUGE, labels=labels)

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
            self.metrics[key] = Metric(name=name, metric_type=MetricType.HISTOGRAM, labels=labels)

        self.metrics[key].value = value
        self._record_history(key, self.metrics[key])

    def _record_history(self, key: str, metric: Metric) -> None:
        """Record metric in history."""
        if key not in self.history:
            self.history[key] = []

        # Keep only last 1000 values
        self.history[key].append({"value": metric.value, "timestamp": metric.timestamp.isoformat()})

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
        return {key: metric.to_dict() for key, metric in self.metrics.items()}

    def get_health_metrics(self) -> Dict[str, Any]:
        """Get health metrics summary."""
        uptime = (datetime.now() - self.start_time).total_seconds()

        return {
            "uptime_seconds": uptime,
            "total_metrics": len(self.metrics),
            "metrics": self.get_all_metrics(),
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
        results = {"timestamp": datetime.now().isoformat(), "checks": {}}

        for name, check_fn in self.checks.items():
            try:
                result = await check_fn()
                self.check_results[name] = result
                self.last_check_time[name] = datetime.now()

                results["checks"][name] = {
                    "status": "healthy" if result else "unhealthy",
                    "last_check": self.last_check_time[name].isoformat(),
                }
            except Exception as e:
                logger.error(f"Health check failed ({name}): {e}")
                self.check_results[name] = False
                results["checks"][name] = {
                    "status": "error",
                    "error": str(e),
                    "last_check": (
                        self.last_check_time.get(name, "never").isoformat()
                        if isinstance(self.last_check_time.get(name), datetime)
                        else "never"
                    ),
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

        def __init__(self, monitor: "PerformanceMonitor", name: str):
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
                "execution_time_ms", elapsed * 1000, labels={"operation": self.name}
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
            "total_ms": sum(times) * 1000,
        }


class WellbeingMetrics:
    """🌟 Specialized metrics for AVA Wellbeing System."""

    def __init__(self):
        """Initialize wellbeing metrics."""
        self.metrics_collector = MetricsCollector()
        self.pillar_scores: Dict[str, list] = {
            "happiness": [],
            "health": [],
            "love": [],
            "freedom": [],
            "leisure": [],
            "wealth": [],
            "peace": [],
        }
        self.overall_scores: list = []
        self.recommendations_generated: int = 0
        self.ai_predictions_made: int = 0
        self.chill_mode_activations: int = 0
        self.meditation_sessions: int = 0
        self.automations_created: int = 0
        self.cloud_providers_registered: int = 0
        logger.info("Wellbeing metrics initialized")

    def record_pillar_score(self, pillar: str, score: float) -> None:
        """Record a pillar score.

        Args:
            pillar: Pillar name (happiness, health, etc.)
            score: Score value (0-100)
        """
        if pillar in self.pillar_scores:
            self.pillar_scores[pillar].append(score)
            self.metrics_collector.set_gauge(
                "wellbeing_pillar_score", score, labels={"pillar": pillar}
            )

    def record_overall_score(self, score: float) -> None:
        """Record overall wellbeing score.

        Args:
            score: Overall score (0-100)
        """
        self.overall_scores.append(score)
        self.metrics_collector.set_gauge("wellbeing_overall_score", score)

    def record_recommendation(self, pillar: str) -> None:
        """Record a recommendation generated.

        Args:
            pillar: Pillar for which recommendation was generated
        """
        self.recommendations_generated += 1
        self.metrics_collector.increment_counter(
            "wellbeing_recommendations_generated", labels={"pillar": pillar}
        )

    def record_ai_prediction(self, pillar: str) -> None:
        """Record an AI prediction.

        Args:
            pillar: Pillar being predicted
        """
        self.ai_predictions_made += 1
        self.metrics_collector.increment_counter(
            "wellbeing_ai_predictions_made", labels={"pillar": pillar}
        )

    def record_chill_mode(self, duration_hours: float, intensity: float) -> None:
        """Record a chill mode activation.

        Args:
            duration_hours: Duration in hours
            intensity: Intensity (0-1)
        """
        self.chill_mode_activations += 1
        self.metrics_collector.increment_counter("wellbeing_chill_mode_activations")
        self.metrics_collector.record_histogram("wellbeing_chill_mode_intensity", intensity)

    def record_meditation(self, duration_minutes: int) -> None:
        """Record a meditation session.

        Args:
            duration_minutes: Duration in minutes
        """
        self.meditation_sessions += 1
        self.metrics_collector.increment_counter("wellbeing_meditation_sessions")
        self.metrics_collector.record_histogram(
            "wellbeing_meditation_duration_minutes", duration_minutes
        )

    def record_automation(self) -> None:
        """Record automation creation."""
        self.automations_created += 1
        self.metrics_collector.increment_counter("wellbeing_automations_created")

    def record_cloud_provider(self, provider: str) -> None:
        """Record cloud provider registration.

        Args:
            provider: Provider name (AWS, Azure, GCP, etc.)
        """
        self.cloud_providers_registered += 1
        self.metrics_collector.increment_counter(
            "wellbeing_cloud_providers_registered", labels={"provider": provider}
        )

    def get_wellbeing_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of wellbeing metrics.

        Returns:
            Dictionary with wellbeing metrics summary
        """
        # Calculate averages
        pillar_averages = {}
        for pillar, scores in self.pillar_scores.items():
            if scores:
                pillar_averages[pillar] = sum(scores) / len(scores)
            else:
                pillar_averages[pillar] = 0

        overall_average = (
            sum(self.overall_scores) / len(self.overall_scores) if self.overall_scores else 0
        )

        return {
            "timestamp": datetime.now().isoformat(),
            "overall_average_score": overall_average,
            "pillar_averages": pillar_averages,
            "metrics": {
                "recommendations_generated": self.recommendations_generated,
                "ai_predictions_made": self.ai_predictions_made,
                "chill_mode_activations": self.chill_mode_activations,
                "meditation_sessions": self.meditation_sessions,
                "meditation_total_minutes": (
                    sum([self.meditation_sessions * 10])  # Assume avg 10 min
                    if self.meditation_sessions > 0
                    else 0
                ),
                "automations_created": self.automations_created,
                "cloud_providers_registered": self.cloud_providers_registered,
                "total_pillar_scores_recorded": sum(len(s) for s in self.pillar_scores.values()),
            },
            "trend": self._calculate_trend(),
        }

    def _calculate_trend(self) -> str:
        """Calculate wellbeing trend.

        Returns:
            Trend indicator (improving, stable, declining)
        """
        if len(self.overall_scores) < 2:
            return "stable"

        recent = self.overall_scores[-5:] if len(self.overall_scores) >= 5 else self.overall_scores

        if len(recent) > 1:
            avg_recent = sum(recent) / len(recent)
            avg_previous = (
                sum(self.overall_scores[:-5]) / (len(self.overall_scores) - 5)
                if len(self.overall_scores) > 5
                else avg_recent
            )

            if avg_recent > avg_previous + 5:
                return "improving"
            elif avg_recent < avg_previous - 5:
                return "declining"

        return "stable"

    def export_prometheus_format(self) -> str:
        """Export metrics in Prometheus format.

        Returns:
            Prometheus format metric string
        """
        lines = []

        # Overall score
        if self.overall_scores:
            latest = self.overall_scores[-1]
            lines.append(f"ava_wellbeing_overall_score {latest}")

        # Pillar scores
        for pillar, scores in self.pillar_scores.items():
            if scores:
                latest = scores[-1]
                lines.append(f'ava_wellbeing_pillar_score{{pillar="{pillar}"}} {latest}')

        # Counters
        lines.append(f"ava_wellbeing_recommendations_total {self.recommendations_generated}")
        lines.append(f"ava_wellbeing_predictions_total {self.ai_predictions_made}")
        lines.append(f"ava_wellbeing_chill_activations_total {self.chill_mode_activations}")
        lines.append(f"ava_wellbeing_meditation_sessions_total {self.meditation_sessions}")
        lines.append(f"ava_wellbeing_automations_total {self.automations_created}")
        lines.append(f"ava_wellbeing_providers_registered_total {self.cloud_providers_registered}")

        return "\n".join(lines)
