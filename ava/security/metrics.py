"""
AVA Adaptive Security - Prometheus Metrics
===========================================
Exportiert Metriken für Grafana/Prometheus Monitoring
"""

import time
from typing import Optional

try:
    from prometheus_client import (
        Counter,
        Gauge,
        Histogram,
        Summary,
        Info,
        CollectorRegistry,
        generate_latest,
    )

    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False


class SecurityMetrics:
    """Prometheus Metrics für Adaptive Security System"""

    def __init__(self, registry: Optional["CollectorRegistry"] = None):
        if not PROMETHEUS_AVAILABLE:
            raise ImportError("prometheus_client not installed. Run: pip install prometheus-client")

        # Use provided registry or create new one
        if registry is None:
            from prometheus_client import CollectorRegistry

            registry = CollectorRegistry()

        self.registry = registry

        # Adaptive Network IDS Metrics
        self.network_scans_total = Counter(
            "ava_security_network_scans_total",
            "Total number of network scans performed",
            ["result"],  # allowed, blocked, suspicious
            registry=registry,
        )

        self.network_threats_detected = Counter(
            "ava_security_network_threats_detected_total",
            "Total number of network threats detected",
            ["threat_level"],  # benign, suspicious, malicious, critical
            registry=registry,
        )

        self.network_patterns_learned = Counter(
            "ava_security_network_patterns_learned_total",
            "Total number of attack patterns learned",
            registry=registry,
        )

        self.network_blacklist_size = Gauge(
            "ava_security_network_blacklist_size",
            "Current size of IP/MAC blacklists",
            ["type"],  # ip, mac
            registry=registry,
        )

        self.network_fingerprints = Gauge(
            "ava_security_network_fingerprints_total",
            "Total number of unique network fingerprints",
            registry=registry,
        )

        self.network_trust_score = Histogram(
            "ava_security_network_trust_score",
            "Distribution of network trust scores",
            buckets=[0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100],
            registry=registry,
        )

        # Cookie Security Scanner Metrics
        self.cookie_scans_total = Counter(
            "ava_security_cookie_scans_total", "Total number of cookies scanned", registry=registry
        )

        self.cookie_threats_found = Counter(
            "ava_security_cookie_threats_found_total",
            "Total number of cookie threats found",
            ["threat_type"],  # xss_payload, sql_injection, tracking, etc.
            registry=registry,
        )

        self.cookie_patterns_learned = Counter(
            "ava_security_cookie_patterns_learned_total",
            "Total number of malicious cookie patterns learned",
            registry=registry,
        )

        self.cookie_blacklist_size = Gauge(
            "ava_security_cookie_blacklist_size",
            "Current size of cookie blacklists",
            ["type"],  # name, hash
            registry=registry,
        )

        # Distributed Security Mesh Metrics
        self.mesh_nodes_total = Gauge(
            "ava_security_mesh_nodes_total",
            "Total number of mesh nodes",
            ["state"],  # secure, monitoring, threatened, under_attack, isolated
            registry=registry,
        )

        self.mesh_events_total = Counter(
            "ava_security_mesh_events_total",
            "Total number of mesh events",
            ["event_type", "severity"],
            registry=registry,
        )

        self.mesh_policies_active = Gauge(
            "ava_security_mesh_policies_active",
            "Number of active security policies",
            registry=registry,
        )

        self.mesh_shared_intelligence = Gauge(
            "ava_security_mesh_shared_intelligence",
            "Size of shared threat intelligence",
            ["type"],  # blacklist_ips, blacklist_macs, threat_signatures
            registry=registry,
        )

        # Universal Interface Protection Metrics
        self.interface_requests_total = Counter(
            "ava_security_interface_requests_total",
            "Total number of interface requests",
            ["interface_type", "action"],  # http/websocket/raw_socket, allow/block/rate_limit
            registry=registry,
        )

        self.interface_threats_detected = Counter(
            "ava_security_interface_threats_detected_total",
            "Total number of interface threats detected",
            ["interface_type", "threat_type"],
            registry=registry,
        )

        self.interface_threat_score = Histogram(
            "ava_security_interface_threat_score",
            "Distribution of interface threat scores",
            ["interface_type"],
            buckets=[0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100],
            registry=registry,
        )

        # Global Security Metrics
        self.global_security_score = Gauge(
            "ava_security_global_score", "Global security score (0-100)", registry=registry
        )

        self.system_uptime_seconds = Gauge(
            "ava_security_uptime_seconds", "System uptime in seconds", registry=registry
        )

        self.system_info = Info("ava_security_system", "System information", registry=registry)

        # Request Duration
        self.scan_duration_seconds = Summary(
            "ava_security_scan_duration_seconds",
            "Duration of security scans",
            ["scan_type"],  # network, cookie, interface
            registry=registry,
        )

        # Start time
        self.start_time = time.time()

    def update_from_adaptive_ids(self, anids):
        """Update metrics from Adaptive Network IDS"""
        stats = anids.get_statistics()

        # Blacklist sizes
        self.network_blacklist_size.labels(type="ip").set(stats["blacklisted_ips"])
        self.network_blacklist_size.labels(type="mac").set(stats["blacklisted_macs"])

        # Fingerprints
        self.network_fingerprints.set(stats["unique_fingerprints"])

        # Trust scores
        for fp in anids.fingerprints.values():
            self.network_trust_score.observe(fp.trust_score)

    def update_from_cookie_scanner(self, scanner):
        """Update metrics from Cookie Security Scanner"""
        stats = scanner.get_statistics()

        # Blacklist sizes
        self.cookie_blacklist_size.labels(type="name").set(stats["blacklisted_names_count"])
        self.cookie_blacklist_size.labels(type="hash").set(stats["blacklisted_hashes_count"])

    def update_from_security_mesh(self, mesh):
        """Update metrics from Security Mesh"""
        stats = mesh.get_mesh_statistics()

        # Node states
        for state, count in stats["state_distribution"].items():
            self.mesh_nodes_total.labels(state=state).set(count)

        # Policies
        self.mesh_policies_active.set(stats["total_policies"])

        # Shared intelligence
        self.mesh_shared_intelligence.labels(type="blacklist_ips").set(
            stats["shared_blacklist_ips"]
        )
        self.mesh_shared_intelligence.labels(type="blacklist_macs").set(
            stats["shared_blacklist_macs"]
        )
        self.mesh_shared_intelligence.labels(type="threat_signatures").set(
            stats["shared_threat_signatures"]
        )

    def update_from_universal_protection(self, protection):
        """Update metrics from Universal Protection"""
        stats = protection.get_statistics()

        # Per-protector stats
        for interface_type, pstats in stats["protectors"].items():
            # Requests processed
            # Note: Counter increment should happen in real-time, not batch
            pass

    def update_global_score(self, score: float):
        """Update global security score"""
        self.global_security_score.set(score)

    def update_uptime(self):
        """Update system uptime"""
        uptime = time.time() - self.start_time
        self.system_uptime_seconds.set(uptime)

    def set_system_info(self, version: str, platform: str):
        """Set system information"""
        self.system_info.info(
            {
                "version": version,
                "platform": platform,
                "components": "adaptive_ids,cookie_scanner,security_mesh,universal_protection",
            }
        )

    def get_metrics(self) -> bytes:
        """Get metrics in Prometheus format"""
        return generate_latest(self.registry)


# Global metrics instance
_metrics: Optional[SecurityMetrics] = None


def get_metrics(registry: Optional["CollectorRegistry"] = None) -> SecurityMetrics:
    """Get or create global metrics instance"""
    global _metrics
    if _metrics is None:
        _metrics = SecurityMetrics(registry=registry)
        _metrics.set_system_info(version="4.0.0", platform="linux")  # Could be detected
    return _metrics


def update_all_metrics():
    """Update all metrics from all subsystems"""
    from .adaptive_ids import get_adaptive_ids
    from .cookie_scanner import get_cookie_scanner
    from .distributed_mesh import get_security_mesh
    from .universal_protection import get_universal_protection
    from .adaptive_orchestrator import get_orchestrator

    metrics = get_metrics()

    # Update from all systems
    metrics.update_from_adaptive_ids(get_adaptive_ids())
    metrics.update_from_cookie_scanner(get_cookie_scanner())
    metrics.update_from_security_mesh(get_security_mesh())
    metrics.update_from_universal_protection(get_universal_protection())

    # Update global score
    orchestrator = get_orchestrator()
    metrics.update_global_score(orchestrator.get_global_security_score())

    # Update uptime
    metrics.update_uptime()


if __name__ == "__main__":
    if not PROMETHEUS_AVAILABLE:
        print("prometheus_client not installed")
        print("Install: pip install prometheus-client")
    else:
        metrics = get_metrics()
        print("✅ Prometheus metrics initialized")
        print("\nAvailable metrics:")
        print("- ava_security_network_scans_total")
        print("- ava_security_network_threats_detected_total")
        print("- ava_security_cookie_scans_total")
        print("- ava_security_mesh_nodes_total")
        print("- ava_security_global_score")
        print("- ... and more")
