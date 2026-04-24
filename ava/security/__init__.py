"""
AVA Security Module - Adaptive Security Platform v4.0

SELBST-LERNEND • ADAPTIV • DISTRIBUTED • UNIVERSAL

Security Platform v3.0:
- Threat Intelligence (ML anomaly detection)
- Zero Trust Network Access
- Incident Response (automated playbooks)
- Network Defense (IDS/IPS)
- Security Orchestration

Adaptive Security v4.0:
- Adaptive Network IDS (self-learning)
- Cookie Security Scanner
- Distributed Security Mesh
- Universal Interface Protection
- Adaptive Orchestrator
"""

# Import Security Platform v3.0 components
try:
    from .threat_intelligence import get_threat_intelligence, ThreatIntelligence  # noqa: F401
    from .zero_trust import ZeroTrustEngine  # noqa: F401
    from .incident_response import (  # noqa: F401
        get_incident_response_system,
        IncidentResponseSystem,
    )
    from .network_defense import get_defense_engine, NetworkDefenseEngine  # noqa: F401
    from .orchestrator import get_orchestrator, SecurityOrchestrator  # noqa: F401

    SECURITY_V3_AVAILABLE = True
except ImportError as e:
    import warnings

    warnings.warn(f"Security Platform v3.0 modules not available: {e}")
    SECURITY_V3_AVAILABLE = False

# Import Adaptive Security v4.0 components
try:
    from .adaptive_ids import get_adaptive_ids, AdaptiveNetworkIDS  # noqa: F401
    from .cookie_scanner import get_cookie_scanner, CookieSecurityScanner, Cookie  # noqa: F401
    from .distributed_mesh import get_security_mesh, DistributedSecurityMesh, NodeType  # noqa: F401
    from .universal_protection import (  # noqa: F401
        get_universal_protection,
        UniversalProtectionLayer,
    )
    from .adaptive_orchestrator import (  # noqa: F401
        get_orchestrator as get_adaptive_orchestrator,
        AdaptiveSecurityOrchestrator,
    )
    from .windows_lab import get_windows_lab, WindowsSecurityLab  # noqa: F401
    from .metrics import get_metrics, SecurityMetrics  # noqa: F401
    from .metrics_server import MetricsServer, run_metrics_server  # noqa: F401

    ADAPTIVE_V4_AVAILABLE = True
except ImportError as e:
    import warnings

    warnings.warn(f"Adaptive Security v4.0 modules not available: {e}")
    ADAPTIVE_V4_AVAILABLE = False

# Build __all__ based on what's available
__all__ = []

if SECURITY_V3_AVAILABLE:
    __all__.extend(
        [
            "get_threat_intelligence",
            "ThreatIntelligence",
            "ZeroTrustEngine",
            "get_incident_response_system",
            "IncidentResponseSystem",
            "get_defense_engine",
            "NetworkDefenseEngine",
            "get_orchestrator",
            "SecurityOrchestrator",
        ]
    )

if ADAPTIVE_V4_AVAILABLE:
    __all__.extend(
        [
            "get_adaptive_ids",
            "AdaptiveNetworkIDS",
            "get_cookie_scanner",
            "CookieSecurityScanner",
            "Cookie",
            "get_security_mesh",
            "DistributedSecurityMesh",
            "NodeType",
            "get_universal_protection",
            "UniversalProtectionLayer",
            "get_adaptive_orchestrator",
            "AdaptiveSecurityOrchestrator",
        ]
    )

# Import core auth/security primitives (from former ava/security.py)
from .auth import (  # noqa: F401
    ThreatLog,
    ThreatLevel,
    SecurityLevel,
    SecurityValidator,
    RateLimiter,
    SECURITY_HEADERS,
    ADMIN_API_KEYS,
    OWNER_USERNAME,
    OWNER_EMAIL,
    OWNER_PASSWORD_HASH,
    threat_log,
    rate_limiter,
)

# Version info
__version__ = "4.0.0"
__platform_version__ = "3.0.0" if SECURITY_V3_AVAILABLE else None
__adaptive_version__ = "4.0.0" if ADAPTIVE_V4_AVAILABLE else None
