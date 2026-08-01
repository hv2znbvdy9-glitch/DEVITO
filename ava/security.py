"""
AVA legacy security module.

This module re-exports the canonical security implementation from
``ava.security.auth`` for backward compatibility. New code should import
from ``ava.security.auth`` directly.
"""

from ava.security.auth import (
    ADMIN_API_KEYS,
    OWNER_EMAIL,
    OWNER_PASSWORD_HASH,
    OWNER_USERNAME,
    RateLimiter,
    SECURITY_HEADERS,
    SecurityLevel,
    SecurityValidator,
    ThreatLevel,
    ThreatLog,
    rate_limiter,
    threat_log,
)

__all__ = [
    "ADMIN_API_KEYS",
    "OWNER_EMAIL",
    "OWNER_PASSWORD_HASH",
    "OWNER_USERNAME",
    "RateLimiter",
    "SECURITY_HEADERS",
    "SecurityLevel",
    "SecurityValidator",
    "ThreatLevel",
    "ThreatLog",
    "rate_limiter",
    "threat_log",
]
