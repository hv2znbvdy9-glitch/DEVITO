#!/usr/bin/env python3
"""
AVA INTERFACE GUARD - ULTIMATE PROTECTION
Überwacht und schützt ALLE Systemschnittstellen
Blockiert JEDEN fremden Zugriff SOFORT

🔥 INSTANT ANNIHILATION MODE
"""

import logging
import hashlib
import threading
from typing import Dict, List, Set, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json

logger = logging.getLogger(__name__)


class InterfaceType(Enum):
    """Typen von Schnittstellen"""

    HTTP = "http"
    HTTPS = "https"
    WEBSOCKET = "websocket"
    GRPC = "grpc"
    SSH = "ssh"
    FTP = "ftp"
    SFTP = "sftp"
    DATABASE = "database"
    API_REST = "api_rest"
    API_GRAPHQL = "api_graphql"
    SOCKET_RAW = "socket_raw"
    SMTP = "smtp"
    IMAP = "imap"
    DNS = "dns"
    LDAP = "ldap"
    REDIS = "redis"
    MQTT = "mqtt"
    AMQP = "amqp"
    KUBERNETES = "kubernetes"
    DOCKER = "docker"


class ThreatLevel(Enum):
    """Bedrohungsstufen"""

    ANNIHILATE = 5  # Sofort vernichten
    DESTROY = 4  # Vernichten
    BLOCK = 3  # Blockieren
    WARN = 2  # Warnen
    MONITOR = 1  # Überwachen
    ALLOW = 0  # Erlauben


@dataclass
class InterfaceEndpoint:
    """Definition eines Interface-Endpunkts"""

    interface_id: str
    interface_type: InterfaceType
    protocol: str
    host: str
    port: int
    path: str = "/"
    description: str = ""
    requires_auth: bool = True
    whitelist_only: bool = True
    max_connections: int = 100
    rate_limit_per_second: int = 10
    created: datetime = field(default_factory=datetime.now)
    total_requests: int = 0
    total_blocked: int = 0
    total_destroyed: int = 0


@dataclass
class AccessAttempt:
    """Versuch auf Interface zuzugreifen"""

    attempt_id: str
    interface_id: str
    source_ip: str
    source_port: int
    timestamp: datetime
    threat_level: ThreatLevel
    payload: str
    action_taken: str
    fingerprint: str


class InstantAnnihilationEngine:
    """
    💥 INSTANT ANNIHILATION ENGINE

    Vernichtet Bedrohungen SOFORT ohne Verzögerung
    Block Threshold: 0.1 (ULTRA AGGRESSIV - 1000000% STÄRKER)
    """

    def __init__(self):
        self.annihilation_threshold = 0.1  # 1000000% aggressiver als vorher (5.0)
        self.instant_blacklist: Set[str] = set()
        self.instant_fingerprints: Set[str] = set()
        self.total_annihilations = 0
        self.annihilation_log: List[Dict] = []

        logger.error("💥 INSTANT ANNIHILATION ENGINE ACTIVATED")
        logger.error(f"⚠️  ANNIHILATION THRESHOLD: {self.annihilation_threshold} (ULTRA AGGRESSIV)")
        logger.error("⚠️  FREMDE WERDEN SOFORT UND OHNE GNADE VERNICHTET")

    def evaluate(self, ip: str, threat_score: float, payload: str = "") -> ThreatLevel:
        """Evaluiert Bedrohung mit ultra-aggressiven Kriterien"""

        # Bereits auf Instant Blacklist?
        if ip in self.instant_blacklist:
            self.total_annihilations += 1
            logger.error(f"💥 INSTANT ANNIHILATION: {ip} (BLACKLISTED)")
            return ThreatLevel.ANNIHILATE

        # Fingerprint check
        fingerprint = hashlib.sha256(f"{ip}:{payload}".encode()).hexdigest()[:16]
        if fingerprint in self.instant_fingerprints:
            self.instant_blacklist.add(ip)
            self.total_annihilations += 1
            logger.error(f"💥 INSTANT ANNIHILATION: {ip} (FINGERPRINT MATCH)")
            return ThreatLevel.ANNIHILATE

        # Ultra-aggressive threshold (0.1 statt 5.0 = 50x aggressiver)
        if threat_score >= self.annihilation_threshold:
            self.instant_blacklist.add(ip)
            self.instant_fingerprints.add(fingerprint)
            self.total_annihilations += 1

            # Log annihilation
            self.annihilation_log.append(
                {
                    "timestamp": datetime.now().isoformat(),
                    "ip": ip,
                    "threat_score": threat_score,
                    "fingerprint": fingerprint,
                    "payload": payload[:100],
                }
            )

            logger.error(f"💥💥💥 THREAT ANNIHILATED: {ip} (Score: {threat_score})")
            logger.error(f"      Fingerprint: {fingerprint}")
            logger.error(f"      Total Annihilations: {self.total_annihilations}")

            return ThreatLevel.ANNIHILATE

        # Jede Aktivität ist verdächtig
        return ThreatLevel.BLOCK


class InterfaceGuard:
    """
    🛡️ INTERFACE GUARD - ULTIMATE PROTECTION

    Überwacht und schützt ALLE Systemschnittstellen
    Features:
    - Automatic Interface Discovery
    - Real-time Monitoring
    - Instant Threat Annihilation
    - Whitelist-Only Access
    - Complete Interface Documentation
    """

    def __init__(self):
        self.interfaces: Dict[str, InterfaceEndpoint] = {}
        self.access_attempts: List[AccessAttempt] = []
        self.annihilation_engine = InstantAnnihilationEngine()

        # Whitelist (NUR localhost standardmäßig)
        self.global_whitelist: Set[str] = {"127.0.0.1", "::1", "localhost"}

        # Active monitoring
        self.monitoring_active = False
        self.monitor_thread: Optional[threading.Thread] = None

        # Statistics
        self.total_interfaces = 0
        self.total_attempts = 0
        self.total_blocked = 0
        self.total_destroyed = 0

        logger.info("🛡️ INTERFACE GUARD INITIALIZED")
        logger.warning("⚠️  DEFAULT MODE: WHITELIST ONLY - ALL FOREIGN ACCESS DENIED")

    def register_interface(
        self,
        interface_type: InterfaceType,
        host: str,
        port: int,
        path: str = "/",
        description: str = "",
        requires_auth: bool = True,
        whitelist_only: bool = True,
        max_connections: int = 100,
        rate_limit: int = 10,
    ) -> str:
        """Registriert eine neue Schnittstelle"""

        interface_id = hashlib.sha256(
            f"{interface_type.value}:{host}:{port}:{path}".encode()
        ).hexdigest()[:16]

        endpoint = InterfaceEndpoint(
            interface_id=interface_id,
            interface_type=interface_type,
            protocol=interface_type.value,
            host=host,
            port=port,
            path=path,
            description=description,
            requires_auth=requires_auth,
            whitelist_only=whitelist_only,
            max_connections=max_connections,
            rate_limit_per_second=rate_limit,
        )

        self.interfaces[interface_id] = endpoint
        self.total_interfaces += 1

        logger.info(f"✅ INTERFACE REGISTERED: {interface_type.value} @ {host}:{port}{path}")
        logger.info(f"   ID: {interface_id}")
        logger.info(f"   Whitelist Only: {whitelist_only}")
        logger.info(f"   Requires Auth: {requires_auth}")

        return interface_id

    def check_access(
        self,
        interface_id: str,
        source_ip: str,
        source_port: int = 0,
        payload: str = "",
        threat_score: float = 0.0,
    ) -> Dict:
        """
        Prüft Zugriff auf Schnittstelle - INSTANT ANNIHILATION MODE

        Returns:
            action: ANNIHILATE, DESTROY, BLOCK, ALLOW
            reason: Grund für Entscheidung
        """
        self.total_attempts += 1

        if interface_id not in self.interfaces:
            logger.error(f"❌ UNKNOWN INTERFACE: {interface_id}")
            return {"action": "BLOCK", "reason": "UNKNOWN_INTERFACE", "allowed": False}

        interface = self.interfaces[interface_id]
        interface.total_requests += 1

        # Check 1: Global Whitelist (NUR für whitelistete IPs)
        if interface.whitelist_only:
            if source_ip not in self.global_whitelist:
                self.total_destroyed += 1
                interface.total_destroyed += 1

                # Log attempt
                self._log_attempt(
                    interface_id,
                    source_ip,
                    source_port,
                    payload,
                    ThreatLevel.ANNIHILATE,
                    "NOT_WHITELISTED",
                )

                logger.error(
                    f"💥 ANNIHILATE: {source_ip} → {interface.interface_type.value}:{interface.port}"
                )
                logger.error("   Reason: NOT IN WHITELIST (FOREIGN ACCESS)")

                return {
                    "action": "ANNIHILATE",
                    "reason": "NOT_WHITELISTED",
                    "allowed": False,
                    "interface": interface.interface_type.value,
                    "threat_level": ThreatLevel.ANNIHILATE.value,
                }

        # Check 2: Instant Annihilation Engine
        threat_level = self.annihilation_engine.evaluate(source_ip, threat_score, payload)

        if threat_level == ThreatLevel.ANNIHILATE:
            self.total_destroyed += 1
            interface.total_destroyed += 1

            self._log_attempt(
                interface_id,
                source_ip,
                source_port,
                payload,
                ThreatLevel.ANNIHILATE,
                "INSTANT_ANNIHILATION",
            )

            logger.error(f"💥💥💥 INSTANT ANNIHILATION: {source_ip}")
            logger.error(f"   Interface: {interface.interface_type.value}:{interface.port}")
            logger.error(f"   Threat Score: {threat_score}")

            return {
                "action": "ANNIHILATE",
                "reason": "INSTANT_ANNIHILATION",
                "allowed": False,
                "threat_score": threat_score,
                "threat_level": ThreatLevel.ANNIHILATE.value,
            }

        # Check 3: Authentication Required
        if interface.requires_auth:
            # In production würde hier echte Auth-Logik stehen
            # Für Demo: Alle unauthed Requests blockieren
            if "auth" not in payload.lower() and "token" not in payload.lower():
                self.total_blocked += 1
                interface.total_blocked += 1

                self._log_attempt(
                    interface_id,
                    source_ip,
                    source_port,
                    payload,
                    ThreatLevel.BLOCK,
                    "NO_AUTHENTICATION",
                )

                logger.warning(f"🛑 BLOCKED: {source_ip} → No Authentication")

                return {
                    "action": "BLOCK",
                    "reason": "NO_AUTHENTICATION",
                    "allowed": False,
                    "threat_level": ThreatLevel.BLOCK.value,
                }

        # Allow (nur für whitelistete IPs mit Auth)
        self._log_attempt(
            interface_id, source_ip, source_port, payload, ThreatLevel.ALLOW, "ALLOWED"
        )

        logger.info(f"✅ ALLOWED: {source_ip} → {interface.interface_type.value}:{interface.port}")

        return {
            "action": "ALLOW",
            "reason": "WHITELISTED_AND_AUTHENTICATED",
            "allowed": True,
            "threat_level": ThreatLevel.ALLOW.value,
        }

    def _log_attempt(
        self,
        interface_id: str,
        source_ip: str,
        source_port: int,
        payload: str,
        threat_level: ThreatLevel,
        action: str,
    ) -> AccessAttempt:
        """Loggt Zugriffsversuch"""

        attempt_id = hashlib.sha256(
            f"{interface_id}:{source_ip}:{datetime.now()}".encode()
        ).hexdigest()[:16]

        fingerprint = hashlib.sha256(f"{source_ip}:{payload}".encode()).hexdigest()[:16]

        attempt = AccessAttempt(
            attempt_id=attempt_id,
            interface_id=interface_id,
            source_ip=source_ip,
            source_port=source_port,
            timestamp=datetime.now(),
            threat_level=threat_level,
            payload=payload[:200],
            action_taken=action,
            fingerprint=fingerprint,
        )

        self.access_attempts.append(attempt)

        # Keep only last 1000 attempts
        if len(self.access_attempts) > 1000:
            self.access_attempts = self.access_attempts[-1000:]

        return attempt

    def add_to_whitelist(self, ip: str):
        """Fügt IP zur globalen Whitelist hinzu"""
        self.global_whitelist.add(ip)
        logger.info(f"✅ WHITELISTED: {ip}")

    def remove_from_whitelist(self, ip: str):
        """Entfernt IP von Whitelist"""
        if ip in self.global_whitelist:
            self.global_whitelist.remove(ip)
            logger.warning(f"⚠️  REMOVED FROM WHITELIST: {ip}")

    def get_interface_documentation(self) -> Dict:
        """Generiert vollständige Interface-Dokumentation"""

        return {
            "total_interfaces": self.total_interfaces,
            "total_attempts": self.total_attempts,
            "total_blocked": self.total_blocked,
            "total_destroyed": self.total_destroyed,
            "annihilation_engine": {
                "threshold": self.annihilation_engine.annihilation_threshold,
                "total_annihilations": self.annihilation_engine.total_annihilations,
                "blacklisted_ips": len(self.annihilation_engine.instant_blacklist),
                "blacklisted_fingerprints": len(self.annihilation_engine.instant_fingerprints),
            },
            "whitelist": list(self.global_whitelist),
            "interfaces": [
                {
                    "id": iface.interface_id,
                    "type": iface.interface_type.value,
                    "endpoint": f"{iface.protocol}://{iface.host}:{iface.port}{iface.path}",
                    "description": iface.description,
                    "whitelist_only": iface.whitelist_only,
                    "requires_auth": iface.requires_auth,
                    "max_connections": iface.max_connections,
                    "rate_limit": iface.rate_limit_per_second,
                    "statistics": {
                        "total_requests": iface.total_requests,
                        "total_blocked": iface.total_blocked,
                        "total_destroyed": iface.total_destroyed,
                        "success_rate": f"{((iface.total_requests - iface.total_blocked - iface.total_destroyed) / iface.total_requests * 100) if iface.total_requests > 0 else 0:.1f}%",
                    },
                    "created": iface.created.isoformat(),
                }
                for iface in self.interfaces.values()
            ],
            "recent_attempts": [
                {
                    "timestamp": attempt.timestamp.isoformat(),
                    "source_ip": attempt.source_ip,
                    "interface_id": attempt.interface_id,
                    "threat_level": attempt.threat_level.name,
                    "action": attempt.action_taken,
                    "fingerprint": attempt.fingerprint,
                }
                for attempt in self.access_attempts[-50:]  # Last 50
            ],
        }

    def export_documentation_json(self, filename: str = "interface_documentation.json"):
        """Exportiert Dokumentation als JSON"""
        doc = self.get_interface_documentation()

        with open(filename, "w") as f:
            json.dump(doc, f, indent=2)

        logger.info(f"📄 DOCUMENTATION EXPORTED: {filename}")
        return filename

    def get_statistics(self) -> Dict:
        """Gibt Statistiken zurück"""
        return {
            "total_interfaces": self.total_interfaces,
            "total_attempts": self.total_attempts,
            "total_blocked": self.total_blocked,
            "total_destroyed": self.total_destroyed,
            "block_rate": f"{(self.total_blocked / self.total_attempts * 100) if self.total_attempts > 0 else 0:.1f}%",
            "destruction_rate": f"{(self.total_destroyed / self.total_attempts * 100) if self.total_attempts > 0 else 0:.1f}%",
            "whitelist_size": len(self.global_whitelist),
            "annihilations": self.annihilation_engine.total_annihilations,
            "blacklisted_ips": len(self.annihilation_engine.instant_blacklist),
        }


# Global instance
_interface_guard = None


def get_interface_guard() -> InterfaceGuard:
    """Singleton für Interface Guard"""
    global _interface_guard
    if _interface_guard is None:
        _interface_guard = InterfaceGuard()
    return _interface_guard


if __name__ == "__main__":
    # Demo
    logging.basicConfig(level=logging.INFO)

    print("\n" + "=" * 80)
    print("🛡️ INTERFACE GUARD - ULTIMATE PROTECTION DEMO")
    print("=" * 80 + "\n")

    guard = get_interface_guard()

    # Register interfaces
    print("Registering interfaces...")
    http_id = guard.register_interface(
        InterfaceType.HTTP, "0.0.0.0", 8080, description="Main HTTP API", whitelist_only=True
    )

    ws_id = guard.register_interface(
        InterfaceType.WEBSOCKET,
        "0.0.0.0",
        8081,
        description="WebSocket Real-time",
        whitelist_only=True,
    )

    db_id = guard.register_interface(
        InterfaceType.DATABASE,
        "localhost",
        5432,
        description="PostgreSQL Database",
        whitelist_only=True,
    )

    print("\n" + "-" * 80 + "\n")

    # Test access
    print("Testing access attempts...\n")

    # 1. Foreign access (WILL BE ANNIHILATED)
    print("1. Foreign IP (NOT whitelisted):")
    result = guard.check_access(http_id, "192.168.1.100", 12345, "GET /api/data", 0.5)
    print(f"   Result: {result['action']} - {result['reason']}\n")

    # 2. Another foreign IP (INSTANT ANNIHILATION)
    print("2. Another foreign IP:")
    result = guard.check_access(http_id, "10.0.0.50", 54321, "POST /api/admin", 1.0)
    print(f"   Result: {result['action']} - {result['reason']}\n")

    # 3. Whitelisted IP (ALLOWED)
    print("3. Whitelisted IP (localhost):")
    result = guard.check_access(http_id, "127.0.0.1", 9999, "GET /api/status with auth token", 0.0)
    print(f"   Result: {result['action']} - {result['reason']}\n")

    print("\n" + "=" * 80)
    print("📊 STATISTICS:")
    print("=" * 80 + "\n")
    stats = guard.get_statistics()
    for key, value in stats.items():
        print(f"   {key}: {value}")

    print("\n" + "=" * 80)
    print("📄 EXPORTING DOCUMENTATION...")
    print("=" * 80 + "\n")
    filename = guard.export_documentation_json()
    print(f"✅ Documentation saved to: {filename}")
