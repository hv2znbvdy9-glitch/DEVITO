"""
AVA Security Module - Admin Protection System
Nur Devito hat Zugriff. Alle anderen werden blockiert & geloggt.
"""

import hashlib
import time
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, List
from fastapi import HTTPException, Request, Header
from enum import Enum

logger = logging.getLogger(__name__)

# ============================================================================
# OWNER CREDENTIALS (DEVITO ONLY)
# ============================================================================

OWNER_USERNAME = "Devito"
OWNER_EMAIL = "devito@ava-system.local"
# Hash des sicheren Passworts (bcrypt würde hier verwendet)
OWNER_PASSWORD_HASH = hashlib.sha256(b"YourSecurePasswordHere_ChangeMe").hexdigest()

# ============================================================================
# SECURITY ADMIN API KEYS (Permanent für Devito)
# ============================================================================

ADMIN_API_KEYS = {
    "devito-master-key-001": {
        "owner": "Devito",
        "permissions": ["*"],  # All permissions
        "created": datetime.now().isoformat(),
        "expires": None,  # Never expires
        "active": True,
    }
}

# ============================================================================
# SECURITY SETTINGS
# ============================================================================


class SecurityLevel(str, Enum):
    PUBLIC = "public"
    AUTHENTICATED = "authenticated"
    ADMIN_ONLY = "admin_only"
    OWNER_ONLY = "owner_only"


class ThreatLevel(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"
    BLOCKED = "blocked"


# ============================================================================
# THREAT DETECTION & LOGGING
# ============================================================================


class ThreatLog:
    """Protokolliert alle Zugriffversuche und verdächtige Aktivitäten"""

    def __init__(self):
        self.threats: List[Dict] = []
        self.blocked_ips: Dict[str, datetime] = {}
        self.failed_attempts: Dict[str, int] = {}

    def log_threat(
        self,
        ip: str,
        endpoint: str,
        threat_level: ThreatLevel,
        reason: str,
        user_agent: Optional[str] = None,
    ):
        """Protokolliere verdächtige Aktivität"""

        timestamp = datetime.now()
        threat_record = {
            "timestamp": timestamp.isoformat(),
            "ip": ip,
            "endpoint": endpoint,
            "threat_level": threat_level,
            "reason": reason,
            "user_agent": user_agent,
        }

        self.threats.append(threat_record)
        logger.warning(f"🚨 THREAT DETECTED: {ip} - {reason}")

        # Bei kritischen Angriffen: IP blockieren
        if threat_level == ThreatLevel.CRITICAL or threat_level == ThreatLevel.BLOCKED:
            self.block_ip(ip, duration_minutes=1440)  # 24 Stunden Blockierung

    def block_ip(self, ip: str, duration_minutes: int = 60):
        """Blockiere eine IP-Adresse"""
        self.blocked_ips[ip] = datetime.now() + timedelta(minutes=duration_minutes)
        logger.critical(f"🔒 IP BLOCKED: {ip} für {duration_minutes} Minuten")

    def is_ip_blocked(self, ip: str) -> bool:
        """Prüfe ob IP blockiert ist"""
        if ip in self.blocked_ips:
            if datetime.now() < self.blocked_ips[ip]:
                return True
            else:
                del self.blocked_ips[ip]
                logger.info(f"✅ IP-Block aufgehoben: {ip}")
        return False

    def get_threat_report(self) -> Dict:
        """Gibt Sicherheitsbericht zurück"""
        return {
            "total_threats": len(self.threats),
            "blocked_ips": len(self.blocked_ips),
            "recent_threats": self.threats[-10:] if self.threats else [],
        }


# Global threat tracking
threat_log = ThreatLog()

# ============================================================================
# AUTHENTIFIZIERUNG & VALIDIERUNG
# ============================================================================


class SecurityValidator:
    """Validiert alle Zugriffe"""

    @staticmethod
    def validate_api_key(api_key: Optional[str]) -> Dict:
        """Validiere API-Key"""
        if not api_key:
            raise HTTPException(status_code=401, detail="API Key erforderlich")

        if api_key not in ADMIN_API_KEYS:
            raise HTTPException(status_code=403, detail="Ungültiger API Key")

        key_data = ADMIN_API_KEYS[api_key]

        if not key_data["active"]:
            raise HTTPException(status_code=403, detail="API Key deaktiviert")

        if key_data["expires"] and datetime.fromisoformat(key_data["expires"]) < datetime.now():
            raise HTTPException(status_code=403, detail="API Key abgelaufen")

        return key_data

    @staticmethod
    def validate_owner_password(password: str) -> bool:
        """Validiere Owner-Passwort"""
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        return password_hash == OWNER_PASSWORD_HASH

    @staticmethod
    def check_admin_access(request: Optional[Request], api_key: Optional[str] = Header(None)):
        """Prüfe Admin-Zugriff"""
        client_ip = request.client.host if request and request.client else "unknown"
        endpoint = str(request.url) if request else "unknown"

        # Prüfe ob IP blockiert ist
        if threat_log.is_ip_blocked(client_ip):
            threat_log.log_threat(client_ip, endpoint, ThreatLevel.BLOCKED, "IP ist blockiert")
            raise HTTPException(status_code=403, detail="Zugriff verweigert")

        # Prüfe API-Key
        try:
            key_data = SecurityValidator.validate_api_key(api_key)
            logger.info(f"✅ Admin-Zugriff authorized: {key_data['owner']} von {client_ip}")
            return key_data
        except HTTPException as e:
            threat_log.log_threat(
                client_ip,
                endpoint,
                ThreatLevel.CRITICAL,
                f"Unauthorized access attempt: {e.detail}",
                request.headers.get("user-agent") if request else None,
            )
            raise


# ============================================================================
# RATE LIMITING
# ============================================================================


class RateLimiter:
    """Verhindert Brute-Force-Attacken"""

    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, List[float]] = {}

    def is_allowed(self, client_id: str) -> bool:
        """Prüfe ob Request erlaubt ist"""
        now = time.time()

        if client_id not in self.requests:
            self.requests[client_id] = []

        # Entferne alte Requests außerhalb des Fensters
        self.requests[client_id] = [
            req_time
            for req_time in self.requests[client_id]
            if now - req_time < self.window_seconds
        ]

        if len(self.requests[client_id]) >= self.max_requests:
            logger.warning(f"🚨 Rate limit exceeded for {client_id}")
            return False

        self.requests[client_id].append(now)
        return True

    def update_limits(self, max_requests: int, window_seconds: int) -> None:
        """Update rate limit settings."""
        if max_requests < 1 or window_seconds < 1:
            raise ValueError("Rate limit values must be positive")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = {}


rate_limiter = RateLimiter(max_requests=100, window_seconds=60)

# ============================================================================
# SECURITY HEADERS & MIDDLEWARE
# ============================================================================

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "Access-Control-Allow-Origin": "http://localhost:3000",
    "Access-Control-Allow-Credentials": "true",
}

# ============================================================================
# EXPORT
# ============================================================================

__all__ = [
    "ThreatLog",
    "SecurityValidator",
    "RateLimiter",
    "SECURITY_HEADERS",
    "threat_log",
    "rate_limiter",
    "ADMIN_API_KEYS",
    "OWNER_USERNAME",
    "ThreatLevel",
    "SecurityLevel",
]
