"""
AVA Security Middleware - Защита системы
Nur Devito hat Zugriff. Alle Zugriffe werden protokolliert.
"""

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
import logging
from datetime import datetime
import csv
import io

from ava.security import (
    threat_log,
    rate_limiter,
    SECURITY_HEADERS,
    ThreatLevel
)

logger = logging.getLogger(__name__)

class SecurityMiddleware(BaseHTTPMiddleware):
    """Sicherheits-Middleware für alle Requests"""
    
    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        endpoint = request.url.path
        timestamp = datetime.now().isoformat()
        
        # 1. IP-Blockierung prüfen
        if threat_log.is_ip_blocked(client_ip):
            logger.critical(f"🔒 BLOCKED {client_ip} trying to access {endpoint}")
            return JSONResponse(
                status_code=403,
                content={
                    "error": "Zugriff verweigert",
                    "reason": "Diese IP-Adresse ist blockiert",
                    "timestamp": timestamp
                },
                headers=SECURITY_HEADERS
            )
        
        # 2. Rate Limiting prüfen
        if not rate_limiter.is_allowed(client_ip):
            threat_log.log_threat(
                client_ip,
                endpoint,
                ThreatLevel.WARNING,
                "Rate limit exceeded",
                request.headers.get("user-agent")
            )
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Too many requests",
                    "reason": "Rate limit überschritten",
                    "timestamp": timestamp
                },
                headers=SECURITY_HEADERS
            )
        
        # 3. Request ausführen
        response = await call_next(request)
        
        # 4. Security Headers hinzufügen
        for header, value in SECURITY_HEADERS.items():
            response.headers[header] = value
        
        # 5. Alle Requests protokollieren
        logger.info(f"📝 {request.method} {endpoint} - {client_ip} - Status: {response.status_code}")
        
        return response

def apply_security_middleware(app: FastAPI) -> None:
    """Wende Security-Middleware auf FastAPI-App an"""
    app.add_middleware(SecurityMiddleware)
    
    # Custom exception handlers
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        client_ip = request.client.host if request.client else "unknown"
        
        # Protokolliere Fehler
        threat_log.log_threat(
            client_ip,
            str(request.url),
            ThreatLevel.CRITICAL,
            f"System error: {str(exc)}",
            request.headers.get("user-agent")
        )
        
        logger.error(f"🔴 SYSTEM ERROR: {str(exc)}")
        
        return JSONResponse(
            status_code=500,
            content={
                "error": "Internal Server Error",
                "timestamp": datetime.now().isoformat()
            },
            headers=SECURITY_HEADERS
        )

# ============================================================================
# AUDIT LOGGING
# ============================================================================

class AuditLogger:
    """Protokolliert alle wichtigen Aktionen"""
    
    def __init__(self):
        self.audit_log = []
    
    def log_action(self, 
                   user: str,
                   action: str,
                   resource: str,
                   status: str,
                   details: dict = None):
        """Protokolliere Admin-Aktion"""
        
        record = {
            "timestamp": datetime.now().isoformat(),
            "user": user,
            "action": action,
            "resource": resource,
            "status": status,
            "details": details or {}
        }
        
        self.audit_log.append(record)
        logger.info(f"📋 AUDIT: {user} - {action} - {resource} - {status}")
    
    def get_audit_log(self, limit: int = 100) -> list:
        """Gebe Audit-Log zurück"""
        return self.audit_log[-limit:]

    def export_csv(self) -> str:
        """Export audit log as CSV string."""
        output = io.StringIO()
        fieldnames = ["timestamp", "user", "action", "resource", "status", "details"]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for record in self.audit_log:
            writer.writerow(
                {
                    "timestamp": record.get("timestamp"),
                    "user": record.get("user"),
                    "action": record.get("action"),
                    "resource": record.get("resource"),
                    "status": record.get("status"),
                    "details": record.get("details")
                }
            )
        return output.getvalue()

audit_logger = AuditLogger()

# ============================================================================
# EXPORT
# ============================================================================

__all__ = [
    "SecurityMiddleware",
    "apply_security_middleware",
    "audit_logger",
    "AuditLogger"
]
