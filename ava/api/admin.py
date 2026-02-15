"""
AVA Admin Console - Nur für Devito
Sicherheitskontrolle, Threat Management, Audit Logs
"""

from fastapi import APIRouter, Request, Header, HTTPException
from fastapi.responses import HTMLResponse, Response
from typing import Optional
from datetime import datetime
from pydantic import BaseModel, Field
import html as html_mod
from ipaddress import ip_address as parse_ip_address, AddressValueError

from ava.security import (
    SecurityValidator,
    threat_log,
    OWNER_USERNAME,
    ThreatLevel,
    ADMIN_API_KEYS,
    rate_limiter
)
from ava.security_middleware import audit_logger

admin_router = APIRouter(prefix="/api/admin", tags=["admin"])
admin_page_router = APIRouter(tags=["admin"])

# ============================================================================
# MODELS
# ============================================================================

class AdminLoginRequest(BaseModel):
    username: str
    password: str

class IPBlockRequest(BaseModel):
    ip: str
    duration_minutes: int = Field(default=1440, ge=1, le=10080)

class ApiKeyRequest(BaseModel):
    name: str
    expires_days: Optional[int] = None

class ThreatReportResponse(BaseModel):
    total_threats: int
    blocked_ips: int
    recent_threats: list

class RateLimitRequest(BaseModel):
    max_requests: int
    window_seconds: int

# ============================================================================
# ADMIN AUTHENTICATION
# ============================================================================

@admin_router.post("/login")
async def admin_login(request: AdminLoginRequest):
    """Nur Devito kann sich einloggen"""
    
    if request.username != OWNER_USERNAME:
        threat_log.log_threat(
            "unknown",
            "/api/admin/login",
            ThreatLevel.WARNING,
            f"Invalid login: {request.username}"
        )
        raise HTTPException(status_code=401, detail="Ungültige Anmeldedaten")
    
    if not SecurityValidator.validate_owner_password(request.password):
        threat_log.log_threat(
            "unknown",
            "/api/admin/login",
            ThreatLevel.CRITICAL,
            f"Wrong password attempt for {request.username}"
        )
        raise HTTPException(status_code=401, detail="Ungültige Anmeldedaten")
    
    audit_logger.log_action(
        OWNER_USERNAME,
        "LOGIN",
        "admin_console",
        "SUCCESS"
    )
    
    return {
        "status": "success",
        "message": f"Willkommen {OWNER_USERNAME}!",
        "timestamp": datetime.now().isoformat()
    }

# ============================================================================
# THREAT MANAGEMENT
# ============================================================================

@admin_router.get("/threats")
async def get_threats(request: Request, api_key: Optional[str] = Header(None)):
    """Zeige Threat-Report"""
    
    SecurityValidator.check_admin_access(request=request, api_key=api_key)
    
    report = threat_log.get_threat_report()
    
    audit_logger.log_action(
        OWNER_USERNAME,
        "VIEW",
        "threat_report",
        "SUCCESS"
    )
    
    return {
        "timestamp": datetime.now().isoformat(),
        "report": report
    }

@admin_router.post("/block-ip")
async def block_ip(
    request: Request,
    block_request: IPBlockRequest,
    api_key: Optional[str] = Header(None)
):
    """Blockiere eine IP-Adresse"""
    
    SecurityValidator.check_admin_access(request, api_key)

    try:
        parse_ip_address(block_request.ip)
    except (AddressValueError, ValueError):
        raise HTTPException(status_code=400, detail="Ung\u00fcltige IP-Adresse")

    threat_log.block_ip(block_request.ip, block_request.duration_minutes)
    
    audit_logger.log_action(
        OWNER_USERNAME,
        "BLOCK_IP",
        block_request.ip,
        "SUCCESS",
        {"duration_minutes": block_request.duration_minutes}
    )
    
    return {
        "status": "success",
        "message": f"IP {block_request.ip} wurde blockiert",
        "duration_minutes": block_request.duration_minutes,
        "timestamp": datetime.now().isoformat()
    }

@admin_router.get("/blocked-ips")
async def get_blocked_ips(request: Request, api_key: Optional[str] = Header(None)):
    """Zeige alle blockierten IPs"""
    
    SecurityValidator.check_admin_access(request=request, api_key=api_key)
    
    blocked_ips = [
        {
            "ip": ip,
            "blocked_until": expires.isoformat()
        }
        for ip, expires in threat_log.blocked_ips.items()
    ]
    
    return {
        "count": len(blocked_ips),
        "blocked_ips": blocked_ips,
        "timestamp": datetime.now().isoformat()
    }

# ============================================================================
# API KEY MANAGEMENT
# ============================================================================

@admin_router.get("/api-keys")
async def list_api_keys(request: Request, api_key: Optional[str] = Header(None)):
    """Zeige alle API-Keys (nur für Admin)"""
    
    SecurityValidator.check_admin_access(request=request, api_key=api_key)
    
    keys = []
    for key, data in ADMIN_API_KEYS.items():
        keys.append({
            "key": f"{key[:10]}...",  # Nur Anfang anzeigen
            "owner": data["owner"],
            "active": data["active"],
            "created": data["created"],
            "expires": data.get("expires")
        })
    
    audit_logger.log_action(
        OWNER_USERNAME,
        "VIEW",
        "api_keys",
        "SUCCESS"
    )
    
    return {
        "count": len(keys),
        "api_keys": keys
    }

@admin_router.post("/api-keys/revoke")
async def revoke_api_key(
    request: Request,
    api_key_to_revoke: str,
    api_key: Optional[str] = Header(None)
):
    """Deaktiviere einen API-Key"""
    
    SecurityValidator.check_admin_access(request=request, api_key=api_key)
    
    if api_key_to_revoke not in ADMIN_API_KEYS:
        raise HTTPException(status_code=404, detail="API-Key nicht gefunden")
    
    ADMIN_API_KEYS[api_key_to_revoke]["active"] = False
    
    audit_logger.log_action(
        OWNER_USERNAME,
        "REVOKE_API_KEY",
        api_key_to_revoke[:10],
        "SUCCESS"
    )
    
    return {
        "status": "success",
        "message": f"API-Key wurde deaktiviert",
        "timestamp": datetime.now().isoformat()
    }

# ============================================================================
# AUDIT LOGS
# ============================================================================

@admin_router.get("/audit-log")
async def get_audit_log(
    request: Request,
    limit: int = 100,
    api_key: Optional[str] = Header(None)
):
    """Zeige Audit-Log"""
    
    SecurityValidator.check_admin_access(request=request, api_key=api_key)
    
    logs = audit_logger.get_audit_log(limit)
    
    return {
        "count": len(logs),
        "logs": logs,
        "timestamp": datetime.now().isoformat()
    }

# ============================================================================
# SYSTEM STATUS
# ============================================================================

@admin_router.get("/status")
async def admin_status(request: Request, api_key: Optional[str] = Header(None)):
    """System-Status (nur Admin)"""
    
    SecurityValidator.check_admin_access(request=request, api_key=api_key)
    
    return {
        "system": "AVA Wellbeing System",
        "owner": OWNER_USERNAME,
        "status": "SECURE",
        "security_level": "MAXIMUM",
        "threat_log_entries": len(threat_log.threats),
        "blocked_ips": len(threat_log.blocked_ips),
        "timestamp": datetime.now().isoformat()
    }

# ============================================================================
# EXPORT
# ============================================================================

@admin_router.post("/rate-limit")
async def update_rate_limit(
    request: Request,
    config: RateLimitRequest,
    api_key: Optional[str] = Header(None)
):
    """Update rate limit rules (JSON)."""
    SecurityValidator.check_admin_access(request=request, api_key=api_key)
    try:
        rate_limiter.update_limits(config.max_requests, config.window_seconds)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    audit_logger.log_action(
        OWNER_USERNAME,
        "UPDATE_RATE_LIMIT",
        "rate_limiter",
        "SUCCESS",
        {"max_requests": config.max_requests, "window_seconds": config.window_seconds}
    )

    return {
        "status": "success",
        "max_requests": rate_limiter.max_requests,
        "window_seconds": rate_limiter.window_seconds,
        "timestamp": datetime.now().isoformat()
    }


@admin_page_router.get("/admin", response_class=HTMLResponse)
async def admin_page(request: Request, api_key: Optional[str] = Header(None)):
    """Simple admin landing page (Devito only)."""
    SecurityValidator.check_admin_access(request=request, api_key=api_key)

    content = """<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>AVA Admin Console</title>
  </head>
  <body>
    <h1>AVA Admin Console</h1>
    <p>Owner: Devito</p>
    <p><em>Verwende den API-Key Header f&uuml;r authentifizierte Zugriffe.</em></p>
    <ul>
            <li><a href="/api/admin/status">System Status</a></li>
            <li><a href="/api/admin/threats">Threat Report</a></li>
            <li><a href="/api/admin/audit-log">Audit Log</a></li>
            <li><a href="/audit/export">Audit CSV Export</a></li>
    </ul>
  </body>
</html>
"""

    return HTMLResponse(content=content)


@admin_page_router.get("/audit/export")
async def export_audit_csv(request: Request, api_key: Optional[str] = Header(None)):
    """Export audit log as CSV (Devito only)."""
    SecurityValidator.check_admin_access(request=request, api_key=api_key)

    csv_data = audit_logger.export_csv()
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_log.csv"}
    )

__all__ = ["admin_router", "admin_page_router"]
