"""
AVA Security API - REST endpoints for security monitoring
Integrates Windows/Linux security monitoring into AVA
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Dict, List, Optional
import logging

try:
    from ava.security.windows_monitor import SecurityMonitor

    SECURITY_AVAILABLE = True
except ImportError:
    SECURITY_AVAILABLE = False

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/security", tags=["security"])

# Global security monitor instance
if SECURITY_AVAILABLE:
    security_monitor = SecurityMonitor()
else:
    security_monitor = None


class SecurityScanResponse(BaseModel):
    """Security scan response."""

    timestamp: str
    platform: str
    alerts: List[Dict]
    status: Dict


class SecurityAction(BaseModel):
    """Security action request."""

    action: str  # "scan", "disable_rdp", "kill_process"
    params: Optional[Dict] = None


@router.get("/status")
async def get_security_status() -> Dict:
    """Get current security status."""
    if not SECURITY_AVAILABLE:
        raise HTTPException(
            status_code=501, detail="Security monitoring not available on this platform"
        )

    try:
        if security_monitor.platform == "Windows":
            status = security_monitor.windows_monitor.get_security_status()
        else:
            status = security_monitor._get_unix_security_status()

        return {"success": True, "data": status}
    except Exception as e:
        logger.error(f"Error getting security status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/scan")
async def run_security_scan(background_tasks: BackgroundTasks) -> SecurityScanResponse:
    """Run comprehensive security scan."""
    if not SECURITY_AVAILABLE:
        raise HTTPException(status_code=501, detail="Security monitoring not available")

    try:
        results = security_monitor.run_security_scan()

        # Log alerts in background
        if results["alerts"]:
            background_tasks.add_task(log_security_alerts, results["alerts"])

        return SecurityScanResponse(**results)

    except Exception as e:
        logger.error(f"Error running security scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/action")
async def execute_security_action(action: SecurityAction) -> Dict:
    """Execute security action."""
    if not SECURITY_AVAILABLE:
        raise HTTPException(status_code=501, detail="Security features not available")

    if security_monitor.platform != "Windows":
        raise HTTPException(status_code=400, detail="This action is only available on Windows")

    try:
        if action.action == "disable_rdp":
            success = security_monitor.windows_monitor.disable_rdp()
            return {
                "success": success,
                "message": "RDP disabled" if success else "Failed to disable RDP",
            }

        elif action.action == "kill_process":
            if not action.params or "pid" not in action.params:
                raise HTTPException(status_code=400, detail="Parameter 'pid' required")

            pid = action.params["pid"]
            success = security_monitor.windows_monitor.kill_blocked_process(pid)
            return {
                "success": success,
                "message": f"Process {pid} terminated" if success else f"Failed to kill {pid}",
            }

        elif action.action == "check_processes":
            alerts = security_monitor.windows_monitor.check_blocked_processes()
            return {"success": True, "alerts": alerts, "count": len(alerts)}

        else:
            raise HTTPException(status_code=400, detail=f"Unknown action: {action.action}")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error executing action: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/alerts")
async def get_recent_alerts(limit: int = 50) -> Dict:
    """Get recent security alerts."""
    if not SECURITY_AVAILABLE:
        raise HTTPException(status_code=501, detail="Security monitoring not available")

    try:
        # Check for blocked processes
        alerts = []
        if security_monitor.platform == "Windows":
            alerts = security_monitor.windows_monitor.check_blocked_processes()

        return {"success": True, "count": len(alerts), "alerts": alerts[:limit]}

    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def log_security_alerts(alerts: List[Dict]):
    """Background task to log security alerts."""
    for alert in alerts:
        logger.warning(f"Security Alert: {alert['type']} - {alert['name']} [PID: {alert['pid']}]")


# Health check for security module
@router.get("/health")
async def security_health() -> Dict:
    """Health check for security monitoring."""
    return {
        "available": SECURITY_AVAILABLE,
        "platform": security_monitor.platform if SECURITY_AVAILABLE else None,
        "windows_features": security_monitor.platform == "Windows" if SECURITY_AVAILABLE else False,
    }
