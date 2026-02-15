"""
AVA Automated Incident Response System (AIRS)
==============================================
Automated detection, containment, and remediation of security incidents.

Response Phases:
1. Detection - Identify security incidents
2. Analysis - Assess severity and scope
3. Containment - Isolate and limit damage
4. Eradication - Remove threat
5. Recovery - Restore normal operations
6. Post-Incident - Lessons learned
"""

import asyncio
import json
import logging
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class IncidentSeverity(Enum):
    """Incident severity levels"""
    INFORMATIONAL = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class IncidentStatus(Enum):
    """Incident lifecycle status"""
    DETECTED = "detected"
    ANALYZING = "analyzing"
    CONTAINED = "contained"
    ERADICATING = "eradicating"
    RECOVERING = "recovering"
    RESOLVED = "resolved"
    CLOSED = "closed"


class ResponseAction(Enum):
    """Automated response actions"""
    BLOCK_IP = "block_ip"
    KILL_PROCESS = "kill_process"
    DISABLE_USER = "disable_user"
    ISOLATE_HOST = "isolate_host"
    ROTATE_CREDENTIALS = "rotate_credentials"
    BACKUP_EVIDENCE = "backup_evidence"
    ALERT_TEAM = "alert_team"
    ROLLBACK_CHANGES = "rollback_changes"
    QUARANTINE_FILE = "quarantine_file"
    PATCH_VULNERABILITY = "patch_vulnerability"


@dataclass
class Incident:
    """Security incident"""
    incident_id: str
    title: str
    description: str
    severity: IncidentSeverity
    status: IncidentStatus = IncidentStatus.DETECTED
    detected_at: datetime = field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None
    affected_assets: List[str] = field(default_factory=list)
    indicators: List[Dict[str, Any]] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    actions_taken: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_timeline_event(self, event: str, details: Optional[Dict] = None):
        """Add event to incident timeline"""
        self.timeline.append({
            "timestamp": datetime.utcnow().isoformat(),
            "event": event,
            "details": details or {}
        })
        
    def add_action(self, action: ResponseAction, success: bool, details: Optional[Dict] = None):
        """Record response action"""
        self.actions_taken.append({
            "timestamp": datetime.utcnow().isoformat(),
            "action": action.value,
            "success": success,
            "details": details or {}
        })
        
    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.name,
            "status": self.status.value,
            "detected_at": self.detected_at.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
            "affected_assets": self.affected_assets,
            "indicators": self.indicators,
            "timeline": self.timeline,
            "actions_taken": self.actions_taken,
            "metadata": self.metadata
        }


@dataclass
class ResponsePlaybook:
    """Automated response playbook"""
    playbook_id: str
    name: str
    description: str
    trigger_conditions: Dict[str, Any]  # Conditions to activate playbook
    actions: List[ResponseAction]
    auto_execute: bool = False  # Auto-execute or require approval
    severity_threshold: IncidentSeverity = IncidentSeverity.MEDIUM
    
    def should_activate(self, incident: Incident) -> bool:
        """Check if playbook should activate for incident"""
        # Check severity
        if incident.severity.value < self.severity_threshold.value:
            return False
            
        # Check trigger conditions (simplified)
        for key, expected_value in self.trigger_conditions.items():
            if incident.metadata.get(key) != expected_value:
                return False
                
        return True


class ResponseExecutor:
    """Execute automated response actions"""
    
    def __init__(self):
        self.evidence_dir = Path.home() / ".ava" / "incident_evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        
    async def execute(self, action: ResponseAction, incident: Incident, 
                     params: Optional[Dict[str, Any]] = None) -> Tuple[bool, str]:
        """
        Execute a response action
        Returns: (success, message)
        """
        params = params or {}
        
        try:
            if action == ResponseAction.BLOCK_IP:
                return await self._block_ip(params.get("ip"))
            elif action == ResponseAction.KILL_PROCESS:
                return await self._kill_process(params.get("pid"))
            elif action == ResponseAction.DISABLE_USER:
                return await self._disable_user(params.get("username"))
            elif action == ResponseAction.ISOLATE_HOST:
                return await self._isolate_host(params.get("hostname"))
            elif action == ResponseAction.ROTATE_CREDENTIALS:
                return await self._rotate_credentials(params.get("service"))
            elif action == ResponseAction.BACKUP_EVIDENCE:
                return await self._backup_evidence(incident)
            elif action == ResponseAction.ALERT_TEAM:
                return await self._alert_team(incident)
            elif action == ResponseAction.QUARANTINE_FILE:
                return await self._quarantine_file(params.get("file_path"))
            elif action == ResponseAction.PATCH_VULNERABILITY:
                return await self._patch_vulnerability(params.get("vuln_id"))
            else:
                return False, f"Unknown action: {action}"
        except Exception as e:
            logger.error(f"Error executing {action}: {e}")
            return False, str(e)
            
    async def _block_ip(self, ip: str) -> Tuple[bool, str]:
        """Block IP address in firewall"""
        if not ip:
            return False, "No IP provided"
            
        logger.warning(f"🚫 Blocking IP: {ip}")
        
        # On Linux (iptables)
        try:
            # Note: Would require root privileges
            cmd = f"sudo iptables -A INPUT -s {ip} -j DROP"
            # In demo mode, just log it
            logger.info(f"Would execute: {cmd}")
            return True, f"IP {ip} blocked (simulated)"
        except Exception as e:
            return False, str(e)
            
    async def _kill_process(self, pid: int) -> Tuple[bool, str]:
        """Kill malicious process"""
        if not pid:
            return False, "No PID provided"
            
        logger.warning(f"💀 Killing process: {pid}")
        
        try:
            import psutil
            process = psutil.Process(pid)
            process_name = process.name()
            process.kill()
            return True, f"Process {process_name} (PID {pid}) killed"
        except psutil.NoSuchProcess:
            return False, f"Process {pid} not found"
        except psutil.AccessDenied:
            return False, f"Access denied to kill process {pid}"
        except Exception as e:
            return False, str(e)
            
    async def _disable_user(self, username: str) -> Tuple[bool, str]:
        """Disable compromised user account"""
        if not username:
            return False, "No username provided"
            
        logger.warning(f"🔒 Disabling user: {username}")
        
        # Would integrate with user management system
        logger.info(f"Would disable user account: {username}")
        return True, f"User {username} disabled (simulated)"
        
    async def _isolate_host(self, hostname: str) -> Tuple[bool, str]:
        """Network isolation of compromised host"""
        if not hostname:
            return False, "No hostname provided"
            
        logger.warning(f"🏝️ Isolating host: {hostname}")
        
        # Would configure network segmentation
        logger.info(f"Would isolate host from network: {hostname}")
        return True, f"Host {hostname} isolated (simulated)"
        
    async def _rotate_credentials(self, service: str) -> Tuple[bool, str]:
        """Rotate compromised credentials"""
        if not service:
            return False, "No service provided"
            
        logger.warning(f"🔑 Rotating credentials for: {service}")
        
        # Would trigger credential rotation workflow
        logger.info(f"Would rotate credentials for service: {service}")
        return True, f"Credentials rotated for {service} (simulated)"
        
    async def _backup_evidence(self, incident: Incident) -> Tuple[bool, str]:
        """Backup forensic evidence"""
        logger.info(f"💾 Backing up evidence for incident {incident.incident_id}")
        
        evidence_file = self.evidence_dir / f"{incident.incident_id}_evidence.json"
        try:
            with open(evidence_file, 'w') as f:
                json.dump({
                    "incident": incident.to_dict(),
                    "timestamp": datetime.utcnow().isoformat(),
                    "system_state": self._capture_system_state()
                }, f, indent=2)
            return True, f"Evidence saved to {evidence_file}"
        except Exception as e:
            return False, f"Failed to backup evidence: {e}"
            
    def _capture_system_state(self) -> Dict[str, Any]:
        """Capture current system state for forensics"""
        import psutil
        return {
            "processes": [{"pid": p.pid, "name": p.name()} 
                         for p in psutil.process_iter(['pid', 'name'])],
            "network_connections": len(psutil.net_connections()),
            "cpu_percent": psutil.cpu_percent(),
            "memory_percent": psutil.virtual_memory().percent,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    async def _alert_team(self, incident: Incident) -> Tuple[bool, str]:
        """Alert security team"""
        logger.warning(f"📢 Alerting team about incident {incident.incident_id}")
        
        # Would integrate with alerting system (email, Slack, PagerDuty, etc.)
        alert_message = f"""
        🚨 SECURITY INCIDENT ALERT 🚨
        
        Incident ID: {incident.incident_id}
        Severity: {incident.severity.name}
        Title: {incident.title}
        Description: {incident.description}
        Detected: {incident.detected_at.isoformat()}
        Affected Assets: {', '.join(incident.affected_assets)}
        """
        
        logger.info(alert_message)
        return True, "Team alerted (simulated)"
        
    async def _quarantine_file(self, file_path: str) -> Tuple[bool, str]:
        """Quarantine malicious file"""
        if not file_path:
            return False, "No file path provided"
            
        logger.warning(f"🗂️ Quarantining file: {file_path}")
        
        quarantine_dir = self.evidence_dir / "quarantine"
        quarantine_dir.mkdir(exist_ok=True)
        
        try:
            import shutil
            from pathlib import Path
            
            source = Path(file_path)
            if source.exists():
                dest = quarantine_dir / f"{datetime.utcnow().timestamp()}_{source.name}"
                shutil.move(str(source), str(dest))
                return True, f"File quarantined to {dest}"
            else:
                return False, f"File not found: {file_path}"
        except Exception as e:
            return False, f"Failed to quarantine: {e}"
            
    async def _patch_vulnerability(self, vuln_id: str) -> Tuple[bool, str]:
        """Apply security patch"""
        if not vuln_id:
            return False, "No vulnerability ID provided"
            
        logger.warning(f"🔧 Patching vulnerability: {vuln_id}")
        
        # Would trigger patch management system
        logger.info(f"Would apply patch for vulnerability: {vuln_id}")
        return True, f"Patch applied for {vuln_id} (simulated)"


class IncidentResponseSystem:
    """Main Incident Response System"""
    
    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = data_dir or Path.home() / ".ava" / "incident_response"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.incidents: Dict[str, Incident] = {}
        self.playbooks: Dict[str, ResponsePlaybook] = {}
        self.executor = ResponseExecutor()
        
        self.initialize_default_playbooks()
        
    def initialize_default_playbooks(self):
        """Create default response playbooks"""
        # Malware detection playbook
        self.add_playbook(ResponsePlaybook(
            playbook_id="malware_response",
            name="Malware Detection Response",
            description="Automated response to malware detection",
            trigger_conditions={"category": "malware"},
            actions=[
                ResponseAction.KILL_PROCESS,
                ResponseAction.QUARANTINE_FILE,
                ResponseAction.BACKUP_EVIDENCE,
                ResponseAction.ALERT_TEAM
            ],
            auto_execute=True,
            severity_threshold=IncidentSeverity.HIGH
        ))
        
        # Brute force attack playbook
        self.add_playbook(ResponsePlaybook(
            playbook_id="brute_force_response",
            name="Brute Force Attack Response",
            description="Automated response to brute force attacks",
            trigger_conditions={"category": "brute_force"},
            actions=[
                ResponseAction.BLOCK_IP,
                ResponseAction.BACKUP_EVIDENCE,
                ResponseAction.ALERT_TEAM
            ],
            auto_execute=True,
            severity_threshold=IncidentSeverity.MEDIUM
        ))
        
        # Compromised account playbook
        self.add_playbook(ResponsePlaybook(
            playbook_id="compromised_account_response",
            name="Compromised Account Response",
            description="Automated response to account compromise",
            trigger_conditions={"category": "compromised_account"},
            actions=[
                ResponseAction.DISABLE_USER,
                ResponseAction.ROTATE_CREDENTIALS,
                ResponseAction.BACKUP_EVIDENCE,
                ResponseAction.ALERT_TEAM
            ],
            auto_execute=False,  # Requires approval
            severity_threshold=IncidentSeverity.HIGH
        ))
        
    def add_playbook(self, playbook: ResponsePlaybook):
        """Add a response playbook"""
        self.playbooks[playbook.playbook_id] = playbook
        logger.info(f"Playbook added: {playbook.name}")
        
    async def create_incident(self, incident: Incident) -> str:
        """Create and process a new incident"""
        self.incidents[incident.incident_id] = incident
        incident.add_timeline_event("Incident detected", {"severity": incident.severity.name})
        
        logger.warning(f"🚨 New incident: {incident.incident_id} - {incident.title}")
        
        # Save incident
        self._save_incident(incident)
        
        # Trigger automated response
        await self.respond_to_incident(incident)
        
        return incident.incident_id
        
    async def respond_to_incident(self, incident: Incident):
        """Execute automated response for incident"""
        incident.status = IncidentStatus.ANALYZING
        incident.add_timeline_event("Analysis started")
        
        # Find applicable playbooks
        applicable_playbooks = [
            playbook for playbook in self.playbooks.values()
            if playbook.should_activate(incident)
        ]
        
        if not applicable_playbooks:
            logger.info(f"No playbooks activated for incident {incident.incident_id}")
            return
            
        for playbook in applicable_playbooks:
            logger.info(f"Activating playbook: {playbook.name}")
            incident.add_timeline_event(f"Playbook activated: {playbook.name}")
            
            if not playbook.auto_execute:
                logger.info(f"Playbook requires manual approval: {playbook.name}")
                continue
                
            # Execute playbook actions
            incident.status = IncidentStatus.CONTAINED
            for action in playbook.actions:
                success, message = await self.executor.execute(
                    action, incident, incident.metadata.get("action_params", {})
                )
                incident.add_action(action, success, {"message": message})
                logger.info(f"Action {action.value}: {message}")
                
        # Mark incident as resolved if all actions succeeded
        if all(action['success'] for action in incident.actions_taken):
            incident.status = IncidentStatus.RESOLVED
            incident.resolved_at = datetime.utcnow()
            incident.add_timeline_event("Incident resolved")
            logger.info(f"✅ Incident {incident.incident_id} resolved")
        else:
            logger.warning(f"⚠️ Some actions failed for incident {incident.incident_id}")
            
        self._save_incident(incident)
        
    def _save_incident(self, incident: Incident):
        """Save incident to disk"""
        incident_file = self.data_dir / f"{incident.incident_id}.json"
        try:
            with open(incident_file, 'w') as f:
                json.dump(incident.to_dict(), f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save incident: {e}")
            
    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Get incident by ID"""
        return self.incidents.get(incident_id)
        
    def get_statistics(self) -> Dict[str, Any]:
        """Get incident response statistics"""
        total = len(self.incidents)
        by_severity = {}
        by_status = {}
        
        for incident in self.incidents.values():
            severity = incident.severity.name
            status = incident.status.value
            by_severity[severity] = by_severity.get(severity, 0) + 1
            by_status[status] = by_status.get(status, 0) + 1
            
        return {
            "total_incidents": total,
            "by_severity": by_severity,
            "by_status": by_status,
            "total_playbooks": len(self.playbooks)
        }


# Global instance
_irs: Optional[IncidentResponseSystem] = None


def get_incident_response_system() -> IncidentResponseSystem:
    """Get or create global IRS instance"""
    global _irs
    if _irs is None:
        _irs = IncidentResponseSystem()
    return _irs


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Demo
    async def demo():
        irs = IncidentResponseSystem()
        
        # Create test incident
        incident = Incident(
            incident_id="INC_001",
            title="Malware Detected on Workstation",
            description="Suspicious process behavior detected",
            severity=IncidentSeverity.HIGH,
            affected_assets=["workstation-42"],
            metadata={
                "category": "malware",
                "action_params": {
                    "pid": 12345,
                    "file_path": "/tmp/suspicious.exe"
                }
            }
        )
        
        print("\n🚨 Incident Response System Demo\n")
        await irs.create_incident(incident)
        
        print(f"\n📊 Statistics:")
        stats = irs.get_statistics()
        print(json.dumps(stats, indent=2))
        
        print(f"\n📝 Incident Timeline:")
        for event in incident.timeline:
            print(f"  [{event['timestamp']}] {event['event']}")
            
        print(f"\n⚡ Actions Taken:")
        for action in incident.actions_taken:
            status = "✅" if action['success'] else "❌"
            print(f"  {status} {action['action']}: {action['details'].get('message')}")
        
    asyncio.run(demo())
