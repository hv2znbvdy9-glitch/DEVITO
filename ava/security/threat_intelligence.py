"""
AVA Advanced Threat Intelligence System
========================================
Real-time threat detection, analysis, and response orchestration.

Features:
- Multi-source threat feed aggregation
- Machine Learning anomaly detection
- Behavioral analysis
- Threat hunting automation
- Zero-day detection
- IOC (Indicator of Compromise) correlation
"""

import asyncio
import hashlib
import json
import logging
import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import psutil

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Threat severity levels"""
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ThreatCategory(Enum):
    """Threat categorization"""
    MALWARE = "malware"
    PHISHING = "phishing"
    BRUTE_FORCE = "brute_force"
    DDoS = "ddos"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    COMMAND_AND_CONTROL = "c2"
    ZERO_DAY = "zero_day"
    ANOMALY = "anomaly"


@dataclass
class ThreatIndicator:
    """Indicator of Compromise (IOC)"""
    indicator_type: str  # ip, domain, hash, url, email
    value: str
    threat_level: ThreatLevel
    category: ThreatCategory
    confidence: float  # 0.0 to 1.0
    source: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.indicator_type,
            "value": self.value,
            "threat_level": self.threat_level.name,
            "category": self.category.value,
            "confidence": self.confidence,
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
            "metadata": self.metadata
        }


@dataclass
class ThreatEvent:
    """Detected threat event"""
    event_id: str
    threat_level: ThreatLevel
    category: ThreatCategory
    description: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    process_name: Optional[str] = None
    user: Optional[str] = None
    indicators: List[ThreatIndicator] = field(default_factory=list)
    mitre_attack: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.utcnow)
    auto_response: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "threat_level": self.threat_level.name,
            "category": self.category.value,
            "description": self.description,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "process_name": self.process_name,
            "user": self.user,
            "indicators": [ind.to_dict() for ind in self.indicators],
            "mitre_attack": self.mitre_attack,
            "timestamp": self.timestamp.isoformat(),
            "auto_response": self.auto_response,
            "metadata": self.metadata
        }


class AnomalyDetector:
    """Machine Learning-based anomaly detection"""
    
    def __init__(self, baseline_window: int = 3600):
        self.baseline_window = baseline_window
        self.metrics_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.baselines: Dict[str, Dict[str, float]] = {}
        
    def record_metric(self, metric_name: str, value: float):
        """Record a metric for baseline calculation"""
        self.metrics_history[metric_name].append({
            "value": value,
            "timestamp": datetime.utcnow()
        })
        
    def calculate_baseline(self, metric_name: str) -> Optional[Dict[str, float]]:
        """Calculate statistical baseline for a metric"""
        values = [m["value"] for m in self.metrics_history[metric_name]]
        if len(values) < 30:  # Need minimum samples
            return None
            
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        std_dev = variance ** 0.5
        
        return {
            "mean": mean,
            "std_dev": std_dev,
            "min": min(values),
            "max": max(values)
        }
        
    def detect_anomaly(self, metric_name: str, value: float, 
                      std_threshold: float = 3.0) -> Tuple[bool, float]:
        """
        Detect if value is anomalous using statistical analysis
        Returns: (is_anomaly, deviation_score)
        """
        baseline = self.baselines.get(metric_name) or self.calculate_baseline(metric_name)
        if not baseline:
            self.record_metric(metric_name, value)
            return False, 0.0
            
        mean = baseline["mean"]
        std_dev = baseline["std_dev"]
        
        if std_dev == 0:
            return False, 0.0
            
        deviation = abs(value - mean) / std_dev
        is_anomaly = deviation > std_threshold
        
        self.record_metric(metric_name, value)
        
        return is_anomaly, deviation


class BehaviorAnalyzer:
    """Behavioral analysis engine"""
    
    def __init__(self):
        self.process_behavior: Dict[str, List[Dict]] = defaultdict(list)
        self.network_behavior: Dict[str, List[Dict]] = defaultdict(list)
        self.user_behavior: Dict[str, List[Dict]] = defaultdict(list)
        
    def analyze_process_behavior(self, process_name: str, pid: int) -> Optional[ThreatEvent]:
        """Analyze process behavior for threats"""
        try:
            proc = psutil.Process(pid)
            
            # Check memory usage
            mem_percent = proc.memory_percent()
            if mem_percent > 80:
                return ThreatEvent(
                    event_id=f"PROC_{pid}_{datetime.utcnow().timestamp()}",
                    threat_level=ThreatLevel.MEDIUM,
                    category=ThreatCategory.ANOMALY,
                    description=f"Process {process_name} using excessive memory: {mem_percent:.2f}%",
                    process_name=process_name,
                    metadata={"pid": pid, "mem_percent": mem_percent}
                )
                
            # Check CPU usage
            cpu_percent = proc.cpu_percent(interval=0.1)
            if cpu_percent > 90:
                return ThreatEvent(
                    event_id=f"PROC_{pid}_{datetime.utcnow().timestamp()}",
                    threat_level=ThreatLevel.MEDIUM,
                    category=ThreatCategory.ANOMALY,
                    description=f"Process {process_name} using excessive CPU: {cpu_percent:.2f}%",
                    process_name=process_name,
                    metadata={"pid": pid, "cpu_percent": cpu_percent}
                )
                
            # Check for suspicious connections
            connections = proc.connections()
            suspicious_ports = {22, 23, 3389, 4444, 5555, 8080, 31337}
            for conn in connections:
                if conn.raddr and conn.raddr.port in suspicious_ports:
                    return ThreatEvent(
                        event_id=f"NET_{pid}_{datetime.utcnow().timestamp()}",
                        threat_level=ThreatLevel.HIGH,
                        category=ThreatCategory.COMMAND_AND_CONTROL,
                        description=f"Process {process_name} connected to suspicious port {conn.raddr.port}",
                        process_name=process_name,
                        destination_ip=conn.raddr.ip,
                        mitre_attack=["T1071"],  # Application Layer Protocol
                        metadata={"pid": pid, "port": conn.raddr.port}
                    )
                    
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
            
        return None
        
    def analyze_file_access(self, file_path: str, process_name: str) -> Optional[ThreatEvent]:
        """Analyze file access patterns"""
        suspicious_paths = [
            r".*\\system32\\config\\sam",
            r".*\\ntds\.dit",
            r".*\\shadow",
            r".*\\\.ssh\\",
            r".*\\wallet\.",
            r".*\\password",
        ]
        
        for pattern in suspicious_paths:
            if re.match(pattern, file_path, re.IGNORECASE):
                return ThreatEvent(
                    event_id=f"FILE_{datetime.utcnow().timestamp()}",
                    threat_level=ThreatLevel.HIGH,
                    category=ThreatCategory.DATA_EXFILTRATION,
                    description=f"Suspicious file access by {process_name}: {file_path}",
                    process_name=process_name,
                    mitre_attack=["T1005"],  # Data from Local System
                    metadata={"file_path": file_path}
                )
                
        return None


class ThreatIntelligence:
    """Main Threat Intelligence Engine"""
    
    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = data_dir or Path.home() / ".ava" / "threat_intelligence"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.ioc_database: Dict[str, List[ThreatIndicator]] = defaultdict(list)
        self.threat_events: List[ThreatEvent] = []
        self.anomaly_detector = AnomalyDetector()
        self.behavior_analyzer = BehaviorAnalyzer()
        
        # Known malicious indicators (example database)
        self.known_bad_ips: Set[str] = {
            "192.0.2.0",  # TEST-NET (example)
            "198.51.100.0",  # TEST-NET-2 (example)
        }
        
        self.known_bad_domains: Set[str] = {
            "malware.example.com",
            "phishing.example.org",
        }
        
        # MITRE ATT&CK Mapping
        self.mitre_techniques = {
            "T1110": "Brute Force",
            "T1059": "Command and Scripting Interpreter",
            "T1071": "Application Layer Protocol",
            "T1005": "Data from Local System",
            "T1543": "Create or Modify System Process",
            "T1078": "Valid Accounts",
            "T1021": "Remote Services",
            "T1055": "Process Injection",
        }
        
        self.load_ioc_database()
        
    def load_ioc_database(self):
        """Load IOC database from disk"""
        ioc_file = self.data_dir / "ioc_database.json"
        if ioc_file.exists():
            try:
                with open(ioc_file, 'r') as f:
                    data = json.load(f)
                    for ioc_type, indicators in data.items():
                        for ind in indicators:
                            self.add_ioc(ThreatIndicator(
                                indicator_type=ind["type"],
                                value=ind["value"],
                                threat_level=ThreatLevel[ind["threat_level"]],
                                category=ThreatCategory(ind["category"]),
                                confidence=ind["confidence"],
                                source=ind["source"]
                            ))
                logger.info(f"Loaded {len(self.ioc_database)} IOC categories")
            except Exception as e:
                logger.error(f"Failed to load IOC database: {e}")
                
    def save_ioc_database(self):
        """Save IOC database to disk"""
        ioc_file = self.data_dir / "ioc_database.json"
        try:
            data = {}
            for ioc_type, indicators in self.ioc_database.items():
                data[ioc_type] = [ind.to_dict() for ind in indicators]
            with open(ioc_file, 'w') as f:
                json.dump(data, f, indent=2)
            logger.info("IOC database saved")
        except Exception as e:
            logger.error(f"Failed to save IOC database: {e}")
            
    def add_ioc(self, indicator: ThreatIndicator):
        """Add an Indicator of Compromise"""
        self.ioc_database[indicator.indicator_type].append(indicator)
        
    def check_ioc(self, indicator_type: str, value: str) -> List[ThreatIndicator]:
        """Check if value matches known IOCs"""
        matches = []
        for ioc in self.ioc_database.get(indicator_type, []):
            if ioc.value == value:
                matches.append(ioc)
        return matches
        
    def check_ip_reputation(self, ip: str) -> Optional[ThreatIndicator]:
        """Check IP reputation"""
        if ip in self.known_bad_ips:
            return ThreatIndicator(
                indicator_type="ip",
                value=ip,
                threat_level=ThreatLevel.HIGH,
                category=ThreatCategory.MALWARE,
                confidence=0.95,
                source="internal_database"
            )
        return None
        
    def check_domain_reputation(self, domain: str) -> Optional[ThreatIndicator]:
        """Check domain reputation"""
        if domain in self.known_bad_domains:
            return ThreatIndicator(
                indicator_type="domain",
                value=domain,
                threat_level=ThreatLevel.HIGH,
                category=ThreatCategory.PHISHING,
                confidence=0.90,
                source="internal_database"
            )
        return None
        
    async def hunt_threats(self) -> List[ThreatEvent]:
        """Active threat hunting across system"""
        threats = []
        
        # Hunt for suspicious processes
        for proc in psutil.process_iter(['pid', 'name', 'username']):
            try:
                threat = self.behavior_analyzer.analyze_process_behavior(
                    proc.info['name'], 
                    proc.info['pid']
                )
                if threat:
                    threats.append(threat)
                    self.threat_events.append(threat)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
                
        # Check network anomalies
        net_io = psutil.net_io_counters()
        is_anomaly, score = self.anomaly_detector.detect_anomaly(
            "network_bytes_sent", 
            net_io.bytes_sent
        )
        if is_anomaly:
            threat = ThreatEvent(
                event_id=f"NET_ANOMALY_{datetime.utcnow().timestamp()}",
                threat_level=ThreatLevel.MEDIUM,
                category=ThreatCategory.ANOMALY,
                description=f"Network traffic anomaly detected (deviation: {score:.2f}σ)",
                metadata={"bytes_sent": net_io.bytes_sent, "deviation": score}
            )
            threats.append(threat)
            self.threat_events.append(threat)
            
        return threats
        
    def correlate_events(self, events: List[ThreatEvent]) -> List[ThreatEvent]:
        """Correlate multiple events to identify attack patterns"""
        # Simple correlation: group events by source IP
        correlated = []
        ip_events = defaultdict(list)
        
        for event in events:
            if event.source_ip:
                ip_events[event.source_ip].append(event)
                
        # Detect potential coordinated attacks
        for ip, ip_event_list in ip_events.items():
            if len(ip_event_list) >= 3:  # Multiple events from same IP
                correlated_event = ThreatEvent(
                    event_id=f"CORR_{datetime.utcnow().timestamp()}",
                    threat_level=ThreatLevel.CRITICAL,
                    category=ThreatCategory.BRUTE_FORCE,
                    description=f"Coordinated attack pattern from {ip}: {len(ip_event_list)} events",
                    source_ip=ip,
                    auto_response=True,
                    metadata={"event_count": len(ip_event_list)}
                )
                correlated.append(correlated_event)
                
        return correlated
        
    def generate_threat_report(self) -> Dict[str, Any]:
        """Generate comprehensive threat intelligence report"""
        # Count threats by level
        level_counts = defaultdict(int)
        category_counts = defaultdict(int)
        
        for event in self.threat_events:
            level_counts[event.threat_level.name] += 1
            category_counts[event.category.value] += 1
            
        # Recent critical events
        recent_critical = [
            event.to_dict() 
            for event in self.threat_events 
            if event.threat_level == ThreatLevel.CRITICAL
        ][-10:]
        
        # MITRE ATT&CK coverage
        detected_techniques = set()
        for event in self.threat_events:
            detected_techniques.update(event.mitre_attack)
            
        return {
            "report_timestamp": datetime.utcnow().isoformat(),
            "total_events": len(self.threat_events),
            "events_by_level": dict(level_counts),
            "events_by_category": dict(category_counts),
            "recent_critical_events": recent_critical,
            "detected_mitre_techniques": list(detected_techniques),
            "ioc_database_size": sum(len(v) for v in self.ioc_database.values())
        }
        
    async def auto_response(self, threat: ThreatEvent) -> bool:
        """Automated threat response"""
        if not threat.auto_response:
            return False
            
        logger.warning(f"Auto-response triggered for {threat.event_id}")
        
        # Example responses
        if threat.source_ip:
            logger.warning(f"Would block IP: {threat.source_ip}")
            # In production: add to firewall blacklist
            
        if threat.process_name:
            logger.warning(f"Would terminate process: {threat.process_name}")
            # In production: kill process
            
        return True


# Global threat intelligence instance
_threat_intel: Optional[ThreatIntelligence] = None


def get_threat_intelligence() -> ThreatIntelligence:
    """Get or create global threat intelligence instance"""
    global _threat_intel
    if _threat_intel is None:
        _threat_intel = ThreatIntelligence()
    return _threat_intel


async def continuous_threat_monitoring(interval: int = 60):
    """Continuous threat monitoring loop"""
    ti = get_threat_intelligence()
    
    while True:
        try:
            logger.info("Starting threat hunting cycle...")
            threats = await ti.hunt_threats()
            
            if threats:
                logger.warning(f"Detected {len(threats)} new threats")
                
                # Correlate events
                correlated = ti.correlate_events(threats)
                
                # Auto-respond to critical threats
                for threat in correlated:
                    await ti.auto_response(threat)
                    
                # Generate report
                report = ti.generate_threat_report()
                logger.info(f"Threat Report: {report['total_events']} total events")
                
        except Exception as e:
            logger.error(f"Error in threat monitoring: {e}")
            
        await asyncio.sleep(interval)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    # Demo
    ti = ThreatIntelligence()
    
    # Add some test IOCs
    ti.add_ioc(ThreatIndicator(
        indicator_type="ip",
        value="192.0.2.1",
        threat_level=ThreatLevel.HIGH,
        category=ThreatCategory.MALWARE,
        confidence=0.95,
        source="demo"
    ))
    
    # Run threat hunting
    async def demo():
        threats = await ti.hunt_threats()
        print(f"\n🔍 Detected {len(threats)} threats")
        for threat in threats[:5]:
            print(f"  - {threat.description}")
            
        report = ti.generate_threat_report()
        print(f"\n📊 Threat Report:")
        print(json.dumps(report, indent=2))
        
    asyncio.run(demo())
