"""
AVA Real-Time Network Defense Layer
====================================
Advanced IDS/IPS with packet inspection, attack detection, and automatic blocking.

Features:
- Deep Packet Inspection (DPI)
- Signature-based detection
- Anomaly-based detection
- Rate limiting & DDoS protection
- Automatic threat blocking
- Network traffic analysis
"""

import asyncio
import hashlib
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

import logging

logger = logging.getLogger(__name__)


class AttackType(Enum):
    """Network attack types"""
    PORT_SCAN = "port_scan"
    BRUTE_FORCE = "brute_force"
    DDoS = "ddos"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    MALWARE_DOWNLOAD = "malware_download"
    DATA_EXFILTRATION = "data_exfiltration"
    MAN_IN_THE_MIDDLE = "mitm"
    DNS_POISONING = "dns_poisoning"


@dataclass
class NetworkPacket:
    """Network packet representation"""
    timestamp: datetime
    source_ip: str
    dest_ip: str
    source_port: int
    dest_port: int
    protocol: str  # TCP, UDP, ICMP, etc.
    payload: bytes
    flags: List[str] = field(default_factory=list)  # TCP flags
    size: int = 0
    
    def __post_init__(self):
        self.size = len(self.payload)


@dataclass
class AttackSignature:
    """Attack signature for pattern matching"""
    signature_id: str
    name: str
    attack_type: AttackType
    pattern: str  # Regex pattern
    description: str
    severity: int = 5  # 1-10 scale
    
    def matches(self, packet: NetworkPacket) -> bool:
        """Check if packet matches signature"""
        try:
            payload_str = packet.payload.decode('utf-8', errors='ignore')
            return bool(re.search(self.pattern, payload_str, re.IGNORECASE))
        except Exception:
            return False


class RateLimiter:
    """Rate limiting for DDoS protection"""
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, deque] = defaultdict(lambda: deque(maxlen=max_requests))
        
    def is_allowed(self, ip: str) -> bool:
        """Check if request from IP is allowed"""
        now = time.time()
        cutoff = now - self.window_seconds
        
        # Remove old requests
        while self.requests[ip] and self.requests[ip][0] < cutoff:
            self.requests[ip].popleft()
            
        # Check rate limit
        if len(self.requests[ip]) >= self.max_requests:
            return False
            
        # Add current request
        self.requests[ip].append(now)
        return True
        
    def get_request_count(self, ip: str) -> int:
        """Get current request count for IP"""
        now = time.time()
        cutoff = now - self.window_seconds
        
        # Clean old requests
        while self.requests[ip] and self.requests[ip][0] < cutoff:
            self.requests[ip].popleft()
            
        return len(self.requests[ip])


class PortScanDetector:
    """Detect port scanning activity"""
    
    def __init__(self, threshold: int = 20, window_seconds: int = 60):
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.port_attempts: Dict[str, Set[int]] = defaultdict(set)
        self.attempt_times: Dict[str, deque] = defaultdict(deque)
        
    def check_packet(self, packet: NetworkPacket) -> bool:
        """Check if packet indicates port scanning"""
        ip = packet.source_ip
        port = packet.dest_port
        now = time.time()
        
        # Add port to attempts
        self.port_attempts[ip].add(port)
        self.attempt_times[ip].append(now)
        
        # Clean old attempts
        cutoff = now - self.window_seconds
        while self.attempt_times[ip] and self.attempt_times[ip][0] < cutoff:
            self.attempt_times[ip].popleft()
            
        # Check if threshold exceeded
        if len(self.port_attempts[ip]) >= self.threshold:
            return True
            
        return False
        
    def reset_ip(self, ip: str):
        """Reset tracking for IP"""
        self.port_attempts.pop(ip, None)
        self.attempt_times.pop(ip, None)


class TrafficAnalyzer:
    """Analyze network traffic patterns"""
    
    def __init__(self):
        self.traffic_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "packet_count": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "connections": set(),
            "protocols": defaultdict(int)
        })
        self.baseline_metrics: Dict[str, float] = {}
        
    def analyze_packet(self, packet: NetworkPacket):
        """Analyze individual packet"""
        source = packet.source_ip
        dest = packet.dest_ip
        
        # Update source stats
        self.traffic_stats[source]["packet_count"] += 1
        self.traffic_stats[source]["bytes_sent"] += packet.size
        self.traffic_stats[source]["connections"].add(dest)
        self.traffic_stats[source]["protocols"][packet.protocol] += 1
        
        # Update dest stats
        self.traffic_stats[dest]["bytes_received"] += packet.size
        
    def detect_anomalies(self, ip: str) -> List[str]:
        """Detect anomalous traffic patterns"""
        anomalies = []
        stats = self.traffic_stats.get(ip)
        
        if not stats:
            return anomalies
            
        # Too many connections
        if len(stats["connections"]) > 100:
            anomalies.append(f"Excessive connections: {len(stats['connections'])}")
            
        # Too much data
        if stats["bytes_sent"] > 1_000_000_000:  # 1 GB
            anomalies.append(f"Excessive data sent: {stats['bytes_sent'] / 1e9:.2f} GB")
            
        # Unusual protocol distribution
        total_packets = sum(stats["protocols"].values())
        for protocol, count in stats["protocols"].items():
            ratio = count / total_packets
            if protocol == "ICMP" and ratio > 0.5:
                anomalies.append(f"Unusual ICMP traffic: {ratio*100:.1f}%")
                
        return anomalies
        
    def get_top_talkers(self, limit: int = 10) -> List[Tuple[str, int]]:
        """Get IPs sending most traffic"""
        talkers = [(ip, stats["bytes_sent"]) 
                   for ip, stats in self.traffic_stats.items()]
        talkers.sort(key=lambda x: x[1], reverse=True)
        return talkers[:limit]


class NetworkDefenseEngine:
    """Main network defense engine"""
    
    def __init__(self):
        self.signatures: List[AttackSignature] = []
        self.blocked_ips: Set[str] = set()
        self.rate_limiter = RateLimiter(max_requests=100, window_seconds=60)
        self.port_scan_detector = PortScanDetector(threshold=20, window_seconds=60)
        self.traffic_analyzer = TrafficAnalyzer()
        
        self.alerts: List[Dict[str, Any]] = []
        self.packet_count = 0
        self.blocked_packet_count = 0
        
        self._initialize_signatures()
        
    def _initialize_signatures(self):
        """Initialize attack signatures"""
        # SQL Injection signatures
        self.signatures.extend([
            AttackSignature(
                signature_id="SQL_001",
                name="SQL Injection - Basic",
                attack_type=AttackType.SQL_INJECTION,
                pattern=r"(\bunion\b.*\bselect\b|'\s*or\s*'1'\s*=\s*'1)",
                description="Detects basic SQL injection attempts",
                severity=8
            ),
            AttackSignature(
                signature_id="SQL_002",
                name="SQL Injection - Comments",
                attack_type=AttackType.SQL_INJECTION,
                pattern=r"(--|\#|\/\*|\*\/)",
                description="Detects SQL comment-based injection",
                severity=7
            ),
        ])
        
        # XSS signatures
        self.signatures.extend([
            AttackSignature(
                signature_id="XSS_001",
                name="Cross-Site Scripting",
                attack_type=AttackType.XSS,
                pattern=r"<script[^>]*>.*?</script>|javascript:|onerror=|onload=",
                description="Detects XSS attempts",
                severity=7
            ),
        ])
        
        # Path traversal
        self.signatures.append(
            AttackSignature(
                signature_id="PATH_001",
                name="Path Traversal",
                attack_type=AttackType.PATH_TRAVERSAL,
                pattern=r"\.\./|\.\./|\.\.\\|%2e%2e[/\\]",
                description="Detects directory traversal attempts",
                severity=6
            )
        )
        
        # Command injection
        self.signatures.append(
            AttackSignature(
                signature_id="CMD_001",
                name="Command Injection",
                attack_type=AttackType.COMMAND_INJECTION,
                pattern=r";\s*(cat|ls|wget|curl|bash|sh|nc|netcat|python|perl)\s+",
                description="Detects command injection attempts",
                severity=9
            )
        )
        
        # Malware download patterns
        self.signatures.append(
            AttackSignature(
                signature_id="MAL_001",
                name="Malware Download Pattern",
                attack_type=AttackType.MALWARE_DOWNLOAD,
                pattern=r"\.(exe|dll|bat|cmd|ps1|vbs|js)\?download",
                description="Detects potential malware downloads",
                severity=8
            )
        )
        
        logger.info(f"Loaded {len(self.signatures)} attack signatures")
        
    def block_ip(self, ip: str, reason: str):
        """Block IP address"""
        self.blocked_ips.add(ip)
        logger.warning(f"🚫 BLOCKED IP: {ip} - Reason: {reason}")
        self._create_alert("IP Blocked", f"Blocked {ip}: {reason}", severity=8)
        
    def unblock_ip(self, ip: str):
        """Unblock IP address"""
        self.blocked_ips.discard(ip)
        logger.info(f"✅ UNBLOCKED IP: {ip}")
        
    def _create_alert(self, title: str, description: str, severity: int = 5, 
                     attack_type: Optional[AttackType] = None, packet: Optional[NetworkPacket] = None):
        """Create security alert"""
        alert = {
            "timestamp": datetime.utcnow().isoformat(),
            "title": title,
            "description": description,
            "severity": severity,
            "attack_type": attack_type.value if attack_type else None,
            "source_ip": packet.source_ip if packet else None,
            "dest_ip": packet.dest_ip if packet else None,
        }
        self.alerts.append(alert)
        logger.warning(f"🚨 ALERT: {title} - {description}")
        
    async def inspect_packet(self, packet: NetworkPacket) -> Tuple[bool, Optional[str]]:
        """
        Inspect packet and determine if it should be allowed
        Returns: (allow, reason)
        """
        self.packet_count += 1
        
        # Check if IP is blocked
        if packet.source_ip in self.blocked_ips:
            self.blocked_packet_count += 1
            return False, "IP blocked"
            
        # Check rate limiting
        if not self.rate_limiter.is_allowed(packet.source_ip):
            self._create_alert(
                "Rate Limit Exceeded",
                f"IP {packet.source_ip} exceeded rate limit",
                severity=6,
                attack_type=AttackType.DDoS,
                packet=packet
            )
            self.block_ip(packet.source_ip, "Rate limit exceeded (possible DDoS)")
            return False, "Rate limit exceeded"
            
        # Check for port scanning
        if self.port_scan_detector.check_packet(packet):
            self._create_alert(
                "Port Scan Detected",
                f"Port scanning from {packet.source_ip}",
                severity=7,
                attack_type=AttackType.PORT_SCAN,
                packet=packet
            )
            self.block_ip(packet.source_ip, "Port scanning detected")
            return False, "Port scan detected"
            
        # Check attack signatures
        for signature in self.signatures:
            if signature.matches(packet):
                self._create_alert(
                    f"Attack Detected: {signature.name}",
                    f"{signature.description} from {packet.source_ip}",
                    severity=signature.severity,
                    attack_type=signature.attack_type,
                    packet=packet
                )
                
                # Block high-severity attacks
                if signature.severity >= 8:
                    self.block_ip(packet.source_ip, f"Attack detected: {signature.name}")
                    return False, f"Attack blocked: {signature.name}"
                else:
                    return True, f"Attack logged: {signature.name}"
                    
        # Analyze traffic
        self.traffic_analyzer.analyze_packet(packet)
        anomalies = self.traffic_analyzer.detect_anomalies(packet.source_ip)
        
        if anomalies:
            self._create_alert(
                "Traffic Anomaly Detected",
                f"Anomalies from {packet.source_ip}: {', '.join(anomalies)}",
                severity=5,
                packet=packet
            )
            
        return True, "Allowed"
        
    def get_statistics(self) -> Dict[str, Any]:
        """Get defense statistics"""
        return {
            "total_packets_inspected": self.packet_count,
            "packets_blocked": self.blocked_packet_count,
            "blocked_ips": len(self.blocked_ips),
            "total_alerts": len(self.alerts),
            "recent_alerts": self.alerts[-10:],
            "top_talkers": self.traffic_analyzer.get_top_talkers(5)
        }
        
    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent security alerts"""
        return self.alerts[-limit:]


# Global defense engine
_defense_engine: Optional[NetworkDefenseEngine] = None


def get_defense_engine() -> NetworkDefenseEngine:
    """Get or create global defense engine"""
    global _defense_engine
    if _defense_engine is None:
        _defense_engine = NetworkDefenseEngine()
    return _defense_engine


async def simulate_traffic():
    """Simulate network traffic for testing"""
    engine = get_defense_engine()
    
    # Normal traffic
    for i in range(10):
        packet = NetworkPacket(
            timestamp=datetime.utcnow(),
            source_ip=f"192.168.1.{i+10}",
            dest_ip="10.0.0.1",
            source_port=random.randint(1024, 65535),
            dest_port=80,
            protocol="TCP",
            payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        )
        allowed, reason = await engine.inspect_packet(packet)
        
    # SQL Injection attack
    attack_packet = NetworkPacket(
        timestamp=datetime.utcnow(),
        source_ip="203.0.113.42",
        dest_ip="10.0.0.1",
        source_port=55123,
        dest_port=80,
        protocol="TCP",
        payload=b"GET /login?user=admin' OR '1'='1 HTTP/1.1\r\n"
    )
    allowed, reason = await engine.inspect_packet(attack_packet)
    print(f"Attack packet: {allowed} - {reason}")
    
    # Port scan simulation
    for port in range(1, 25):
        scan_packet = NetworkPacket(
            timestamp=datetime.utcnow(),
            source_ip="198.51.100.10",
            dest_ip="10.0.0.1",
            source_port=random.randint(1024, 65535),
            dest_port=port,
            protocol="TCP",
            payload=b"",
            flags=["SYN"]
        )
        allowed, reason = await engine.inspect_packet(scan_packet)


if __name__ == "__main__":
    import random
    logging.basicConfig(level=logging.INFO)
    
    async def demo():
        print("\n🛡️ Network Defense Engine Demo\n")
        
        await simulate_traffic()
        
        engine = get_defense_engine()
        stats = engine.get_statistics()
        
        print(f"\n📊 Defense Statistics:")
        print(f"  Total packets: {stats['total_packets_inspected']}")
        print(f"  Blocked packets: {stats['packets_blocked']}")
        print(f"  Blocked IPs: {stats['blocked_ips']}")
        print(f"  Total alerts: {stats['total_alerts']}")
        
        print(f"\n🚨 Recent Alerts:")
        for alert in stats['recent_alerts']:
            print(f"  [{alert['timestamp']}] {alert['title']}")
            print(f"    {alert['description']}")
        
    asyncio.run(demo())
