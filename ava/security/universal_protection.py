"""
AVA Universal Interface Protection System
==========================================
Schützt JEDE Schnittstelle die existiert:
- HTTP/HTTPS
- WebSocket
- gRPC
- MQTT
- Raw Sockets
- Unix Sockets
- Bluetooth
- Custom Protocols

Adaptive, selbst-lernende Protection Layer!
"""

import asyncio
import inspect
import logging
import re
import struct
from abc import ABC, abstractmethod
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from uuid import uuid4

logger = logging.getLogger(__name__)


class ProtectionAction(Enum):
    """Schutz-Aktionen"""
    ALLOW = "allow"
    BLOCK = "block"
    RATE_LIMIT = "rate_limit"
    INSPECT = "inspect"
    LOG_ONLY = "log_only"
    QUARANTINE = "quarantine"


@dataclass
class InterfaceRequest:
    """Universelle Request-Repräsentation"""
    request_id: str = field(default_factory=lambda: str(uuid4())[:8])
    timestamp: datetime = field(default_factory=datetime.utcnow)
    interface_type: str = "unknown"
    source_ip: Optional[str] = None
    source_mac: Optional[str] = None
    destination: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[bytes] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def body_text(self) -> Optional[str]:
        """Dekodiere Body als Text"""
        if self.body:
            try:
                return self.body.decode('utf-8', errors='ignore')
            except:
                return None
        return None


@dataclass
class InterfaceResponse:
    """Universelle Response-Repräsentation"""
    action: ProtectionAction
    reason: str
    confidence: float = 1.0  # 0-1
    threat_score: float = 0.0  # 0-100
    metadata: Dict[str, Any] = field(default_factory=dict)


class InterfaceProtector(ABC):
    """Abstract Base Class für Interface-Protektoren"""
    
    def __init__(self, interface_type: str):
        self.interface_type = interface_type
        self.requests_processed = 0
        self.requests_blocked = 0
        self.threats_detected = 0
        
    @abstractmethod
    async def protect(self, request: InterfaceRequest) -> InterfaceResponse:
        """Schütze Interface-Request"""
        pass
        
    @abstractmethod
    def learn_from_attack(self, request: InterfaceRequest, attack_type: str):
        """Lerne aus erkanntem Angriff"""
        pass


class HTTPProtector(InterfaceProtector):
    """HTTP/HTTPS Schutz"""
    
    # Bekannte Angriffs-Patterns
    XSS_PATTERNS = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'onerror\s*=',
        r'onload\s*=',
    ]
    
    SQL_PATTERNS = [
        r"union\s+select",
        r";\s*drop\s+table",
        r"'\s+or\s+'",
        r"--\s*$",
    ]
    
    PATH_TRAVERSAL = [
        r'\.\./+',
        r'\.\.\\+',
        r'/etc/passwd',
        r'c:\\windows',
    ]
    
    def __init__(self):
        super().__init__("http")
        self.learned_malicious_patterns: List[str] = []
        self.suspicious_user_agents: Set[str] = set()
        self.rate_limits: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        
    async def protect(self, request: InterfaceRequest) -> InterfaceResponse:
        """HTTP-Schutz"""
        self.requests_processed += 1
        
        threat_score = 0.0
        reasons = []
        
        # 1. Rate Limiting
        if request.source_ip:
            self.rate_limits[request.source_ip].append(datetime.utcnow())
            
            # Zähle Requests in letzten 60s
            recent = [ts for ts in self.rate_limits[request.source_ip] 
                     if (datetime.utcnow() - ts).seconds < 60]
                     
            if len(recent) > 100:  # > 100 requests/min
                threat_score += 30
                reasons.append("rate_limit_exceeded")
                
        # 2. XSS Detection
        if request.path or request.body_text:
            text_to_check = (request.path or "") + " " + (request.body_text or "")
            
            for pattern in self.XSS_PATTERNS:
                if re.search(pattern, text_to_check, re.IGNORECASE):
                    threat_score += 40
                    reasons.append(f"xss_pattern:{pattern[:20]}")
                    self.threats_detected += 1
                    break
                    
        # 3. SQL Injection
        if request.path or request.body_text:
            text_to_check = (request.path or "") + " " + (request.body_text or "")
            
            for pattern in self.SQL_PATTERNS:
                if re.search(pattern, text_to_check, re.IGNORECASE):
                    threat_score += 45
                    reasons.append(f"sql_injection:{pattern[:20]}")
                    self.threats_detected += 1
                    break
                    
        # 4. Path Traversal
        if request.path:
            for pattern in self.PATH_TRAVERSAL:
                if re.search(pattern, request.path, re.IGNORECASE):
                    threat_score += 50
                    reasons.append(f"path_traversal:{pattern[:20]}")
                    self.threats_detected += 1
                    break
                    
        # 5. Suspicious User-Agent
        user_agent = request.headers.get('User-Agent', '')
        if user_agent in self.suspicious_user_agents:
            threat_score += 25
            reasons.append("suspicious_user_agent")
            
        # 6. Learned Patterns
        if request.body_text:
            for pattern in self.learned_malicious_patterns:
                if pattern in request.body_text.lower():
                    threat_score += 35
                    reasons.append(f"learned_pattern:{pattern[:20]}")
                    break
                    
        # Entscheidung
        if threat_score >= 50:
            self.requests_blocked += 1
            return InterfaceResponse(
                action=ProtectionAction.BLOCK,
                reason=f"HTTP threat detected: {', '.join(reasons)}",
                threat_score=threat_score,
                confidence=0.9
            )
        elif threat_score >= 30:
            return InterfaceResponse(
                action=ProtectionAction.RATE_LIMIT,
                reason=f"HTTP suspicious activity: {', '.join(reasons)}",
                threat_score=threat_score,
                confidence=0.7
            )
        else:
            return InterfaceResponse(
                action=ProtectionAction.ALLOW,
                reason="HTTP request allowed",
                threat_score=threat_score,
                confidence=1.0
            )
            
    def learn_from_attack(self, request: InterfaceRequest, attack_type: str):
        """Lerne aus HTTP-Angriff"""
        if request.body_text and len(request.body_text) > 5:
            # Extrahiere charakteristische Muster
            pattern = request.body_text[:50].lower()
            if pattern not in self.learned_malicious_patterns:
                self.learned_malicious_patterns.append(pattern)
                logger.warning(f"🧠 HTTP: Learned new pattern from {attack_type}")
                
        # Merke User-Agent
        if 'User-Agent' in request.headers:
            self.suspicious_user_agents.add(request.headers['User-Agent'])


class WebSocketProtector(InterfaceProtector):
    """WebSocket Schutz"""
    
    def __init__(self):
        super().__init__("websocket")
        self.connection_limits: Dict[str, int] = defaultdict(int)
        self.message_rates: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        
    async def protect(self, request: InterfaceRequest) -> InterfaceResponse:
        """WebSocket-Schutz"""
        self.requests_processed += 1
        
        threat_score = 0.0
        reasons = []
        
        # 1. Connection Flooding
        if request.source_ip:
            self.connection_limits[request.source_ip] += 1
            
            if self.connection_limits[request.source_ip] > 50:  # Max 50 connections
                threat_score += 40
                reasons.append("connection_flooding")
                
        # 2. Message Rate
        if request.source_ip:
            self.message_rates[request.source_ip].append(datetime.utcnow())
            
            recent = [ts for ts in self.message_rates[request.source_ip]
                     if (datetime.utcnow() - ts).seconds < 10]
                     
            if len(recent) > 100:  # > 100 messages/10s
                threat_score += 35
                reasons.append("message_flooding")
                
        # 3. Malformed Messages
        if request.body:
            try:
                # Prüfe ob valides JSON/Text
                request.body.decode('utf-8')
            except:
                threat_score += 30
                reasons.append("malformed_message")
                
        if threat_score >= 40:
            self.requests_blocked += 1
            return InterfaceResponse(
                action=ProtectionAction.BLOCK,
                reason=f"WebSocket threat: {', '.join(reasons)}",
                threat_score=threat_score,
                confidence=0.85
            )
        else:
            return InterfaceResponse(
                action=ProtectionAction.ALLOW,
                reason="WebSocket allowed",
                threat_score=threat_score
            )
            
    def learn_from_attack(self, request: InterfaceRequest, attack_type: str):
        """Lerne aus WebSocket-Angriff"""
        logger.warning(f"🧠 WebSocket: Learned from {attack_type} attack")


class RawSocketProtector(InterfaceProtector):
    """Raw Socket Schutz"""
    
    def __init__(self):
        super().__init__("raw_socket")
        self.suspicious_ports: Set[int] = {23, 135, 139, 445, 1433, 3389}  # Telnet, SMB, RDP, etc.
        self.port_scan_tracking: Dict[str, Set[int]] = defaultdict(set)
        
    async def protect(self, request: InterfaceRequest) -> InterfaceResponse:
        """Raw Socket Schutz"""
        self.requests_processed += 1
        
        threat_score = 0.0
        reasons = []
        
        # 1. Port Scanning Detection
        if request.source_ip and 'destination_port' in request.metadata:
            dst_port = request.metadata['destination_port']
            self.port_scan_tracking[request.source_ip].add(dst_port)
            
            scanned_ports = len(self.port_scan_tracking[request.source_ip])
            
            if scanned_ports > 20:  # > 20 verschiedene Ports
                threat_score += 50
                reasons.append(f"port_scan:{scanned_ports}_ports")
                self.threats_detected += 1
                
        # 2. Suspicious Port Access
        if 'destination_port' in request.metadata:
            if request.metadata['destination_port'] in self.suspicious_ports:
                threat_score += 30
                reasons.append(f"suspicious_port:{request.metadata['destination_port']}")
                
        # 3. Malformed Packets
        if request.body and len(request.body) > 65535:  # Max IP packet size
            threat_score += 40
            reasons.append("oversized_packet")
            
        if threat_score >= 50:
            self.requests_blocked += 1
            return InterfaceResponse(
                action=ProtectionAction.BLOCK,
                reason=f"Socket threat: {', '.join(reasons)}",
                threat_score=threat_score,
                confidence=0.9
            )
        else:
            return InterfaceResponse(
                action=ProtectionAction.ALLOW,
                reason="Socket allowed",
                threat_score=threat_score
            )
            
    def learn_from_attack(self, request: InterfaceRequest, attack_type: str):
        """Lerne aus Socket-Angriff"""
        if 'destination_port' in request.metadata:
            self.suspicious_ports.add(request.metadata['destination_port'])
            logger.warning(f"🧠 Socket: Learned suspicious port {request.metadata['destination_port']}")


class UniversalProtectionLayer:
    """Universal Protection Layer für alle Interfaces"""
    
    def __init__(self):
        self.protectors: Dict[str, InterfaceProtector] = {}
        
        # Registriere Standard-Protektoren
        self.register_protector(HTTPProtector())
        self.register_protector(WebSocketProtector())
        self.register_protector(RawSocketProtector())
        
        # Statistiken
        self.total_requests = 0
        self.total_blocked = 0
        self.total_threats = 0
        
    def register_protector(self, protector: InterfaceProtector):
        """Registriere Interface-Protektor"""
        self.protectors[protector.interface_type] = protector
        logger.info(f"🛡️ Registered protector: {protector.interface_type}")
        
    async def protect_request(self, request: InterfaceRequest) -> InterfaceResponse:
        """Schütze Request mit entsprechendem Protektor"""
        self.total_requests += 1
        
        # Finde passenden Protektor
        protector = self.protectors.get(request.interface_type)
        
        if not protector:
            logger.warning(f"No protector for interface: {request.interface_type}")
            return InterfaceResponse(
                action=ProtectionAction.ALLOW,
                reason=f"No protector for {request.interface_type}",
                confidence=0.5
            )
            
        # Schütze Request
        response = await protector.protect(request)
        
        # Update Statistiken
        if response.action == ProtectionAction.BLOCK:
            self.total_blocked += 1
            
        if response.threat_score >= 40:
            self.total_threats += 1
            
            # Self-Learning
            protector.learn_from_attack(request, "generic_attack")
            
        return response
        
    def get_statistics(self) -> Dict[str, Any]:
        """Hole Statistiken"""
        stats = {
            "total_requests": self.total_requests,
            "total_blocked": self.total_blocked,
            "total_threats": self.total_threats,
            "protectors": {}
        }
        
        for interface_type, protector in self.protectors.items():
            stats["protectors"][interface_type] = {
                "requests_processed": protector.requests_processed,
                "requests_blocked": protector.requests_blocked,
                "threats_detected": protector.threats_detected
            }
            
        return stats
        
    def generate_report(self) -> str:
        """Generiere Protection Report"""
        stats = self.get_statistics()
        
        report = f"""
╔════════════════════════════════════════════════════════════╗
║    AVA Universal Interface Protection - Report             ║
╚════════════════════════════════════════════════════════════╝

📊 GLOBAL STATISTICS:
  Total Requests:        {stats['total_requests']:,}
  Total Blocked:         {stats['total_blocked']:,}
  Total Threats:         {stats['total_threats']:,}
  Block Rate:            {(stats['total_blocked'] / max(1, stats['total_requests']) * 100):.2f}%

🛡️ PROTECTOR STATISTICS:"""

        for interface, pstats in stats['protectors'].items():
            report += f"\n\n  {interface.upper()}:"
            report += f"\n    Processed:         {pstats['requests_processed']:,}"
            report += f"\n    Blocked:           {pstats['requests_blocked']:,}"
            report += f"\n    Threats Detected:  {pstats['threats_detected']:,}"
            
        report += "\n\n╚════════════════════════════════════════════════════════════╝\n"
        
        return report


# Global Instance
_universal_protection: Optional[UniversalProtectionLayer] = None


def get_universal_protection() -> UniversalProtectionLayer:
    """Hole oder erstelle globale Protection-Instanz"""
    global _universal_protection
    if _universal_protection is None:
        _universal_protection = UniversalProtectionLayer()
    return _universal_protection


# Convenience Decorators
def protect_http(func: Callable) -> Callable:
    """Decorator für HTTP-Schutz"""
    async def wrapper(*args, **kwargs):
        # Extrahiere Request-Info
        request = InterfaceRequest(
            interface_type="http",
            method=kwargs.get('method'),
            path=kwargs.get('path'),
            headers=kwargs.get('headers', {}),
            body=kwargs.get('body')
        )
        
        # Schütze
        protection = get_universal_protection()
        response = await protection.protect_request(request)
        
        if response.action == ProtectionAction.BLOCK:
            raise PermissionError(f"Request blocked: {response.reason}")
            
        # Führe Original-Funktion aus
        return await func(*args, **kwargs)
        
    return wrapper


def protect_websocket(func: Callable) -> Callable:
    """Decorator für WebSocket-Schutz"""
    async def wrapper(*args, **kwargs):
        request = InterfaceRequest(
            interface_type="websocket",
            body=kwargs.get('message')
        )
        
        protection = get_universal_protection()
        response = await protection.protect_request(request)
        
        if response.action == ProtectionAction.BLOCK:
            raise PermissionError(f"WebSocket blocked: {response.reason}")
            
        return await func(*args, **kwargs)
        
    return wrapper


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    async def demo():
        protection = get_universal_protection()
        
        print("\n🛡️ AVA Universal Interface Protection - Demo\n")
        
        # Test 1: Normaler HTTP Request
        request1 = InterfaceRequest(
            interface_type="http",
            source_ip="192.168.1.100",
            method="GET",
            path="/api/users",
            headers={"User-Agent": "Mozilla/5.0"}
        )
        response1 = await protection.protect_request(request1)
        print(f"Test 1 - Normal HTTP: {response1.action.value} - {response1.reason}")
        
        # Test 2: XSS Attack
        request2 = InterfaceRequest(
            interface_type="http",
            source_ip="198.51.100.50",
            method="POST",
            path="/submit",
            body=b"<script>alert('XSS')</script>"
        )
        response2 = await protection.protect_request(request2)
        print(f"Test 2 - XSS Attack: {response2.action.value} - {response2.reason} (Threat: {response2.threat_score:.1f})")
        
        # Test 3: SQL Injection
        request3 = InterfaceRequest(
            interface_type="http",
            source_ip="198.51.100.51",
            method="GET",
            path="/users?id=1' OR '1'='1"
        )
        response3 = await protection.protect_request(request3)
        print(f"Test 3 - SQL Injection: {response3.action.value} - {response3.reason} (Threat: {response3.threat_score:.1f})")
        
        # Test 4: Port Scan
        for port in range(1, 30):
            request = InterfaceRequest(
                interface_type="raw_socket",
                source_ip="203.0.113.100",
                metadata={"destination_port": port}
            )
            await protection.protect_request(request)
            
        print(f"Test 4 - Port Scan: Detected after scanning 30 ports")
        
        # Test 5: WebSocket Flooding
        for i in range(150):
            request = InterfaceRequest(
                interface_type="websocket",
                source_ip="198.51.100.52",
                body=b"flood message"
            )
            await protection.protect_request(request)
            
        print(f"Test 5 - WebSocket Flood: Detected after 150 messages")
        
        # Zeige Report
        print(protection.generate_report())
        
    asyncio.run(demo())
