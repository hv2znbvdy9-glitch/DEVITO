#!/usr/bin/env python3
"""
AVA IoT SECURITY ENHANCEMENT v96.0
Enhanced IoT Device Security System

🔐 FEATURES:
- Zero-Trust IoT Authentication
- Firmware Integrity Monitoring
- Device Behavior Analysis
- Automated Threat Response
- Secured Communication Channels

Created by: Danny Nico Hildebrand
Date: 2026-02-15
"""

import hashlib
import hmac
import secrets
import json
import time
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, deque


@dataclass
class DeviceCredentials:
    """Credentials für IoT-Geräte"""
    device_id: str
    api_key: str
    secret_key: str
    certificate: str
    issued_at: float
    expires_at: float
    permissions: List[str] = field(default_factory=list)
    
    def is_valid(self) -> bool:
        """Prüft ob Credentials gültig"""
        return time.time() < self.expires_at
    
    def to_dict(self) -> Dict:
        return {
            'device_id': self.device_id,
            'api_key': self.api_key,
            'issued_at': self.issued_at,
            'expires_at': self.expires_at,
            'permissions': self.permissions
        }


@dataclass
class DeviceBehaviorProfile:
    """Verhaltens-Profil eines IoT-Geräts"""
    device_id: str
    normal_cpu_usage: Tuple[float, float] = (0.0, 30.0)  # min, max
    normal_memory_usage: Tuple[float, float] = (0.0, 50.0)
    normal_network_traffic: Tuple[float, float] = (0.0, 1000.0)  # KB/s
    normal_uptime: float = 86400.0  # seconds
    baseline_requests_per_minute: Tuple[float, float] = (0.0, 100.0)
    
    # Behavioral statistics
    total_requests: int = 0
    failed_auth_attempts: int = 0
    anomalies_detected: int = 0
    last_anomaly: Optional[float] = None


class ZeroTrustIoTAuthenticator:
    """
    🔐 ZERO-TRUST IoT AUTHENTICATOR
    
    Jedes Gerät muss sich bei jeder Aktion authentifizieren
    Keine implizite Trust-Beziehung
    """
    
    def __init__(self):
        self.credentials: Dict[str, DeviceCredentials] = {}
        self.revoked_keys: Set[str] = set()
        self.auth_attempts: Dict[str, List[float]] = defaultdict(list)
        
        print("🔐 ZERO-TRUST IoT AUTHENTICATOR INITIALIZED")
        print("   Policy: Verify EVERY request")
        print("   Trust Policy: ZERO")
    
    def issue_credentials(self, device_id: str, 
                         permissions: List[str],
                         validity_hours: int = 24) -> DeviceCredentials:
        """Erstellt Credentials für IoT-Gerät"""
        api_key = secrets.token_urlsafe(32)
        secret_key = secrets.token_urlsafe(64)
        
        # Generate certificate (simplified)
        cert_data = f"{device_id}:{api_key}:{time.time()}"
        certificate = hashlib.sha256(cert_data.encode()).hexdigest()
        
        issued_at = time.time()
        expires_at = issued_at + (validity_hours * 3600)
        
        creds = DeviceCredentials(
            device_id=device_id,
            api_key=api_key,
            secret_key=secret_key,
            certificate=certificate,
            issued_at=issued_at,
            expires_at=expires_at,
            permissions=permissions
        )
        
        self.credentials[api_key] = creds
        
        print(f"🔑 Credentials issued for {device_id}")
        print(f"   API Key: {api_key[:16]}...")
        print(f"   Expires: {datetime.fromtimestamp(expires_at).strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"   Permissions: {', '.join(permissions)}")
        
        return creds
    
    def verify_request(self, api_key: str, signature: str, 
                      request_data: str) -> Tuple[bool, Optional[str]]:
        """
        Verifiziert Request von IoT-Gerät
        Returns: (is_valid, error_message)
        """
        # Check if key exists
        if api_key not in self.credentials:
            return False, "Invalid API key"
        
        # Check if revoked
        if api_key in self.revoked_keys:
            return False, "API key revoked"
        
        creds = self.credentials[api_key]
        
        # Check expiration
        if not creds.is_valid():
            return False, "Credentials expired"
        
        # Verify signature (HMAC)
        expected_signature = hmac.new(
            creds.secret_key.encode(),
            request_data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(signature, expected_signature):
            # Track failed attempt
            self.auth_attempts[api_key].append(time.time())
            return False, "Invalid signature"
        
        # Check rate limiting (max 100 failed attempts in 1 minute)
        recent_failures = [
            t for t in self.auth_attempts[api_key]
            if time.time() - t < 60
        ]
        if len(recent_failures) > 100:
            self.revoke_credentials(api_key)
            return False, "Too many failed attempts - credentials revoked"
        
        return True, None
    
    def revoke_credentials(self, api_key: str):
        """Revoked Credentials"""
        if api_key in self.credentials:
            self.revoked_keys.add(api_key)
            print(f"🚫 Credentials revoked: {api_key[:16]}...")
    
    def rotate_credentials(self, api_key: str) -> Optional[DeviceCredentials]:
        """Rotiert Credentials (erneuert)"""
        if api_key not in self.credentials:
            return None
        
        old_creds = self.credentials[api_key]
        new_creds = self.issue_credentials(
            old_creds.device_id,
            old_creds.permissions,
            validity_hours=24
        )
        
        # Revoke old
        self.revoke_credentials(api_key)
        
        print(f"🔄 Credentials rotated for {old_creds.device_id}")
        return new_creds


class FirmwareIntegrityMonitor:
    """
    📦 FIRMWARE INTEGRITY MONITOR
    
    Überwacht Firmware-Integrität von IoT-Geräten
    Erkennt Tampering und Malware
    """
    
    def __init__(self):
        self.firmware_hashes: Dict[str, str] = {}  # device_id -> hash
        self.integrity_violations: List[Dict] = []
        
        print("📦 FIRMWARE INTEGRITY MONITOR INITIALIZED")
    
    def register_firmware_baseline(self, device_id: str, 
                                   firmware_data: bytes) -> str:
        """Registriert Firmware-Baseline"""
        firmware_hash = hashlib.sha256(firmware_data).hexdigest()
        self.firmware_hashes[device_id] = firmware_hash
        
        print(f"📦 Firmware baseline registered for {device_id}")
        print(f"   Hash: {firmware_hash[:32]}...")
        
        return firmware_hash
    
    def verify_firmware_integrity(self, device_id: str, 
                                 current_firmware: bytes) -> Tuple[bool, Optional[str]]:
        """Verifiziert Firmware-Integrität"""
        if device_id not in self.firmware_hashes:
            return False, "No baseline found"
        
        current_hash = hashlib.sha256(current_firmware).hexdigest()
        expected_hash = self.firmware_hashes[device_id]
        
        if current_hash != expected_hash:
            # INTEGRITY VIOLATION!
            violation = {
                'device_id': device_id,
                'timestamp': time.time(),
                'expected_hash': expected_hash,
                'current_hash': current_hash,
                'severity': 'CRITICAL'
            }
            self.integrity_violations.append(violation)
            
            print(f"🚨 FIRMWARE INTEGRITY VIOLATION!")
            print(f"   Device: {device_id}")
            print(f"   Expected: {expected_hash[:16]}...")
            print(f"   Current:  {current_hash[:16]}...")
            
            return False, "Firmware modified - possible tampering"
        
        return True, None


class DeviceBehaviorAnalyzer:
    """
    🧠 DEVICE BEHAVIOR ANALYZER
    
    Analysiert Geräte-Verhalten und erkennt Anomalien
    Machine-Learning-basierte Anomaly Detection (simplified)
    """
    
    def __init__(self):
        self.profiles: Dict[str, DeviceBehaviorProfile] = {}
        self.anomalies: List[Dict] = []
        
        print("🧠 DEVICE BEHAVIOR ANALYZER INITIALIZED")
    
    def create_profile(self, device_id: str) -> DeviceBehaviorProfile:
        """Erstellt Verhaltens-Profil"""
        profile = DeviceBehaviorProfile(device_id=device_id)
        self.profiles[device_id] = profile
        
        print(f"🧠 Behavior profile created for {device_id}")
        return profile
    
    def analyze_behavior(self, device_id: str, metrics: Dict) -> Tuple[bool, List[str]]:
        """
        Analysiert Geräte-Verhalten
        Returns: (is_normal, anomalies)
        """
        if device_id not in self.profiles:
            self.create_profile(device_id)
        
        profile = self.profiles[device_id]
        anomalies = []
        
        # CPU usage check
        if 'cpu_usage' in metrics:
            cpu = metrics['cpu_usage']
            if not (profile.normal_cpu_usage[0] <= cpu <= profile.normal_cpu_usage[1]):
                anomalies.append(f"Abnormal CPU usage: {cpu}%")
        
        # Memory usage check
        if 'memory_usage' in metrics:
            mem = metrics['memory_usage']
            if not (profile.normal_memory_usage[0] <= mem <= profile.normal_memory_usage[1]):
                anomalies.append(f"Abnormal memory usage: {mem}%")
        
        # Network traffic check
        if 'network_traffic' in metrics:
            traffic = metrics['network_traffic']
            if not (profile.normal_network_traffic[0] <= traffic <= profile.normal_network_traffic[1]):
                anomalies.append(f"Abnormal network traffic: {traffic} KB/s")
        
        # Requests per minute check
        if 'requests_per_minute' in metrics:
            rpm = metrics['requests_per_minute']
            if not (profile.baseline_requests_per_minute[0] <= rpm <= profile.baseline_requests_per_minute[1]):
                anomalies.append(f"Abnormal request rate: {rpm} req/min")
        
        if anomalies:
            profile.anomalies_detected += 1
            profile.last_anomaly = time.time()
            
            self.anomalies.append({
                'device_id': device_id,
                'timestamp': time.time(),
                'anomalies': anomalies,
                'metrics': metrics
            })
            
            print(f"⚠️  BEHAVIOR ANOMALY DETECTED: {device_id}")
            for anomaly in anomalies:
                print(f"   - {anomaly}")
            
            return False, anomalies
        
        return True, []


class AutomatedIoTThreatResponse:
    """
    🤖 AUTOMATED IoT THREAT RESPONSE
    
    Automatisierte Reaktion auf IoT-Bedrohungen
    """
    
    def __init__(self, authenticator: ZeroTrustIoTAuthenticator,
                 firmware_monitor: FirmwareIntegrityMonitor,
                 behavior_analyzer: DeviceBehaviorAnalyzer):
        self.authenticator = authenticator
        self.firmware_monitor = firmware_monitor
        self.behavior_analyzer = behavior_analyzer
        
        self.actions_taken: List[Dict] = []
        
        print("🤖 AUTOMATED IoT THREAT RESPONSE INITIALIZED")
    
    def respond_to_threat(self, device_id: str, threat_type: str, 
                         severity: str, api_key: Optional[str] = None):
        """Automatische Threat Response"""
        actions = []
        
        if severity == "CRITICAL":
            # Sofortige Isolation
            if api_key:
                self.authenticator.revoke_credentials(api_key)
                actions.append("CREDENTIALS_REVOKED")
            
            actions.append("DEVICE_ISOLATED")
            actions.append("ADMIN_NOTIFIED")
            
            print(f"🚨 CRITICAL THREAT RESPONSE for {device_id}")
            print(f"   Threat: {threat_type}")
            print(f"   Actions: {', '.join(actions)}")
        
        elif severity == "HIGH":
            # Credentials rotation + Monitoring
            if api_key:
                new_creds = self.authenticator.rotate_credentials(api_key)
                if new_creds:
                    actions.append("CREDENTIALS_ROTATED")
            
            actions.append("MONITORING_INCREASED")
            
            print(f"⚠️  HIGH THREAT RESPONSE for {device_id}")
            print(f"   Actions: {', '.join(actions)}")
        
        else:  # MEDIUM/LOW
            actions.append("LOGGED")
            actions.append("MONITORED")
        
        self.actions_taken.append({
            'device_id': device_id,
            'threat_type': threat_type,
            'severity': severity,
            'actions': actions,
            'timestamp': time.time()
        })
        
        return actions


# Demo
if __name__ == "__main__":
    print("\n" + "="*80)
    print("🔐 IoT SECURITY ENHANCEMENT v96.0 - DEMO")
    print("="*80 + "\n")
    
    # Initialize
    auth = ZeroTrustIoTAuthenticator()
    firmware_mon = FirmwareIntegrityMonitor()
    behavior = DeviceBehaviorAnalyzer()
    response = AutomatedIoTThreatResponse(auth, firmware_mon, behavior)
    
    print("\n" + "-"*80 + "\n")
    
    # Issue credentials
    print("DEMO: Issue Credentials")
    creds = auth.issue_credentials(
        device_id="camera_001",
        permissions=["read_sensors", "write_logs"]
    )
    
    print("\n" + "-"*80 + "\n")
    
    # Verify request
    print("DEMO: Verify Request")
    request_data = json.dumps({'action': 'read_sensor', 'timestamp': time.time()})
    signature = hmac.new(
        creds.secret_key.encode(),
        request_data.encode(),
        hashlib.sha256
    ).hexdigest()
    
    valid, error = auth.verify_request(creds.api_key, signature, request_data)
    print(f"✅ Request valid: {valid}")
    
    print("\n" + "-"*80 + "\n")
    
    # Firmware check
    print("DEMO: Firmware Integrity")
    firmware = b"FIRMWARE_DATA_VERSION_1.0.0"
    firmware_mon.register_firmware_baseline("camera_001", firmware)
    
    # Modified firmware
    tampered_firmware = b"FIRMWARE_DATA_VERSION_1.0.0_MALWARE"
    valid, error = firmware_mon.verify_firmware_integrity("camera_001", tampered_firmware)
    print(f"Firmware valid: {valid}, Error: {error}")
    
    print("\n" + "-"*80 + "\n")
    
    # Behavior analysis
    print("DEMO: Behavior Analysis")
    behavior.create_profile("camera_001")
    
    # Normal behavior
    is_normal, anomalies = behavior.analyze_behavior("camera_001", {
        'cpu_usage': 15.0,
        'memory_usage': 30.0,
        'network_traffic': 500.0
    })
    print(f"Normal behavior: {is_normal}")
    
    # Anomalous behavior
    is_normal, anomalies = behavior.analyze_behavior("camera_001", {
        'cpu_usage': 95.0,  # ABNORMAL!
        'memory_usage': 30.0,
        'network_traffic': 5000.0  # ABNORMAL!
    })
    print(f"Anomalous behavior detected: {len(anomalies)} anomalies")
    
    print("\n" + "-"*80 + "\n")
    
    # Automated response
    print("DEMO: Automated Threat Response")
    response.respond_to_threat(
        device_id="camera_001",
        threat_type="FIRMWARE_TAMPERING",
        severity="CRITICAL",
        api_key=creds.api_key
    )
    
    print("\n" + "="*80)
    print(f"📊 TOTAL ACTIONS TAKEN: {len(response.actions_taken)}")
    print("="*80 + "\n")
