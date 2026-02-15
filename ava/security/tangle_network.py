#!/usr/bin/env python3
"""
AVA TANGLE SECURITY NETWORK v96.0
DAG-based Distributed Security Network (IOTA-inspired)

🌐 FEATURES:
- Directed Acyclic Graph (DAG) für Threat Propagation
- Feeless Threat Information Sharing  
- Tangle-like Distributed Consensus
- IoT Device Integration
- Self-validating Threat Network

Created by: Danny Nico Hildebrand
Date: 2026-02-15
"""

import hashlib
import json
import time
import random
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from collections import deque


@dataclass
class Transaction:
    """Eine Transaction im Tangle (Threat Information)"""
    tx_id: str
    timestamp: float
    threat_data: Dict
    approves: List[str] = field(default_factory=list)  # Approved transactions (DAG edges)
    weight: int = 1
    cumulative_weight: int = 1
    confirmed: bool = False
    hash: str = ""
    
    def calculate_hash(self) -> str:
        """Berechnet Transaction Hash"""
        tx_string = json.dumps({
            'tx_id': self.tx_id,
            'timestamp': self.timestamp,
            'threat_data': self.threat_data,
            'approves': sorted(self.approves)
        }, sort_keys=True)
        return hashlib.sha256(tx_string.encode()).hexdigest()
    
    def __post_init__(self):
        if not self.hash:
            self.hash = self.calculate_hash()


class TangleSecurityNetwork:
    """
    🌐 TANGLE SECURITY NETWORK
    
    DAG-basiertes verteiltes Sicherheitsnetzwerk
    Jede neue Bedrohung validiert 2 vorherige (wie IOTA Tangle)
    """
    
    def __init__(self):
        self.transactions: Dict[str, Transaction] = {}
        self.tips: Set[str] = set()  # Unconfirmed tips
        self.genesis_tx: Optional[Transaction] = None
        
        # Statistics
        self.total_transactions = 0
        self.confirmed_count = 0
        self.pending_count = 0
        
        self._create_genesis()
        
        print("🌐 TANGLE SECURITY NETWORK INITIALIZED")
        print(f"   Genesis TX: {self.genesis_tx.tx_id[:16]}...")
        print("   Topology: Directed Acyclic Graph (DAG)")
    
    def _create_genesis(self):
        """Erstellt Genesis Transaction"""
        self.genesis_tx = Transaction(
            tx_id="genesis_" + hashlib.sha256(b"AVA_v96_GENESIS").hexdigest()[:16],
            timestamp=time.time(),
            threat_data={
                'type': 'GENESIS',
                'message': 'AVA Tangle Security v96.0 Genesis',
                'creator': 'Danny Nico Hildebrand',
                'network': 'DAG-based Distributed Security'
            },
            approves=[],
            weight=100,
            cumulative_weight=100,
            confirmed=True
        )
        self.genesis_tx.hash = self.genesis_tx.calculate_hash()
        
        self.transactions[self.genesis_tx.tx_id] = self.genesis_tx
        self.tips.add(self.genesis_tx.tx_id)
        self.total_transactions = 1
        self.confirmed_count = 1
    
    def _select_tips(self, count: int = 2) -> List[str]:
        """
        Wählt Tips für Approval (MCMC-basiert)
        Tangle: Jede neue TX approved 2 vorherige
        """
        if len(self.tips) == 0:
            return [self.genesis_tx.tx_id]
        
        if len(self.tips) <= count:
            return list(self.tips)
        
        # Weighted random selection (prefer higher weights)
        tip_weights = []
        tip_list = list(self.tips)
        
        for tip_id in tip_list:
            tx = self.transactions[tip_id]
            tip_weights.append(tx.cumulative_weight)
        
        # Random weighted selection
        selected = []
        for _ in range(min(count, len(tip_list))):
            if not tip_list:
                break
            chosen_idx = random.choices(range(len(tip_list)), weights=tip_weights, k=1)[0]
            selected.append(tip_list.pop(chosen_idx))
            tip_weights.pop(chosen_idx)
        
        return selected
    
    def add_threat_transaction(self, threat_data: Dict) -> Transaction:
        """
        Fügt neue Threat Transaction zum Tangle hinzu
        Approved 2 vorherige Transactions (DAG)
        """
        # Select 2 tips to approve
        approved_tips = self._select_tips(2)
        
        # Create new transaction
        tx_id = hashlib.sha256(
            f"{time.time()}:{json.dumps(threat_data)}".encode()
        ).hexdigest()[:16]
        
        new_tx = Transaction(
            tx_id=tx_id,
            timestamp=time.time(),
            threat_data=threat_data,
            approves=approved_tips,
            weight=1
        )
        
        # Calculate cumulative weight (sum of approved + own)
        cumulative = new_tx.weight
        for approved_id in approved_tips:
            if approved_id in self.transactions:
                cumulative += self.transactions[approved_id].cumulative_weight
        new_tx.cumulative_weight = cumulative
        
        # Add to tangle
        self.transactions[tx_id] = new_tx
        self.tips.add(tx_id)
        self.total_transactions += 1
        self.pending_count += 1
        
        # Remove approved tips (no longer tips)
        for approved_id in approved_tips:
            if approved_id in self.tips:
                self.tips.discard(approved_id)
        
        # Update weights of approved parents
        self._update_cumulative_weights(tx_id)
        
        # Check confirmation
        self._check_confirmation(tx_id)
        
        print(f"💠 Threat TX added to Tangle")
        print(f"   TX ID: {tx_id}")
        print(f"   Approved: {[a[:8]+'...' for a in approved_tips]}")
        print(f"   Weight: {new_tx.weight}, Cumulative: {new_tx.cumulative_weight}")
        
        return new_tx
    
    def _update_cumulative_weights(self, tx_id: str):
        """Updated cumulative weights aller ancestors"""
        queue = deque([tx_id])
        visited = set()
        
        while queue:
            current_id = queue.popleft()
            if current_id in visited:
                continue
            visited.add(current_id)
            
            current_tx = self.transactions[current_id]
            
            # Update parents
            for parent_id in current_tx.approves:
                if parent_id in self.transactions:
                    parent_tx = self.transactions[parent_id]
                    parent_tx.cumulative_weight += 1
                    queue.append(parent_id)
    
    def _check_confirmation(self, tx_id: str, threshold: int = 5):
        """
        Prüft ob Transaction confirmed ist
        Confirmed = cumulative_weight >= threshold
        """
        tx = self.transactions[tx_id]
        
        if not tx.confirmed and tx.cumulative_weight >= threshold:
            tx.confirmed = True
            self.confirmed_count += 1
            self.pending_count -= 1
            
            print(f"✅ TX CONFIRMED: {tx_id[:16]}... (weight: {tx.cumulative_weight})")
    
    def get_confirmation_rate(self) -> float:
        """Berechnet Confirmation Rate"""
        if self.total_transactions == 0:
            return 0.0
        return (self.confirmed_count / self.total_transactions) * 100
    
    def get_tangle_statistics(self) -> Dict:
        """Gibt Tangle Statistiken zurück"""
        return {
            'total_transactions': self.total_transactions,
            'confirmed': self.confirmed_count,
            'pending': self.pending_count,
            'tips': len(self.tips),
            'confirmation_rate': f"{self.get_confirmation_rate():.1f}%",
            'average_weight': sum(tx.cumulative_weight for tx in self.transactions.values()) / len(self.transactions) if self.transactions else 0
        }
    
    def visualize_tangle(self, filename: str = "tangle_visualization.json"):
        """Exportiert Tangle für Visualisierung"""
        nodes = []
        edges = []
        
        for tx_id, tx in self.transactions.items():
            nodes.append({
                'id': tx_id,
                'timestamp': tx.timestamp,
                'threat_type': tx.threat_data.get('type', 'unknown'),
                'weight': tx.weight,
                'cumulative_weight': tx.cumulative_weight,
                'confirmed': tx.confirmed
            })
            
            for approved_id in tx.approves:
                edges.append({
                    'from': tx_id,
                    'to': approved_id
                })
        
        tangle_data = {
            'nodes': nodes,
            'edges': edges,
            'statistics': self.get_tangle_statistics()
        }
        
        with open(filename, 'w') as f:
            json.dump(tangle_data, f, indent=2)
        
        print(f"📊 Tangle visualized in {filename}")
        return filename


@dataclass
class IoTDevice:
    """IoT-Gerät im Security Network"""
    device_id: str
    device_type: str  # sensor, camera, gateway, etc.
    ip_address: str
    firmware_version: str
    security_score: float = 100.0
    last_seen: float = field(default_factory=time.time)
    threats_detected: int = 0
    status: str = "active"


class IoTSecurityManager:
    """
    🔌 IoT SECURITY MANAGER
    
    Verwaltet IoT-Geräte im Security Network
    Integriert mit Tangle für Threat Propagation
    """
    
    def __init__(self, tangle: TangleSecurityNetwork):
        self.tangle = tangle
        self.devices: Dict[str, IoTDevice] = {}
        self.device_count = 0
        
        print("🔌 IoT SECURITY MANAGER INITIALIZED")
    
    def register_device(self, device_type: str, ip_address: str,
                       firmware_version: str = "1.0.0") -> IoTDevice:
        """Registriert IoT-Gerät"""
        device_id = hashlib.sha256(
            f"{device_type}:{ip_address}:{time.time()}".encode()
        ).hexdigest()[:12]
        
        device = IoTDevice(
            device_id=device_id,
            device_type=device_type,
            ip_address=ip_address,
            firmware_version=firmware_version
        )
        
        self.devices[device_id] = device
        self.device_count += 1
        
        # Add to Tangle
        self.tangle.add_threat_transaction({
            'type': 'IOT_DEVICE_REGISTERED',
            'device_id': device_id,
            'device_type': device_type,
            'ip': ip_address,
            'firmware': firmware_version
        })
        
        print(f"🔌 IoT Device registered: {device_id}")
        print(f"   Type: {device_type}")
        print(f"   IP: {ip_address}")
        
        return device
    
    def report_iot_threat(self, device_id: str, threat_data: Dict):
        """IoT-Gerät meldet Bedrohung"""
        if device_id not in self.devices:
            print(f"❌ Unknown device: {device_id}")
            return
        
        device = self.devices[device_id]
        device.threats_detected += 1
        device.security_score = max(0, device.security_score - 5)
        
        # Propagate through Tangle
        self.tangle.add_threat_transaction({
            'type': 'IOT_THREAT_DETECTED',
            'device_id': device_id,
            'device_type': device.device_type,
            'ip': device.ip_address,
            'threat_data': threat_data,
            'security_score': device.security_score
        })
        
        print(f"⚠️  IoT Threat detected by {device_id}")
        print(f"   New Security Score: {device.security_score}")
    
    def get_device_statistics(self) -> Dict:
        """Gibt IoT-Statistiken zurück"""
        return {
            'total_devices': self.device_count,
            'active_devices': len([d for d in self.devices.values() if d.status == 'active']),
            'total_threats_detected': sum(d.threats_detected for d in self.devices.values()),
            'average_security_score': sum(d.security_score for d in self.devices.values()) / len(self.devices) if self.devices else 0,
            'devices_by_type': {}
        }


# Global instances
_tangle_network = None
_iot_manager = None


def get_tangle_network() -> TangleSecurityNetwork:
    """Singleton für Tangle Network"""
    global _tangle_network
    if _tangle_network is None:
        _tangle_network = TangleSecurityNetwork()
    return _tangle_network


def get_iot_manager() -> IoTSecurityManager:
    """Singleton für IoT Manager"""
    global _iot_manager
    if _iot_manager is None:
        tangle = get_tangle_network()
        _iot_manager = IoTSecurityManager(tangle)
    return _iot_manager


if __name__ == "__main__":
    print("\n" + "="*80)
    print("🌐 TANGLE SECURITY NETWORK v96.0 - DEMO")
    print("="*80 + "\n")
    
    # Initialize
    tangle = get_tangle_network()
    iot_mgr = get_iot_manager()
    
    print("\n" + "-"*80 + "\n")
    
    # Register IoT devices
    print("DEMO: IoT Device Registration")
    camera1 = iot_mgr.register_device("security_camera", "192.168.1.10")
    sensor1 = iot_mgr.register_device("motion_sensor", "192.168.1.20")
    gateway1 = iot_mgr.register_device("iot_gateway", "192.168.1.1")
    
    print("\n" + "-"*80 + "\n")
    
    # Add threat transactions
    print("DEMO: Threat Transaction Propagation")
    for i in range(10):
        tangle.add_threat_transaction({
            'type': 'NETWORK_THREAT',
            'severity': random.choice(['LOW', 'MEDIUM', 'HIGH']),
            'source': f'node_{i}',
            'timestamp': time.time()
        })
        time.sleep(0.1)  # Small delay
    
    print("\n" + "-"*80 + "\n")
    
    # IoT threat detection
    print("DEMO: IoT Threat Detection")
    iot_mgr.report_iot_threat(camera1.device_id, {
        'attack_type': 'unauthorized_access',
        'severity': 'HIGH'
    })
    
    print("\n" + "-"*80 + "\n")
    
    # Statistics
    print("📊 TANGLE STATISTICS:")
    stats = tangle.get_tangle_statistics()
    for key, value in stats.items():
        print(f"   {key}: {value}")
    
    print("\n📊 IoT STATISTICS:")
    iot_stats = iot_mgr.get_device_statistics()
    for key, value in iot_stats.items():
        print(f"   {key}: {value}")
    
    print("\n" + "-"*80 + "\n")
    
    # Visualize
    tangle.visualize_tangle()
