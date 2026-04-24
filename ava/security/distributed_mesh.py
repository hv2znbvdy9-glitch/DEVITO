"""
AVA Distributed Security Architecture
======================================
Koordiniert Sicherheitsschutz über alle Schnittstellen:
- Online/Offline Nodes
- Local/Dezentral/Zentral
- Server/Cloud/Edge
- Alle Netzwerk-Interfaces

Selbst-organisierende, adaptive Security Mesh!
"""

import asyncio
import json
import logging
import socket
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set
from uuid import uuid4

logger = logging.getLogger(__name__)


class NodeType(Enum):
    """Art des Security-Knotens"""

    LOCAL = "local"
    EDGE = "edge"
    CLOUD = "cloud"
    PEER = "peer"
    COORDINATOR = "coordinator"


class InterfaceType(Enum):
    """Netzwerk-Interface Typen"""

    HTTP = "http"
    HTTPS = "https"
    WEBSOCKET = "websocket"
    GRPC = "grpc"
    MQTT = "mqtt"
    RAW_SOCKET = "raw_socket"
    UNIX_SOCKET = "unix_socket"
    BLUETOOTH = "bluetooth"
    ZIGBEE = "zigbee"
    CUSTOM = "custom"


class SecurityState(Enum):
    """Sicherheitszustand"""

    SECURE = "secure"
    MONITORING = "monitoring"
    THREATENED = "threatened"
    UNDER_ATTACK = "under_attack"
    ISOLATED = "isolated"


@dataclass
class SecurityEvent:
    """Sicherheitsereignis"""

    event_id: str = field(default_factory=lambda: str(uuid4())[:8])
    timestamp: datetime = field(default_factory=datetime.utcnow)
    source_node: str = ""
    event_type: str = ""
    severity: int = 5  # 1-10
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityEvent":
        data = data.copy()
        data["timestamp"] = datetime.fromisoformat(data["timestamp"])
        return cls(**data)


@dataclass
class SecurityNode:
    """Einzelner Security-Knoten im Mesh"""

    node_id: str
    node_type: NodeType
    hostname: str
    ip_address: str
    interfaces: List[InterfaceType] = field(default_factory=list)
    state: SecurityState = SecurityState.MONITORING
    trust_score: float = 50.0  # 0-100
    last_seen: datetime = field(default_factory=datetime.utcnow)
    events_processed: int = 0
    threats_blocked: int = 0
    uptime_seconds: int = 0
    load: float = 0.0  # 0-1

    def is_healthy(self) -> bool:
        """Prüfe ob Knoten gesund ist"""
        age = (datetime.utcnow() - self.last_seen).seconds
        return (
            age < 60  # Gesehen in letzten 60s
            and self.state != SecurityState.ISOLATED
            and self.trust_score > 30
            and self.load < 0.9
        )

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["node_type"] = self.node_type.value
        data["interfaces"] = [i.value for i in self.interfaces]
        data["state"] = self.state.value
        data["last_seen"] = self.last_seen.isoformat()
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecurityNode":
        data = data.copy()
        data["node_type"] = NodeType(data["node_type"])
        data["interfaces"] = [InterfaceType(i) for i in data["interfaces"]]
        data["state"] = SecurityState(data["state"])
        data["last_seen"] = datetime.fromisoformat(data["last_seen"])
        return cls(**data)


@dataclass
class SecurityPolicy:
    """Verteilte Security-Policy"""

    policy_id: str
    name: str
    enabled: bool = True
    priority: int = 5  # 1-10, höher = wichtiger
    conditions: Dict[str, Any] = field(default_factory=dict)
    actions: List[str] = field(default_factory=list)
    applied_to: List[str] = field(default_factory=list)  # Node IDs
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["created_at"] = self.created_at.isoformat()
        return data


class DistributedSecurityMesh:
    """Verteiltes Self-Healing Security Mesh"""

    def __init__(self, node_id: Optional[str] = None, node_type: NodeType = NodeType.LOCAL):
        self.node_id = node_id or f"{node_type.value}_{uuid4().hex[:8]}"
        self.node_type = node_type

        # Eigener Knoten
        self.local_node = SecurityNode(
            node_id=self.node_id,
            node_type=node_type,
            hostname=socket.gethostname(),
            ip_address=self._get_local_ip(),
        )

        # Mesh-Topologie
        self.nodes: Dict[str, SecurityNode] = {self.node_id: self.local_node}
        self.policies: Dict[str, SecurityPolicy] = {}

        # Event-System
        self.event_queue: deque = deque(maxlen=10000)
        self.event_handlers: Dict[str, List[Callable]] = defaultdict(list)

        # Bedrohungs-Intelligenz (geteilt)
        self.shared_blacklist_ips: Set[str] = set()
        self.shared_blacklist_macs: Set[str] = set()
        self.shared_threat_signatures: Dict[str, int] = {}

        # Statistiken
        self.total_events = 0
        self.total_threats_global = 0

        # Persistenz
        self.data_dir = Path.home() / ".ava" / "distributed_security"
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.load_state()

    def _get_local_ip(self) -> str:
        """Ermittle lokale IP"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def load_state(self):
        """Lade persistierten Zustand"""
        state_file = self.data_dir / f"mesh_{self.node_id}.json"

        if state_file.exists():
            try:
                with open(state_file, "r") as f:
                    state = json.load(f)

                    # Lade Nodes
                    if "nodes" in state:
                        self.nodes = {
                            nid: SecurityNode.from_dict(ndata)
                            for nid, ndata in state["nodes"].items()
                        }

                    # Lade Policies
                    if "policies" in state:
                        for pid, pdata in state["policies"].items():
                            pdata["created_at"] = datetime.fromisoformat(pdata["created_at"])
                            self.policies[pid] = SecurityPolicy(**pdata)

                    # Lade Shared Intelligence
                    self.shared_blacklist_ips = set(state.get("blacklist_ips", []))
                    self.shared_blacklist_macs = set(state.get("blacklist_macs", []))
                    self.shared_threat_signatures = state.get("threat_signatures", {})

                logger.info(
                    f"✅ Mesh state loaded: {len(self.nodes)} nodes, "
                    f"{len(self.policies)} policies, "
                    f"{len(self.shared_blacklist_ips)} blacklisted IPs"
                )
            except Exception as e:
                logger.error(f"Failed to load mesh state: {e}")

    def save_state(self):
        """Speichere Zustand"""
        state_file = self.data_dir / f"mesh_{self.node_id}.json"

        try:
            state = {
                "node_id": self.node_id,
                "nodes": {nid: node.to_dict() for nid, node in self.nodes.items()},
                "policies": {pid: policy.to_dict() for pid, policy in self.policies.items()},
                "blacklist_ips": list(self.shared_blacklist_ips),
                "blacklist_macs": list(self.shared_blacklist_macs),
                "threat_signatures": self.shared_threat_signatures,
                "timestamp": datetime.utcnow().isoformat(),
            }

            with open(state_file, "w") as f:
                json.dump(state, f, indent=2)

            logger.info("💾 Mesh state saved")
        except Exception as e:
            logger.error(f"Failed to save mesh state: {e}")

    def register_node(self, node: SecurityNode):
        """Registriere neuen Knoten im Mesh"""
        self.nodes[node.node_id] = node
        logger.info(
            f"➕ Node registered: {node.node_id} ({node.node_type.value}) @ {node.ip_address}"
        )

        # Synchronisiere Threat Intelligence
        self._sync_threat_intelligence_to_node(node.node_id)

        self.save_state()

    def unregister_node(self, node_id: str):
        """Entferne Knoten aus Mesh"""
        if node_id in self.nodes:
            del self.nodes[node_id]
            logger.info(f"➖ Node unregistered: {node_id}")
            self.save_state()

    def add_policy(self, policy: SecurityPolicy):
        """Füge Security-Policy hinzu"""
        self.policies[policy.policy_id] = policy
        logger.info(f"📜 Policy added: {policy.name} (Priority: {policy.priority})")

        # Verteile Policy an alle Knoten
        self._distribute_policy(policy)

        self.save_state()

    def _distribute_policy(self, policy: SecurityPolicy):
        """Verteile Policy an Mesh-Knoten"""
        # In Produktion: Sende Policy an Remote-Knoten via RPC/HTTP
        for node_id in policy.applied_to:
            if node_id in self.nodes:
                logger.info(f"  → Distributing policy to {node_id}")
                # TODO: Implement actual distribution

    def publish_event(self, event: SecurityEvent):
        """Publiziere Security-Event ins Mesh"""
        event.source_node = self.node_id
        self.event_queue.append(event)
        self.total_events += 1

        # Trigger Event Handlers
        for handler in self.event_handlers.get(event.event_type, []):
            try:
                handler(event)
            except Exception as e:
                logger.error(f"Event handler error: {e}")

        # Propagiere kritische Events
        if event.severity >= 8:
            self._propagate_event(event)

    def _propagate_event(self, event: SecurityEvent):
        """Propagiere Event zu anderen Knoten"""
        # In Produktion: Sende an andere Mesh-Knoten
        logger.warning(
            f"🔄 Propagating critical event: {event.event_type} (Severity: {event.severity})"
        )

    def subscribe_event(self, event_type: str, handler: Callable):
        """Abonniere Event-Typ"""
        self.event_handlers[event_type].append(handler)
        logger.info(f"📡 Subscribed to event: {event_type}")

    def share_blacklist_ip(self, ip: str, reason: str):
        """Teile IP-Blacklist global"""
        self.shared_blacklist_ips.add(ip)
        logger.warning(f"🌐 Shared IP blacklist: {ip} - {reason}")

        # Publiziere Event
        event = SecurityEvent(
            source_node=self.node_id,
            event_type="ip_blacklisted",
            severity=8,
            description=f"IP blacklisted globally: {ip}",
            metadata={"ip": ip, "reason": reason},
        )
        self.publish_event(event)

        self.save_state()

    def share_blacklist_mac(self, mac: str, reason: str):
        """Teile MAC-Blacklist global"""
        self.shared_blacklist_macs.add(mac)
        logger.warning(f"🌐 Shared MAC blacklist: {mac} - {reason}")

        event = SecurityEvent(
            source_node=self.node_id,
            event_type="mac_blacklisted",
            severity=8,
            description=f"MAC blacklisted globally: {mac}",
            metadata={"mac": mac, "reason": reason},
        )
        self.publish_event(event)

        self.save_state()

    def share_threat_signature(self, signature: str, severity: int):
        """Teile Threat-Signature global"""
        self.shared_threat_signatures[signature] = severity
        logger.warning(f"🌐 Shared threat signature: {signature} (Severity: {severity})")

        event = SecurityEvent(
            source_node=self.node_id,
            event_type="threat_signature_shared",
            severity=severity,
            description=f"New threat signature shared: {signature}",
            metadata={"signature": signature},
        )
        self.publish_event(event)

        self.save_state()

    def _sync_threat_intelligence_to_node(self, node_id: str):
        """Synchronisiere Threat Intelligence zu Knoten"""
        # In Produktion: Sende via RPC/HTTP
        logger.info(f"🔄 Syncing threat intelligence to {node_id}:")
        logger.info(f"  - {len(self.shared_blacklist_ips)} blacklisted IPs")
        logger.info(f"  - {len(self.shared_blacklist_macs)} blacklisted MACs")
        logger.info(f"  - {len(self.shared_threat_signatures)} threat signatures")

    def update_node_health(self):
        """Aktualisiere Health-Status aller Knoten"""
        unhealthy_nodes = []

        for node_id, node in self.nodes.items():
            if not node.is_healthy():
                unhealthy_nodes.append(node_id)
                logger.warning(
                    f"⚠️ Unhealthy node: {node_id} (State: {node.state.value}, "
                    f"Trust: {node.trust_score:.1f}, Load: {node.load:.2f})"
                )

        # Auto-Heal: Isoliere kritische Knoten
        for node_id in unhealthy_nodes:
            node = self.nodes[node_id]
            if node.state == SecurityState.UNDER_ATTACK and node.trust_score < 20:
                self._isolate_node(node_id)

    def _isolate_node(self, node_id: str):
        """Isoliere kompromittierten Knoten"""
        if node_id in self.nodes:
            self.nodes[node_id].state = SecurityState.ISOLATED
            logger.error(f"🚨 NODE ISOLATED: {node_id}")

            event = SecurityEvent(
                source_node=self.node_id,
                event_type="node_isolated",
                severity=10,
                description=f"Node {node_id} isolated due to compromise",
                metadata={"isolated_node": node_id},
            )
            self.publish_event(event)

            self.save_state()

    def get_mesh_statistics(self) -> Dict[str, Any]:
        """Hole Mesh-Statistiken"""
        healthy_nodes = sum(1 for n in self.nodes.values() if n.is_healthy())

        state_distribution = defaultdict(int)
        for node in self.nodes.values():
            state_distribution[node.state.value] += 1

        return {
            "total_nodes": len(self.nodes),
            "healthy_nodes": healthy_nodes,
            "unhealthy_nodes": len(self.nodes) - healthy_nodes,
            "total_events": self.total_events,
            "total_policies": len(self.policies),
            "shared_blacklist_ips": len(self.shared_blacklist_ips),
            "shared_blacklist_macs": len(self.shared_blacklist_macs),
            "shared_threat_signatures": len(self.shared_threat_signatures),
            "state_distribution": dict(state_distribution),
            "node_details": {
                nid: {
                    "type": node.node_type.value,
                    "state": node.state.value,
                    "trust_score": node.trust_score,
                    "healthy": node.is_healthy(),
                }
                for nid, node in self.nodes.items()
            },
        }

    def generate_mesh_report(self) -> str:
        """Generiere Mesh-Report"""
        stats = self.get_mesh_statistics()

        report = f"""
╔════════════════════════════════════════════════════════════╗
║      AVA Distributed Security Mesh - Report                ║
╚════════════════════════════════════════════════════════════╝

🌐 MESH TOPOLOGY:
  Node ID:               {self.node_id}
  Node Type:             {self.node_type.value}
  Total Nodes:           {stats['total_nodes']:,}
  Healthy Nodes:         {stats['healthy_nodes']:,}
  Unhealthy Nodes:       {stats['unhealthy_nodes']:,}

📊 EVENTS & POLICIES:
  Total Events:          {stats['total_events']:,}
  Active Policies:       {stats['total_policies']:,}

🛡️ SHARED INTELLIGENCE:
  Blacklisted IPs:       {stats['shared_blacklist_ips']:,}
  Blacklisted MACs:      {stats['shared_blacklist_macs']:,}
  Threat Signatures:     {stats['shared_threat_signatures']:,}

⚡ NODE STATE DISTRIBUTION:"""

        for state, count in stats["state_distribution"].items():
            report += f"\n  {state:20s} {count:5,}"

        report += "\n\n🔧 REGISTERED NODES:\n"
        for node_id, details in stats["node_details"].items():
            health_icon = "✅" if details["healthy"] else "❌"
            report += f"  {health_icon} {node_id[:16]:18s} [{details['type']:12s}] "
            report += f"State: {details['state']:15s} Trust: {details['trust_score']:5.1f}\n"

        report += "\n╚════════════════════════════════════════════════════════════╝\n"

        return report


async def mesh_heartbeat(mesh: DistributedSecurityMesh, interval: int = 30):
    """Heartbeat für Mesh-Health-Monitoring"""
    logger.info("💓 Mesh heartbeat started")

    while True:
        try:
            # Update eigenen Knoten
            mesh.local_node.last_seen = datetime.utcnow()
            mesh.local_node.uptime_seconds += interval

            # Prüfe alle Knoten
            mesh.update_node_health()

            # Speichere State
            mesh.save_state()

            await asyncio.sleep(interval)

        except asyncio.CancelledError:
            logger.info("💓 Mesh heartbeat stopped")
            break
        except Exception as e:
            logger.error(f"Heartbeat error: {e}")
            await asyncio.sleep(5)


# Global Mesh Instance
_mesh: Optional[DistributedSecurityMesh] = None


def get_security_mesh(node_type: NodeType = NodeType.LOCAL) -> DistributedSecurityMesh:
    """Hole oder erstelle globale Mesh-Instanz"""
    global _mesh
    if _mesh is None:
        _mesh = DistributedSecurityMesh(node_type=node_type)
    return _mesh


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    async def demo():
        # Erstelle Mesh
        mesh = get_security_mesh(NodeType.LOCAL)

        print("\n🌐 AVA Distributed Security Mesh - Demo\n")

        # Registriere zusätzliche Knoten
        edge_node = SecurityNode(
            node_id="edge_001",
            node_type=NodeType.EDGE,
            hostname="edge-server-01",
            ip_address="10.0.1.100",
            interfaces=[InterfaceType.HTTPS, InterfaceType.WEBSOCKET],
        )
        mesh.register_node(edge_node)

        cloud_node = SecurityNode(
            node_id="cloud_001",
            node_type=NodeType.CLOUD,
            hostname="cloud-instance-01",
            ip_address="203.0.113.10",
            interfaces=[InterfaceType.HTTPS, InterfaceType.GRPC],
        )
        mesh.register_node(cloud_node)

        # Füge Policy hinzu
        policy = SecurityPolicy(
            policy_id="pol_001",
            name="Block High-Risk IPs",
            priority=9,
            conditions={"threat_level": "critical"},
            actions=["block_ip", "alert_admin"],
            applied_to=["edge_001", "cloud_001"],
        )
        mesh.add_policy(policy)

        # Teile Bedrohungsinformationen
        mesh.share_blacklist_ip("198.51.100.50", "DDoS attack detected")
        mesh.share_blacklist_mac("DE:AD:BE:EF:00:00", "Malware propagation")
        mesh.share_threat_signature("sql_injection_v2", 9)

        # Publiziere Event
        event = SecurityEvent(
            event_type="intrusion_detected",
            severity=8,
            description="Port scan detected from external IP",
            metadata={"target_port": 22, "source_ip": "198.51.100.50"},
        )
        mesh.publish_event(event)

        # Zeige Report
        print(mesh.generate_mesh_report())

        # Starte Heartbeat
        heartbeat_task = asyncio.create_task(mesh_heartbeat(mesh, interval=10))

        # Laufe 30 Sekunden
        await asyncio.sleep(30)

        heartbeat_task.cancel()

    asyncio.run(demo())
