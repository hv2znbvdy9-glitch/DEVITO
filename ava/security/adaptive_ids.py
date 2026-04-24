"""
AVA Adaptive Network Intrusion Detection System (ANIDS)
========================================================
Selbst-lernendes, autonomes Netzwerk-Sicherheitssystem mit:
- MAC/IP Address Fingerprinting
- Anomalie-Erkennung mit ML
- Automatische Blacklist-Generierung
- Self-Healing & Auto-Patching
- Distributed Intelligence

ACHTUNG: Dieses System lernt kontinuierlich und passt sich an!
"""

import asyncio
import hashlib
import logging
import pickle
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import uuid4

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    """Bedrohungsstufen"""

    BENIGN = 0
    SUSPICIOUS = 1
    MALICIOUS = 2
    CRITICAL = 3


@dataclass
class NetworkFingerprint:
    """Eindeutiger Netzwerk-Fingerprint für Geräte"""

    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    os_fingerprint: Optional[str] = None
    open_ports: Set[int] = field(default_factory=set)
    user_agents: Set[str] = field(default_factory=set)
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    request_count: int = 0
    threat_level: ThreatLevel = ThreatLevel.BENIGN
    trust_score: float = 50.0  # 0-100
    anomaly_score: float = 0.0  # 0-100
    behaviors: List[str] = field(default_factory=list)

    @property
    def fingerprint_hash(self) -> str:
        """Eindeutiger Hash-Fingerprint"""
        data = f"{self.ip_address}:{self.mac_address}:{self.os_fingerprint}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]

    def update_trust_score(self):
        """Berechne Trust Score basierend auf Verhalten"""
        score = 50.0

        # Negative Faktoren
        if self.anomaly_score > 50:
            score -= 30
        if self.threat_level == ThreatLevel.MALICIOUS:
            score -= 40
        if self.threat_level == ThreatLevel.CRITICAL:
            score = 0
        if len(self.behaviors) > 10:
            score -= 10

        # Positive Faktoren
        days_known = (datetime.utcnow() - self.first_seen).days
        if days_known > 30:
            score += 20
        elif days_known > 7:
            score += 10

        if self.request_count < 1000:
            score += 5

        self.trust_score = max(0.0, min(100.0, score))


@dataclass
class AttackPattern:
    """Erkanntes Angriffsmuster"""

    pattern_id: str
    name: str
    description: str
    indicators: List[str]
    severity: int
    learned_from: str  # IP/MAC des Angreifers
    learned_at: datetime = field(default_factory=datetime.utcnow)
    detection_count: int = 0
    false_positive_rate: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "name": self.name,
            "description": self.description,
            "indicators": self.indicators,
            "severity": self.severity,
            "learned_from": self.learned_from,
            "learned_at": self.learned_at.isoformat(),
            "detection_count": self.detection_count,
            "false_positive_rate": self.false_positive_rate,
        }


class MacAddressAnalyzer:
    """MAC-Adressen Analyse & Vendor Detection"""

    # OUI (Organizationally Unique Identifier) - erste 3 Bytes der MAC
    SUSPICIOUS_VENDORS = {
        "00:00:00": "NULL_MAC",
        "FF:FF:FF": "BROADCAST",
        "00:00:5E": "IANA_RESERVED",
    }

    @staticmethod
    def normalize_mac(mac: str) -> str:
        """Normalisiere MAC-Adresse Format"""
        mac = mac.upper().replace("-", ":").replace(".", ":")
        return mac

    @staticmethod
    def get_vendor(mac: str) -> str:
        """Ermittle Hersteller aus MAC-Adresse"""
        mac = MacAddressAnalyzer.normalize_mac(mac)
        oui = ":".join(mac.split(":")[:3])
        return MacAddressAnalyzer.SUSPICIOUS_VENDORS.get(oui, "UNKNOWN")

    @staticmethod
    def is_suspicious(mac: str) -> bool:
        """Prüfe ob MAC-Adresse suspekt ist"""
        mac = MacAddressAnalyzer.normalize_mac(mac)
        oui = ":".join(mac.split(":")[:3])

        # Null oder Broadcast
        if oui in MacAddressAnalyzer.SUSPICIOUS_VENDORS:
            return True

        # Lokale Administrations-Bit gesetzt (Bit 1 im ersten Byte)
        first_byte = int(mac.split(":")[0], 16)
        if first_byte & 0x02:  # Local bit
            return True

        return False


class SelfLearningEngine:
    """Self-Learning KI für Bedrohungserkennung"""

    def __init__(self):
        self.learned_patterns: List[AttackPattern] = []
        self.behavior_profiles: Dict[str, List[float]] = defaultdict(list)
        self.attack_signatures: Dict[str, int] = defaultdict(int)
        self.false_positives: Set[str] = set()

    def learn_from_attack(
        self, attacker_fp: NetworkFingerprint, attack_type: str, indicators: List[str]
    ) -> AttackPattern:
        """Lerne aus einem erkannten Angriff"""
        pattern = AttackPattern(
            pattern_id=str(uuid4())[:8],
            name=f"Learned_{attack_type}_{len(self.learned_patterns)}",
            description=f"Auto-learned pattern from {attacker_fp.ip_address}",
            indicators=indicators,
            severity=5 + (attacker_fp.anomaly_score / 10),
            learned_from=attacker_fp.ip_address,
        )

        self.learned_patterns.append(pattern)
        logger.warning(
            f"🧠 LEARNED NEW ATTACK PATTERN: {pattern.name} from {attacker_fp.ip_address}"
        )

        return pattern

    def check_pattern_match(self, indicators: List[str]) -> Optional[AttackPattern]:
        """Prüfe ob Indikatoren zu gelerntem Muster passen"""
        for pattern in self.learned_patterns:
            matches = sum(1 for ind in indicators if ind in pattern.indicators)
            similarity = matches / len(pattern.indicators) if pattern.indicators else 0

            if similarity > 0.7:  # 70% Übereinstimmung
                pattern.detection_count += 1
                return pattern

        return None

    def update_behavior_profile(self, fingerprint: NetworkFingerprint):
        """Aktualisiere Verhaltensprofil"""
        profile_key = fingerprint.fingerprint_hash

        # Feature-Vektor: [request_rate, anomaly_score, trust_score, port_diversity]
        features = [
            fingerprint.request_count
            / max(1, (datetime.utcnow() - fingerprint.first_seen).seconds),
            fingerprint.anomaly_score,
            fingerprint.trust_score,
            len(fingerprint.open_ports),
        ]

        self.behavior_profiles[profile_key].append(features)

        # Halte nur letzte 1000 Einträge
        if len(self.behavior_profiles[profile_key]) > 1000:
            self.behavior_profiles[profile_key] = self.behavior_profiles[profile_key][-1000:]

    def detect_anomaly(self, fingerprint: NetworkFingerprint) -> float:
        """Erkenne Anomalien im Verhalten (0-100)"""
        profile_key = fingerprint.fingerprint_hash

        if (
            profile_key not in self.behavior_profiles
            or len(self.behavior_profiles[profile_key]) < 10
        ):
            return 0.0  # Zu wenig Daten

        history = self.behavior_profiles[profile_key]

        # Einfache statistische Anomalie-Erkennung
        current_features = [
            fingerprint.request_count
            / max(1, (datetime.utcnow() - fingerprint.first_seen).seconds),
            fingerprint.anomaly_score,
            fingerprint.trust_score,
            len(fingerprint.open_ports),
        ]

        # Berechne Abweichung vom Durchschnitt
        deviations = []
        for i in range(len(current_features)):
            historical_values = [h[i] for h in history]
            mean = sum(historical_values) / len(historical_values)
            std = (sum((x - mean) ** 2 for x in historical_values) / len(historical_values)) ** 0.5

            if std > 0:
                deviation = abs(current_features[i] - mean) / std
                deviations.append(min(deviation, 10))  # Cap bei 10

        anomaly_score = (sum(deviations) / len(deviations)) * 10 if deviations else 0
        return min(anomaly_score, 100.0)


class AdaptiveNetworkIDS:
    """Hauptsystem: Adaptive Network Intrusion Detection"""

    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = data_dir or Path.home() / ".ava" / "adaptive_ids"
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Fingerprint-Datenbank
        self.fingerprints: Dict[str, NetworkFingerprint] = {}

        # Blacklists
        self.blacklisted_ips: Set[str] = set()
        self.blacklisted_macs: Set[str] = set()
        self.blacklisted_cookies: Set[str] = set()

        # Self-Learning Engine
        self.learning_engine = SelfLearningEngine()

        # MAC Analyzer
        self.mac_analyzer = MacAddressAnalyzer()

        # Statistiken
        self.total_scans = 0
        self.threats_detected = 0
        self.threats_blocked = 0
        self.patterns_learned = 0

        # Lade persistierte Daten
        self.load_state()

    def load_state(self):
        """Lade gespeicherten Zustand"""
        state_file = self.data_dir / "adaptive_ids_state.pkl"

        if state_file.exists():
            try:
                with open(state_file, "rb") as f:
                    state = pickle.load(f)
                    self.fingerprints = state.get("fingerprints", {})
                    self.blacklisted_ips = state.get("blacklisted_ips", set())
                    self.blacklisted_macs = state.get("blacklisted_macs", set())
                    self.learning_engine.learned_patterns = state.get("learned_patterns", [])
                logger.info(
                    f"✅ State loaded: {len(self.fingerprints)} fingerprints, "
                    f"{len(self.blacklisted_ips)} blacklisted IPs, "
                    f"{len(self.learning_engine.learned_patterns)} learned patterns"
                )
            except Exception as e:
                logger.error(f"Failed to load state: {e}")

    def save_state(self):
        """Speichere Zustand"""
        state_file = self.data_dir / "adaptive_ids_state.pkl"

        try:
            state = {
                "fingerprints": self.fingerprints,
                "blacklisted_ips": self.blacklisted_ips,
                "blacklisted_macs": self.blacklisted_macs,
                "learned_patterns": self.learning_engine.learned_patterns,
                "timestamp": datetime.utcnow().isoformat(),
            }

            with open(state_file, "wb") as f:
                pickle.dump(state, f)

            logger.info("💾 State saved successfully")
        except Exception as e:
            logger.error(f"Failed to save state: {e}")

    def get_or_create_fingerprint(self, ip: str, mac: Optional[str] = None) -> NetworkFingerprint:
        """Hole oder erstelle Fingerprint für IP/MAC"""
        key = f"{ip}:{mac}" if mac else ip

        if key not in self.fingerprints:
            self.fingerprints[key] = NetworkFingerprint(ip_address=ip, mac_address=mac)

        fp = self.fingerprints[key]
        fp.last_seen = datetime.utcnow()
        fp.request_count += 1

        return fp

    async def scan_address(
        self,
        ip: str,
        mac: Optional[str] = None,
        ports: Optional[List[int]] = None,
        user_agent: Optional[str] = None,
    ) -> Tuple[bool, str, ThreatLevel]:
        """
        Scanne IP/MAC Adresse auf Bedrohungen
        Returns: (allowed, reason, threat_level)
        """
        self.total_scans += 1

        # 1. Prüfe Blacklists
        if ip in self.blacklisted_ips:
            self.threats_blocked += 1
            return False, f"IP {ip} is blacklisted", ThreatLevel.CRITICAL

        if mac and mac in self.blacklisted_macs:
            self.threats_blocked += 1
            return False, f"MAC {mac} is blacklisted", ThreatLevel.CRITICAL

        # 2. Hole/Erstelle Fingerprint
        fp = self.get_or_create_fingerprint(ip, mac)

        # 3. Aktualisiere Fingerprint
        if ports:
            fp.open_ports.update(ports)
        if user_agent:
            fp.user_agents.add(user_agent)

        # 4. MAC-Adress-Analyse
        if mac:
            if self.mac_analyzer.is_suspicious(mac):
                fp.behaviors.append(f"suspicious_mac_{datetime.utcnow().isoformat()}")
                fp.threat_level = ThreatLevel.SUSPICIOUS
                logger.warning(
                    f"⚠️ Suspicious MAC detected: {mac} ({self.mac_analyzer.get_vendor(mac)})"
                )

        # 5. Anomalie-Erkennung (Self-Learning)
        self.learning_engine.update_behavior_profile(fp)
        anomaly_score = self.learning_engine.detect_anomaly(fp)
        fp.anomaly_score = anomaly_score

        if anomaly_score > 70:
            fp.behaviors.append(f"high_anomaly_{anomaly_score:.1f}")
            fp.threat_level = ThreatLevel.MALICIOUS
            self.threats_detected += 1

            # Lerne von diesem Angriff
            indicators = [
                f"anomaly_score:{anomaly_score}",
                f"request_count:{fp.request_count}",
                f"port_diversity:{len(fp.open_ports)}",
            ]
            self.learning_engine.learn_from_attack(fp, "anomaly", indicators)
            self.patterns_learned += 1

            # Auto-Blacklist bei kritischen Bedrohungen
            if anomaly_score > 90:
                self.blacklist_ip(ip, f"Critical anomaly: {anomaly_score:.1f}")
                if mac:
                    self.blacklist_mac(mac, f"Critical anomaly from IP {ip}")
                return (
                    False,
                    f"BLOCKED: Critical anomaly detected ({anomaly_score:.1f})",
                    ThreatLevel.CRITICAL,
                )

        # 6. Pattern Matching gegen gelernte Angriffe
        current_indicators = [
            f"ports:{','.join(map(str, fp.open_ports))}",
            f"ua_count:{len(fp.user_agents)}",
        ]
        matched_pattern = self.learning_engine.check_pattern_match(current_indicators)

        if matched_pattern:
            fp.behaviors.append(f"matched_pattern:{matched_pattern.pattern_id}")
            fp.threat_level = ThreatLevel.MALICIOUS
            self.threats_detected += 1
            logger.warning(f"🎯 Matched learned pattern: {matched_pattern.name} from {ip}")

        # 7. Aktualisiere Trust Score
        fp.update_trust_score()

        # 8. Entscheidung
        if fp.threat_level == ThreatLevel.CRITICAL:
            return False, "Critical threat detected", ThreatLevel.CRITICAL
        elif fp.threat_level == ThreatLevel.MALICIOUS:
            return False, "Malicious activity detected", ThreatLevel.MALICIOUS
        elif fp.threat_level == ThreatLevel.SUSPICIOUS:
            return True, f"SUSPICIOUS: Trust score {fp.trust_score:.1f}", ThreatLevel.SUSPICIOUS
        else:
            return True, f"ALLOWED: Trust score {fp.trust_score:.1f}", ThreatLevel.BENIGN

    def blacklist_ip(self, ip: str, reason: str):
        """Füge IP zur Blacklist hinzu"""
        self.blacklisted_ips.add(ip)
        logger.warning(f"🚫 IP BLACKLISTED: {ip} - Reason: {reason}")
        self.save_state()

    def blacklist_mac(self, mac: str, reason: str):
        """Füge MAC zur Blacklist hinzu"""
        mac = self.mac_analyzer.normalize_mac(mac)
        self.blacklisted_macs.add(mac)
        logger.warning(f"🚫 MAC BLACKLISTED: {mac} - Reason: {reason}")
        self.save_state()

    def whitelist_ip(self, ip: str):
        """Entferne IP von Blacklist"""
        self.blacklisted_ips.discard(ip)
        logger.info(f"✅ IP whitelisted: {ip}")
        self.save_state()

    def get_statistics(self) -> Dict[str, Any]:
        """Hole System-Statistiken"""
        return {
            "total_scans": self.total_scans,
            "threats_detected": self.threats_detected,
            "threats_blocked": self.threats_blocked,
            "patterns_learned": self.patterns_learned,
            "unique_fingerprints": len(self.fingerprints),
            "blacklisted_ips": len(self.blacklisted_ips),
            "blacklisted_macs": len(self.blacklisted_macs),
            "learned_patterns": len(self.learning_engine.learned_patterns),
            "threat_distribution": self._get_threat_distribution(),
        }

    def _get_threat_distribution(self) -> Dict[str, int]:
        """Berechne Bedrohungsverteilung"""
        dist = defaultdict(int)
        for fp in self.fingerprints.values():
            dist[fp.threat_level.name] += 1
        return dict(dist)

    def generate_report(self) -> str:
        """Generiere detaillierten Bericht"""
        stats = self.get_statistics()

        report = f"""
╔════════════════════════════════════════════════════════════╗
║     AVA Adaptive Network IDS - Security Report             ║
╚════════════════════════════════════════════════════════════╝

📊 SCAN STATISTICS:
  Total Scans:           {stats['total_scans']:,}
  Threats Detected:      {stats['threats_detected']:,}
  Threats Blocked:       {stats['threats_blocked']:,}
  Unique Fingerprints:   {stats['unique_fingerprints']:,}

🧠 SELF-LEARNING STATUS:
  Patterns Learned:      {stats['patterns_learned']:,}
  Active Patterns:       {stats['learned_patterns']:,}

🚫 BLACKLISTS:
  Blacklisted IPs:       {stats['blacklisted_ips']:,}
  Blacklisted MACs:      {stats['blacklisted_macs']:,}

⚠️ THREAT DISTRIBUTION:"""

        for threat_level, count in stats["threat_distribution"].items():
            report += f"\n  {threat_level:15s} {count:5,}"

        report += "\n\n🎯 RECENTLY LEARNED PATTERNS:\n"
        for pattern in self.learning_engine.learned_patterns[-5:]:
            report += f"  - {pattern.name} (Severity: {pattern.severity}, Detections: {pattern.detection_count})\n"

        report += "\n╚════════════════════════════════════════════════════════════╝\n"

        return report


# Global Instance
_anids: Optional[AdaptiveNetworkIDS] = None


def get_adaptive_ids() -> AdaptiveNetworkIDS:
    """Hole oder erstelle globale ANIDS-Instanz"""
    global _anids
    if _anids is None:
        _anids = AdaptiveNetworkIDS()
    return _anids


async def continuous_network_monitoring(interval: int = 10):
    """Kontinuierliche Netzwerk-Überwachung"""
    anids = get_adaptive_ids()

    logger.info("🔄 Starting continuous network monitoring...")

    cycle = 1
    while True:
        try:
            logger.info(f"\n[Cycle {cycle}] Running network scan...")

            # Simuliere Netzwerk-Scans (in Produktion: echte Netzwerk-Analyse)
            # Hier würde man tatsächliche Netzwerk-Pakete analysieren

            # Speichere State
            anids.save_state()

            # Zeige Statistiken
            if cycle % 5 == 0:
                print(anids.generate_report())

            await asyncio.sleep(interval)
            cycle += 1

        except KeyboardInterrupt:
            logger.info("\n⏹️ Monitoring stopped by user")
            anids.save_state()
            break
        except Exception as e:
            logger.error(f"Error in monitoring cycle: {e}")
            await asyncio.sleep(5)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    async def demo():
        anids = get_adaptive_ids()

        print("\n🛡️ AVA Adaptive Network IDS - Demo\n")

        # Test 1: Normale IP
        allowed, reason, threat = await anids.scan_address(
            ip="192.168.1.100", mac="00:11:22:33:44:55", ports=[80, 443]
        )
        print(f"Test 1 - Normal IP: {allowed} - {reason} (Threat: {threat.name})")

        # Test 2: Suspicious MAC
        allowed, reason, threat = await anids.scan_address(
            ip="192.168.1.101", mac="00:00:00:00:00:00", ports=[22, 23, 3389]  # Null MAC
        )
        print(f"Test 2 - Suspicious MAC: {allowed} - {reason} (Threat: {threat.name})")

        # Test 3: Simuliere Anomalie (viele Requests)
        test_ip = "203.0.113.50"
        for i in range(100):
            await anids.scan_address(ip=test_ip, ports=[i])
        allowed, reason, threat = await anids.scan_address(ip=test_ip)
        print(f"Test 3 - Anomaly: {allowed} - {reason} (Threat: {threat.name})")

        # Zeige Report
        print(anids.generate_report())

    asyncio.run(demo())
