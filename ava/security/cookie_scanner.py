"""
AVA Cookie Security Scanner
============================
Analysiert HTTP Cookies auf Sicherheitsbedrohungen:
- Session Hijacking
- XSS Payloads
- Tracking Cookies
- Insecure Cookie Attributes
- Cookie-basierte Angriffe

Lernt automatisch neue Cookie-basierte Bedrohungen!
"""

import base64
import hashlib
import json
import logging
import re
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from uuid import uuid4

logger = logging.getLogger(__name__)


class CookieThreatType(Enum):
    """Cookie-Bedrohungstypen"""

    XSS_PAYLOAD = "xss_payload"
    SQL_INJECTION = "sql_injection"
    SESSION_HIJACKING = "session_hijacking"
    TRACKING = "tracking"
    INSECURE_ATTRIBUTES = "insecure_attributes"
    SUSPICIOUS_ENCODING = "suspicious_encoding"
    LONG_LIVED = "long_lived"
    DOMAIN_MISMATCH = "domain_mismatch"
    MALICIOUS_VALUE = "malicious_value"


@dataclass
class Cookie:
    """HTTP Cookie Repräsentation"""

    name: str
    value: str
    domain: Optional[str] = None
    path: Optional[str] = "/"
    expires: Optional[datetime] = None
    max_age: Optional[int] = None
    secure: bool = False
    http_only: bool = False
    same_site: Optional[str] = None

    @property
    def cookie_hash(self) -> str:
        """Eindeutiger Hash für Cookie"""
        data = f"{self.name}:{self.domain}:{self.path}"
        return hashlib.md5(data.encode()).hexdigest()[:12]

    @classmethod
    def from_header(cls, cookie_header: str) -> List["Cookie"]:
        """Parse Cookie aus HTTP Header"""
        cookies = []

        for cookie_str in cookie_header.split(";"):
            cookie_str = cookie_str.strip()
            if "=" not in cookie_str:
                continue

            name, value = cookie_str.split("=", 1)
            cookies.append(cls(name=name.strip(), value=value.strip()))

        return cookies

    @classmethod
    def from_set_cookie(cls, set_cookie_header: str) -> "Cookie":
        """Parse Set-Cookie Header"""
        parts = [p.strip() for p in set_cookie_header.split(";")]

        if not parts or "=" not in parts[0]:
            raise ValueError("Invalid Set-Cookie header")

        name, value = parts[0].split("=", 1)
        cookie = cls(name=name.strip(), value=value.strip())

        # Parse Attribute
        for part in parts[1:]:
            if "=" in part:
                attr, attr_value = part.split("=", 1)
                attr = attr.strip().lower()

                if attr == "domain":
                    cookie.domain = attr_value.strip()
                elif attr == "path":
                    cookie.path = attr_value.strip()
                elif attr == "expires":
                    try:
                        cookie.expires = datetime.strptime(
                            attr_value.strip(), "%a, %d %b %Y %H:%M:%S GMT"
                        )
                    except Exception:
                        pass
                elif attr == "max-age":
                    try:
                        cookie.max_age = int(attr_value.strip())
                    except Exception:
                        pass
                elif attr == "samesite":
                    cookie.same_site = attr_value.strip()
            else:
                attr = part.strip().lower()
                if attr == "secure":
                    cookie.secure = True
                elif attr == "httponly":
                    cookie.http_only = True

        return cookie


@dataclass
class CookieThreat:
    """Erkannte Cookie-Bedrohung"""

    threat_id: str = field(default_factory=lambda: str(uuid4())[:8])
    threat_type: CookieThreatType = CookieThreatType.MALICIOUS_VALUE
    severity: int = 5  # 1-10
    cookie_name: str = ""
    cookie_value: str = ""
    description: str = ""
    indicators: List[str] = field(default_factory=list)
    detected_at: datetime = field(default_factory=datetime.utcnow)
    confidence: float = 0.5  # 0-1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "threat_id": self.threat_id,
            "threat_type": self.threat_type.value,
            "severity": self.severity,
            "cookie_name": self.cookie_name,
            "cookie_value": self.cookie_value[:100],  # Truncate
            "description": self.description,
            "indicators": self.indicators,
            "detected_at": self.detected_at.isoformat(),
            "confidence": self.confidence,
        }


class CookieSecurityScanner:
    """Cookie Security Scanner mit Self-Learning"""

    # Bekannte XSS Patterns
    XSS_PATTERNS = [
        r"<script[^>]*>",
        r"javascript:",
        r"onerror\s*=",
        r"onload\s*=",
        r"onclick\s*=",
        r"<iframe[^>]*>",
        r"eval\s*\(",
        r"alert\s*\(",
    ]

    # SQL Injection Patterns
    SQL_PATTERNS = [
        r"union\s+select",
        r";\s*drop\s+table",
        r"'\s+or\s+'",
        r"--\s*$",
        r"1\s*=\s*1",
        r"admin'\s*--",
    ]

    # Tracking Cookie Namen
    TRACKING_COOKIES = {
        "_ga",
        "_gid",
        "_gat",
        "__utma",
        "__utmb",
        "__utmc",
        "__utmz",  # Google Analytics
        "_fbp",
        "fr",  # Facebook
        "DSID",
        "IDE",
        "NID",  # DoubleClick
        "_ym_",
        "yandexuid",  # Yandex
        "uuid",
        "uuid2",  # Third-party tracking
    }

    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = data_dir or Path.home() / ".ava" / "cookie_scanner"
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.threats_detected: List[CookieThreat] = []
        self.learned_malicious_patterns: List[str] = []
        self.blacklisted_cookie_names: Set[str] = set()
        self.blacklisted_cookie_hashes: Set[str] = set()

        self.total_cookies_scanned = 0
        self.total_threats_found = 0

        self.load_state()

    def load_state(self):
        """Lade persistierten Zustand"""
        state_file = self.data_dir / "cookie_scanner_state.json"

        if state_file.exists():
            try:
                with open(state_file, "r") as f:
                    state = json.load(f)
                    self.learned_malicious_patterns = state.get("learned_patterns", [])
                    self.blacklisted_cookie_names = set(state.get("blacklisted_names", []))
                    self.blacklisted_cookie_hashes = set(state.get("blacklisted_hashes", []))
                    self.total_cookies_scanned = state.get("total_scanned", 0)
                    self.total_threats_found = state.get("total_threats", 0)

                logger.info(
                    f"✅ Cookie scanner state loaded: {len(self.learned_malicious_patterns)} patterns, "
                    f"{len(self.blacklisted_cookie_names)} blacklisted names"
                )
            except Exception as e:
                logger.error(f"Failed to load cookie scanner state: {e}")

    def save_state(self):
        """Speichere Zustand"""
        state_file = self.data_dir / "cookie_scanner_state.json"

        try:
            state = {
                "learned_patterns": self.learned_malicious_patterns,
                "blacklisted_names": list(self.blacklisted_cookie_names),
                "blacklisted_hashes": list(self.blacklisted_cookie_hashes),
                "total_scanned": self.total_cookies_scanned,
                "total_threats": self.total_threats_found,
                "timestamp": datetime.utcnow().isoformat(),
            }

            with open(state_file, "w") as f:
                json.dump(state, f, indent=2)

            logger.info("💾 Cookie scanner state saved")
        except Exception as e:
            logger.error(f"Failed to save cookie scanner state: {e}")

    def scan_cookie(
        self, cookie: Cookie, request_domain: Optional[str] = None
    ) -> List[CookieThreat]:
        """
        Scanne einzelnen Cookie auf Bedrohungen
        Returns: Liste erkannter Bedrohungen
        """
        self.total_cookies_scanned += 1
        threats = []

        # 1. Blacklist Check
        if cookie.name in self.blacklisted_cookie_names:
            threat = CookieThreat(
                threat_type=CookieThreatType.MALICIOUS_VALUE,
                severity=10,
                cookie_name=cookie.name,
                cookie_value=cookie.value,
                description=f"Cookie name '{cookie.name}' is blacklisted",
                confidence=1.0,
            )
            threats.append(threat)

        if cookie.cookie_hash in self.blacklisted_cookie_hashes:
            threat = CookieThreat(
                threat_type=CookieThreatType.MALICIOUS_VALUE,
                severity=10,
                cookie_name=cookie.name,
                cookie_value=cookie.value,
                description=f"Cookie hash '{cookie.cookie_hash}' is blacklisted",
                confidence=1.0,
            )
            threats.append(threat)

        # 2. XSS Detection
        xss_threat = self._check_xss(cookie)
        if xss_threat:
            threats.append(xss_threat)

        # 3. SQL Injection Detection
        sql_threat = self._check_sql_injection(cookie)
        if sql_threat:
            threats.append(sql_threat)

        # 4. Tracking Cookie Detection
        tracking_threat = self._check_tracking(cookie)
        if tracking_threat:
            threats.append(tracking_threat)

        # 5. Insecure Attributes
        attribute_threat = self._check_insecure_attributes(cookie)
        if attribute_threat:
            threats.append(attribute_threat)

        # 6. Long-Lived Cookie
        longlived_threat = self._check_long_lived(cookie)
        if longlived_threat:
            threats.append(longlived_threat)

        # 7. Domain Mismatch
        if request_domain:
            domain_threat = self._check_domain_mismatch(cookie, request_domain)
            if domain_threat:
                threats.append(domain_threat)

        # 8. Suspicious Encoding
        encoding_threat = self._check_suspicious_encoding(cookie)
        if encoding_threat:
            threats.append(encoding_threat)

        # 9. Learned Pattern Matching
        learned_threat = self._check_learned_patterns(cookie)
        if learned_threat:
            threats.append(learned_threat)

        # 10. Self-Learning: Bei mehreren Bedrohungen, lerne neues Pattern
        if len(threats) >= 2:
            self._learn_from_threat(cookie, threats)

        if threats:
            self.total_threats_found += len(threats)
            self.threats_detected.extend(threats)

        return threats

    def _check_xss(self, cookie: Cookie) -> Optional[CookieThreat]:
        """Prüfe auf XSS Payloads"""
        decoded_value = urllib.parse.unquote(cookie.value)

        for pattern in self.XSS_PATTERNS:
            if re.search(pattern, decoded_value, re.IGNORECASE):
                return CookieThreat(
                    threat_type=CookieThreatType.XSS_PAYLOAD,
                    severity=9,
                    cookie_name=cookie.name,
                    cookie_value=cookie.value,
                    description=f"XSS payload detected in cookie: {pattern}",
                    indicators=[pattern],
                    confidence=0.9,
                )
        return None

    def _check_sql_injection(self, cookie: Cookie) -> Optional[CookieThreat]:
        """Prüfe auf SQL Injection"""
        decoded_value = urllib.parse.unquote(cookie.value)

        for pattern in self.SQL_PATTERNS:
            if re.search(pattern, decoded_value, re.IGNORECASE):
                return CookieThreat(
                    threat_type=CookieThreatType.SQL_INJECTION,
                    severity=9,
                    cookie_name=cookie.name,
                    cookie_value=cookie.value,
                    description=f"SQL injection pattern detected: {pattern}",
                    indicators=[pattern],
                    confidence=0.85,
                )
        return None

    def _check_tracking(self, cookie: Cookie) -> Optional[CookieThreat]:
        """Prüfe auf Tracking Cookies"""
        for tracking_name in self.TRACKING_COOKIES:
            if tracking_name in cookie.name.lower():
                return CookieThreat(
                    threat_type=CookieThreatType.TRACKING,
                    severity=3,
                    cookie_name=cookie.name,
                    cookie_value=cookie.value,
                    description=f"Tracking cookie detected: {tracking_name}",
                    indicators=[tracking_name],
                    confidence=0.95,
                )
        return None

    def _check_insecure_attributes(self, cookie: Cookie) -> Optional[CookieThreat]:
        """Prüfe auf fehlende Security-Attribute"""
        issues = []

        if not cookie.secure:
            issues.append("missing_secure_flag")
        if not cookie.http_only:
            issues.append("missing_httponly_flag")
        if not cookie.same_site or cookie.same_site.lower() == "none":
            issues.append("missing_samesite")

        if issues:
            return CookieThreat(
                threat_type=CookieThreatType.INSECURE_ATTRIBUTES,
                severity=5,
                cookie_name=cookie.name,
                cookie_value=cookie.value,
                description=f"Insecure cookie attributes: {', '.join(issues)}",
                indicators=issues,
                confidence=1.0,
            )
        return None

    def _check_long_lived(self, cookie: Cookie) -> Optional[CookieThreat]:
        """Prüfe auf zu lange Lebensdauer"""
        if cookie.max_age and cookie.max_age > 365 * 24 * 60 * 60:  # > 1 Jahr
            return CookieThreat(
                threat_type=CookieThreatType.LONG_LIVED,
                severity=4,
                cookie_name=cookie.name,
                cookie_value=cookie.value,
                description=f"Long-lived cookie: {cookie.max_age} seconds",
                indicators=[f"max_age:{cookie.max_age}"],
                confidence=1.0,
            )

        if cookie.expires:
            lifetime = (cookie.expires - datetime.utcnow()).days
            if lifetime > 365:
                return CookieThreat(
                    threat_type=CookieThreatType.LONG_LIVED,
                    severity=4,
                    cookie_name=cookie.name,
                    cookie_value=cookie.value,
                    description=f"Long-lived cookie: {lifetime} days",
                    indicators=[f"expires:{lifetime}days"],
                    confidence=1.0,
                )
        return None

    def _check_domain_mismatch(self, cookie: Cookie, request_domain: str) -> Optional[CookieThreat]:
        """Prüfe auf Domain-Mismatch (Third-party Cookie)"""
        if cookie.domain and not request_domain.endswith(cookie.domain.lstrip(".")):
            return CookieThreat(
                threat_type=CookieThreatType.DOMAIN_MISMATCH,
                severity=6,
                cookie_name=cookie.name,
                cookie_value=cookie.value,
                description=f"Third-party cookie: domain '{cookie.domain}' != request '{request_domain}'",
                indicators=[f"domain_mismatch:{cookie.domain}:{request_domain}"],
                confidence=0.8,
            )
        return None

    def _check_suspicious_encoding(self, cookie: Cookie) -> Optional[CookieThreat]:
        """Prüfe auf verdächtige Encodings"""
        # Multi-layer Encoding (Obfuscation)
        decoded = cookie.value
        decode_count = 0

        try:
            while "%" in decoded and decode_count < 5:
                new_decoded = urllib.parse.unquote(decoded)
                if new_decoded == decoded:
                    break
                decoded = new_decoded
                decode_count += 1

            if decode_count >= 3:
                return CookieThreat(
                    threat_type=CookieThreatType.SUSPICIOUS_ENCODING,
                    severity=7,
                    cookie_name=cookie.name,
                    cookie_value=cookie.value,
                    description=f"Multi-layer URL encoding detected ({decode_count} layers)",
                    indicators=[f"encoding_layers:{decode_count}"],
                    confidence=0.75,
                )
        except Exception:
            pass

        # Base64 Obfuscation
        try:
            if len(cookie.value) > 20:
                decoded_b64 = base64.b64decode(cookie.value).decode("utf-8", errors="ignore")
                if any(
                    pattern in decoded_b64.lower()
                    for pattern in ["<script", "javascript:", "eval("]
                ):
                    return CookieThreat(
                        threat_type=CookieThreatType.SUSPICIOUS_ENCODING,
                        severity=8,
                        cookie_name=cookie.name,
                        cookie_value=cookie.value,
                        description="Base64-encoded malicious content detected",
                        indicators=["base64_xss"],
                        confidence=0.85,
                    )
        except Exception:
            pass

        return None

    def _check_learned_patterns(self, cookie: Cookie) -> Optional[CookieThreat]:
        """Prüfe gegen gelernte Patterns"""
        decoded_value = urllib.parse.unquote(cookie.value)

        for pattern in self.learned_malicious_patterns:
            if pattern in decoded_value.lower():
                return CookieThreat(
                    threat_type=CookieThreatType.MALICIOUS_VALUE,
                    severity=8,
                    cookie_name=cookie.name,
                    cookie_value=cookie.value,
                    description=f"Matches learned malicious pattern: {pattern}",
                    indicators=[f"learned:{pattern}"],
                    confidence=0.7,
                )
        return None

    def _learn_from_threat(self, cookie: Cookie, threats: List[CookieThreat]):
        """Lerne aus erkannter Bedrohung"""
        # Extrahiere charakteristische Muster
        decoded_value = urllib.parse.unquote(cookie.value).lower()

        # Lerne nur von hochsicheren Detections
        high_confidence_threats = [t for t in threats if t.confidence > 0.8]

        if high_confidence_threats:
            # Extrahiere gemeinsame Substrings
            if len(decoded_value) > 10:
                # Lerne charakteristische Teilstrings (min 5 Zeichen)
                for i in range(len(decoded_value) - 5):
                    pattern = decoded_value[i : i + 10]
                    if pattern not in self.learned_malicious_patterns:
                        self.learned_malicious_patterns.append(pattern)
                        logger.warning(f"🧠 LEARNED NEW COOKIE PATTERN: {pattern}")

                        # Begrenze auf 1000 Patterns
                        if len(self.learned_malicious_patterns) > 1000:
                            self.learned_malicious_patterns = self.learned_malicious_patterns[
                                -1000:
                            ]

            self.save_state()

    def blacklist_cookie_name(self, name: str):
        """Blackliste Cookie-Name"""
        self.blacklisted_cookie_names.add(name)
        logger.warning(f"🚫 Cookie name blacklisted: {name}")
        self.save_state()

    def blacklist_cookie_hash(self, cookie_hash: str):
        """Blackliste Cookie-Hash"""
        self.blacklisted_cookie_hashes.add(cookie_hash)
        logger.warning(f"🚫 Cookie hash blacklisted: {cookie_hash}")
        self.save_state()

    def get_statistics(self) -> Dict[str, Any]:
        """Hole Statistiken"""
        return {
            "total_cookies_scanned": self.total_cookies_scanned,
            "total_threats_found": self.total_threats_found,
            "learned_patterns_count": len(self.learned_malicious_patterns),
            "blacklisted_names_count": len(self.blacklisted_cookie_names),
            "blacklisted_hashes_count": len(self.blacklisted_cookie_hashes),
            "threat_type_distribution": self._get_threat_distribution(),
        }

    def _get_threat_distribution(self) -> Dict[str, int]:
        """Berechne Threat-Typ Verteilung"""
        dist = {}
        for threat in self.threats_detected:
            threat_type = threat.threat_type.value
            dist[threat_type] = dist.get(threat_type, 0) + 1
        return dist

    def generate_report(self) -> str:
        """Generiere Security Report"""
        stats = self.get_statistics()

        report = f"""
╔════════════════════════════════════════════════════════════╗
║       AVA Cookie Security Scanner - Report                 ║
╚════════════════════════════════════════════════════════════╝

📊 SCAN STATISTICS:
  Cookies Scanned:       {stats['total_cookies_scanned']:,}
  Threats Found:         {stats['total_threats_found']:,}

🧠 SELF-LEARNING:
  Learned Patterns:      {stats['learned_patterns_count']:,}

🚫 BLACKLISTS:
  Blacklisted Names:     {stats['blacklisted_names_count']:,}
  Blacklisted Hashes:    {stats['blacklisted_hashes_count']:,}

⚠️ THREAT DISTRIBUTION:"""

        for threat_type, count in stats["threat_type_distribution"].items():
            report += f"\n  {threat_type:25s} {count:5,}"

        if self.threats_detected:
            report += "\n\n🎯 RECENT THREATS (Last 10):\n"
            for threat in self.threats_detected[-10:]:
                report += (
                    f"  - [{threat.severity}/10] {threat.threat_type.value}: {threat.cookie_name}\n"
                )
                report += f"    {threat.description}\n"

        report += "\n╚════════════════════════════════════════════════════════════╝\n"

        return report


# Global Instance
_cookie_scanner: Optional[CookieSecurityScanner] = None


def get_cookie_scanner() -> CookieSecurityScanner:
    """Hole oder erstelle globale Scanner-Instanz"""
    global _cookie_scanner
    if _cookie_scanner is None:
        _cookie_scanner = CookieSecurityScanner()
    return _cookie_scanner


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    scanner = get_cookie_scanner()

    print("\n🍪 AVA Cookie Security Scanner - Demo\n")

    # Test 1: Normaler Cookie
    cookie1 = Cookie(name="session_id", value="abc123", secure=True, http_only=True)
    threats1 = scanner.scan_cookie(cookie1)
    print(f"Test 1 - Normal Cookie: {len(threats1)} threats")

    # Test 2: XSS Cookie
    cookie2 = Cookie(name="user_input", value="<script>alert('XSS')</script>")
    threats2 = scanner.scan_cookie(cookie2)
    print(f"Test 2 - XSS Cookie: {len(threats2)} threats")
    for t in threats2:
        print(f"  - {t.threat_type.value}: {t.description}")

    # Test 3: Tracking Cookie
    cookie3 = Cookie(name="_ga", value="GA1.2.123456789.1234567890")
    threats3 = scanner.scan_cookie(cookie3)
    print(f"Test 3 - Tracking Cookie: {len(threats3)} threats")
    for t in threats3:
        print(f"  - {t.threat_type.value}: {t.description}")

    # Test 4: Insecure Cookie
    cookie4 = Cookie(name="auth_token", value="secret123", secure=False, http_only=False)
    threats4 = scanner.scan_cookie(cookie4)
    print(f"Test 4 - Insecure Cookie: {len(threats4)} threats")
    for t in threats4:
        print(f"  - {t.threat_type.value}: {t.description}")

    # Zeige Report
    print(scanner.generate_report())
