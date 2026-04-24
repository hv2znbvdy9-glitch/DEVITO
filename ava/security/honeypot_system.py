#!/usr/bin/env python3
"""
AVA Advanced Honeypot System - Deception & Intelligence Gathering
Täuscht Angreifer und sammelt Intelligence über Angriffsmuster
"""

import logging
import json
import hashlib
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class HoneypotType(Enum):
    """Typen von Honeypots"""

    WEB_SERVICE = "web_service"  # Fake Webserver
    DATABASE = "database"  # Fake Datenbank
    SSH_SERVICE = "ssh"  # Fake SSH
    FILE_SYSTEM = "filesystem"  # Fake Dateisystem
    API_ENDPOINT = "api"  # Fake API


@dataclass
class AttackerSession:
    """Session eines Angreifers im Honeypot"""

    session_id: str
    ip: str
    port: int
    honeypot_type: HoneypotType
    started: datetime
    ended: Optional[datetime] = None
    commands: List[str] = field(default_factory=list)
    payloads: List[str] = field(default_factory=list)
    attack_patterns: List[str] = field(default_factory=list)
    intelligence_gathered: Dict = field(default_factory=dict)


class AdvancedHoneypot:
    """
    🍯 ADVANCED HONEYPOT SYSTEM

    Täuscht Angreifer mit realistischen Fake-Systemen
    Sammelt detaillierte Informationen über Angriffsmuster

    Features:
    - Multiple Honeypot-Typen
    - Realistische Fake-Responses
    - Intelligence Gathering
    - Attacker Profiling
    - Automated Evidence Collection
    """

    def __init__(self):
        self.active_sessions: Dict[str, AttackerSession] = {}
        self.completed_sessions: List[AttackerSession] = []

        # Fake data repositories
        self.fake_users = self._generate_fake_users()
        self.fake_files = self._generate_fake_files()
        self.fake_databases = self._generate_fake_databases()

        # Intelligence
        self.known_attack_patterns: List[str] = []
        self.attacker_ips: set = set()

        logger.info("🍯 ADVANCED HONEYPOT SYSTEM INITIALIZED")
        logger.info(f"   Available honeypots: {[t.value for t in HoneypotType]}")

    def _generate_fake_users(self) -> List[Dict]:
        """Generiert realistische Fake-User Daten"""
        return [
            {
                "id": 1,
                "username": "admin",
                "password_hash": hashlib.md5(b"fake_password_123").hexdigest(),
                "email": "admin@fake-company.local",
                "role": "administrator",
                "created": "2024-01-15",
                "last_login": "2026-02-14",
            },
            {
                "id": 2,
                "username": "user",
                "password_hash": hashlib.md5(b"fake_user_pass").hexdigest(),
                "email": "user@fake-company.local",
                "role": "user",
                "created": "2024-03-20",
                "last_login": "2026-02-15",
            },
            {
                "id": 3,
                "username": "root",
                "password_hash": hashlib.sha256(b"fake_root_secret").hexdigest(),
                "email": "root@fake-system.local",
                "role": "superuser",
                "created": "2023-01-01",
                "last_login": "2026-02-15",
            },
        ]

    def _generate_fake_files(self) -> List[Dict]:
        """Generiert Fake-Dateisystem"""
        return [
            {
                "path": "/etc/passwd",
                "content": "root:x:0:0:root:/root:/bin/bash (FAKE)\nadmin:x:1000:1000:Admin:/home/admin:/bin/bash (FAKE)",
            },
            {
                "path": "/etc/shadow",
                "content": "root:$6$fake_hash$... (FAKE)\nadmin:$6$fake_hash$... (FAKE)",
            },
            {
                "path": "/var/www/config.php",
                "content": '<?php\n$db_host = "localhost";\n$db_user = "fake_user";\n$db_pass = "fake_password_123";\n// HONEYPOT DATA\n?>',
            },
            {
                "path": "/home/admin/.ssh/id_rsa",
                "content": "-----BEGIN FAKE RSA PRIVATE KEY-----\nFAKE_KEY_DATA_HONEYPOT\n-----END FAKE RSA PRIVATE KEY-----",
            },
            {
                "path": "/var/log/auth.log",
                "content": "Feb 15 12:00:00 fake-server sshd[1234]: Accepted password for admin (FAKE LOG)",
            },
        ]

    def _generate_fake_databases(self) -> Dict:
        """Generiert Fake-Datenbank-Schemas"""
        return {
            "users": {
                "table": "users",
                "columns": ["id", "username", "password", "email", "role"],
                "rows": self.fake_users,
            },
            "sessions": {
                "table": "sessions",
                "columns": ["id", "user_id", "token", "expires"],
                "rows": [
                    {"id": 1, "user_id": 1, "token": "fake_token_abc123", "expires": "2026-02-16"},
                    {"id": 2, "user_id": 2, "token": "fake_token_xyz789", "expires": "2026-02-16"},
                ],
            },
            "credit_cards": {
                "table": "credit_cards",
                "columns": ["id", "user_id", "card_number", "cvv", "expires"],
                "rows": [
                    {
                        "id": 1,
                        "user_id": 1,
                        "card_number": "4111-1111-1111-1111 (FAKE)",
                        "cvv": "123 (FAKE)",
                        "expires": "12/28",
                    },
                ],
            },
        }

    def create_session(self, ip: str, port: int, honeypot_type: HoneypotType) -> str:
        """Erstellt neue Honeypot-Session für Angreifer"""
        session_id = hashlib.sha256(f"{ip}:{port}:{datetime.now()}".encode()).hexdigest()[:16]

        session = AttackerSession(
            session_id=session_id,
            ip=ip,
            port=port,
            honeypot_type=honeypot_type,
            started=datetime.now(),
        )

        self.active_sessions[session_id] = session
        self.attacker_ips.add(ip)

        logger.warning(
            f"🍯 HONEYPOT SESSION STARTED: {session_id} from {ip} (Type: {honeypot_type.value})"
        )

        return session_id

    def handle_request(self, session_id: str, request_type: str, payload: str) -> Dict:
        """
        Verarbeitet Angreifer-Request und gibt täuschende Antwort

        Args:
            session_id: Session ID
            request_type: Art des Requests (sql, xss, file_access, etc.)
            payload: Der Angriffs-Payload
        """
        if session_id not in self.active_sessions:
            return {"error": "Invalid session"}

        session = self.active_sessions[session_id]
        session.payloads.append(payload)

        # Detect attack pattern
        attack_pattern = self._detect_attack_pattern(request_type, payload)
        if attack_pattern and attack_pattern not in session.attack_patterns:
            session.attack_patterns.append(attack_pattern)
            if attack_pattern not in self.known_attack_patterns:
                self.known_attack_patterns.append(attack_pattern)

        # Generate deceptive response
        response = self._generate_deceptive_response(request_type, payload, session)

        logger.warning(
            f"🍯 HONEYPOT INTERACTION: {session_id} - {request_type} - Pattern: {attack_pattern}"
        )

        return response

    def _detect_attack_pattern(self, request_type: str, payload: str) -> Optional[str]:
        """Erkennt Angriffsmuster"""
        patterns = {
            "sql_injection": ["UNION", "SELECT", "DROP", "--", "OR 1=1", "' OR '"],
            "xss": ["<script>", "javascript:", "onerror=", "onload="],
            "path_traversal": ["../", "..\\", "/etc/passwd", "C:\\Windows"],
            "command_injection": ["|", ";", "&&", "`", "$("],
            "xxe": ["<!ENTITY", "<!DOCTYPE", "SYSTEM"],
            "ldap_injection": ["*", "(", ")", "|", "&"],
        }

        payload_upper = payload.upper()
        for pattern_name, keywords in patterns.items():
            if any(keyword.upper() in payload_upper for keyword in keywords):
                return pattern_name

        return request_type  # Fallback

    def _generate_deceptive_response(
        self, request_type: str, payload: str, session: AttackerSession
    ) -> Dict:
        """Generiert täuschende Antwort basierend auf Request-Typ"""

        if "sql" in request_type.lower() or any(
            k in payload.upper() for k in ["SELECT", "UNION", "DROP"]
        ):
            return self._fake_sql_response(payload)

        elif "xss" in request_type.lower() or "<script>" in payload:
            return self._fake_xss_response(payload)

        elif "file" in request_type.lower() or "../" in payload:
            return self._fake_file_response(payload)

        elif "ssh" in request_type.lower() or session.honeypot_type == HoneypotType.SSH_SERVICE:
            return self._fake_ssh_response(payload)

        elif "api" in request_type.lower() or session.honeypot_type == HoneypotType.API_ENDPOINT:
            return self._fake_api_response(payload)

        else:
            return {
                "status": "success",
                "message": "Request processed successfully (FAKE)",
                "data": {"result": "operation completed"},
                "honeypot": True,
            }

    def _fake_sql_response(self, payload: str) -> Dict:
        """Fake SQL Injection Response"""
        # Analyze payload
        if "users" in payload.lower():
            data = self.fake_databases["users"]["rows"]
        elif "credit" in payload.lower():
            data = self.fake_databases["credit_cards"]["rows"]
        else:
            data = self.fake_users

        return {
            "status": "success",
            "message": "Query executed (HONEYPOT)",
            "rows_affected": len(data),
            "data": data[:2],  # Send limited fake data
            "honeypot": True,
            "warning": "⚠️  All data is FAKE for intelligence gathering",
        }

    def _fake_xss_response(self, payload: str) -> Dict:
        """Fake XSS Response"""
        return {
            "status": "success",
            "message": "Script accepted (HONEYPOT)",
            "reflected": payload,  # Reflect the payload (fake vulnerable)
            "session_token": "fake_session_" + hashlib.md5(payload.encode()).hexdigest()[:16],
            "honeypot": True,
        }

    def _fake_file_response(self, payload: str) -> Dict:
        """Fake File Access Response"""
        # Find matching fake file
        requested_file = None
        for fake_file in self.fake_files:
            if fake_file["path"] in payload:
                requested_file = fake_file
                break

        if requested_file:
            return {
                "status": "success",
                "file": requested_file["path"],
                "content": requested_file["content"],
                "size": len(requested_file["content"]),
                "honeypot": True,
            }

        return {
            "status": "error",
            "message": "File not found (but this is a honeypot)",
            "honeypot": True,
        }

    def _fake_ssh_response(self, payload: str) -> Dict:
        """Fake SSH Login Response"""
        return {
            "status": "success",
            "message": "Authentication successful (HONEYPOT)",
            "user": "root",
            "shell": "/bin/bash",
            "motd": "Welcome to Fake Server (HONEYPOT)\nLast login: Feb 15 2026 from 10.0.0.1",
            "honeypot": True,
        }

    def _fake_api_response(self, payload: str) -> Dict:
        """Fake API Response"""
        return {
            "status": "success",
            "api_version": "2.0",
            "data": {
                "access_token": "fake_token_" + hashlib.sha256(payload.encode()).hexdigest()[:32],
                "refresh_token": "fake_refresh_" + hashlib.md5(payload.encode()).hexdigest()[:32],
                "expires_in": 3600,
                "scope": "admin read write (FAKE)",
            },
            "honeypot": True,
        }

    def end_session(self, session_id: str):
        """Beendet Honeypot-Session und archiviert Intelligence"""
        if session_id in self.active_sessions:
            session = self.active_sessions[session_id]
            session.ended = datetime.now()

            # Gather intelligence
            session.intelligence_gathered = {
                "total_requests": len(session.payloads),
                "attack_patterns": session.attack_patterns,
                "duration_seconds": (session.ended - session.started).total_seconds(),
                "unique_techniques": len(set(session.attack_patterns)),
            }

            self.completed_sessions.append(session)
            del self.active_sessions[session_id]

            logger.warning(
                f"🍯 HONEYPOT SESSION ENDED: {session_id} - Intelligence: {session.intelligence_gathered}"
            )

    def get_intelligence_report(self) -> Dict:
        """Erstellt Intelligence Report"""
        return {
            "total_sessions": len(self.completed_sessions) + len(self.active_sessions),
            "active_sessions": len(self.active_sessions),
            "completed_sessions": len(self.completed_sessions),
            "unique_attacker_ips": len(self.attacker_ips),
            "known_attack_patterns": self.known_attack_patterns,
            "attacker_ips": list(self.attacker_ips),
            "session_details": [
                {
                    "session_id": s.session_id,
                    "ip": s.ip,
                    "honeypot_type": s.honeypot_type.value,
                    "attack_patterns": s.attack_patterns,
                    "total_payloads": len(s.payloads),
                    "intelligence": s.intelligence_gathered,
                }
                for s in self.completed_sessions[-10:]  # Last 10 sessions
            ],
        }


# Global instance
_honeypot_system = None


def get_honeypot_system() -> AdvancedHoneypot:
    """Singleton für Honeypot System"""
    global _honeypot_system
    if _honeypot_system is None:
        _honeypot_system = AdvancedHoneypot()
    return _honeypot_system


if __name__ == "__main__":
    # Demo
    logging.basicConfig(level=logging.INFO)

    print("\n" + "=" * 80)
    print("🍯 ADVANCED HONEYPOT SYSTEM - DEMO")
    print("=" * 80 + "\n")

    honeypot = get_honeypot_system()

    # Simulate attacker session
    print("Simulating SQL injection attack...")
    session_id = honeypot.create_session("192.168.1.100", 8080, HoneypotType.WEB_SERVICE)

    # SQL Injection attempt
    response = honeypot.handle_request(
        session_id, "sql_injection", "SELECT * FROM users WHERE id=1 OR 1=1--"
    )
    print(f"\nFake Response: {json.dumps(response, indent=2)}")

    # XSS attempt
    response = honeypot.handle_request(session_id, "xss", "<script>alert('hacked')</script>")
    print(f"\nFake Response: {json.dumps(response, indent=2)}")

    # End session
    honeypot.end_session(session_id)

    # Intelligence report
    print("\n" + "=" * 80)
    print("📊 INTELLIGENCE REPORT:")
    print("=" * 80)
    report = honeypot.get_intelligence_report()
    print(json.dumps(report, indent=2))
