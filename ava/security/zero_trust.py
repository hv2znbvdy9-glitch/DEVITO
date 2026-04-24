"""
AVA Zero-Trust Network Access (ZTNA)
=====================================
Never trust, always verify. Continuous authentication and authorization.

Principles:
1. Verify explicitly - Always authenticate & authorize
2. Least privilege access - Just-in-time & just-enough-access
3. Assume breach - Minimize blast radius & segment access
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class AccessLevel(Enum):
    """Access privilege levels"""

    NONE = 0
    READ = 1
    WRITE = 2
    EXECUTE = 3
    ADMIN = 4


class TrustScore(Enum):
    """Trust level scoring"""

    UNTRUSTED = 0
    LOW = 25
    MEDIUM = 50
    HIGH = 75
    VERIFIED = 100


@dataclass
class Device:
    """Registered device"""

    device_id: str
    device_type: str  # workstation, mobile, iot
    os: str
    fingerprint: str  # Unique device fingerprint
    owner: str
    trust_score: int = 50
    registered_at: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    security_posture: Dict[str, Any] = field(default_factory=dict)

    def update_trust_score(self):
        """Calculate trust score based on security posture"""
        score = TrustScore.MEDIUM.value

        posture = self.security_posture

        # Positive factors
        if posture.get("antivirus_enabled"):
            score += 10
        if posture.get("firewall_enabled"):
            score += 10
        if posture.get("encryption_enabled"):
            score += 5
        if posture.get("updated_os"):
            score += 10
        if posture.get("mfa_enabled"):
            score += 15

        # Negative factors
        if posture.get("jailbroken"):
            score -= 30
        if posture.get("unknown_software"):
            score -= 10
        if posture.get("outdated_os"):
            score -= 15

        # Time-based decay (haven't seen device in a while)
        days_since_seen = (datetime.utcnow() - self.last_seen).days
        if days_since_seen > 30:
            score -= 20
        elif days_since_seen > 7:
            score -= 10

        self.trust_score = max(0, min(100, score))


@dataclass
class User:
    """Authenticated user"""

    user_id: str
    username: str
    email: str
    roles: List[str]
    trust_score: int = 50
    mfa_enabled: bool = False
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_login: datetime = field(default_factory=datetime.utcnow)
    failed_login_attempts: int = 0
    devices: List[str] = field(default_factory=list)  # device_ids

    def is_admin(self) -> bool:
        return "admin" in self.roles

    def has_role(self, role: str) -> bool:
        return role in self.roles

    def update_trust_score(self):
        """Calculate user trust score"""
        score = TrustScore.MEDIUM.value

        # Positive factors
        if self.mfa_enabled:
            score += 20
        if len(self.devices) <= 3:  # Reasonable number of devices
            score += 5
        if self.failed_login_attempts == 0:
            score += 10

        # Negative factors
        if self.failed_login_attempts > 0:
            score -= self.failed_login_attempts * 5
        if len(self.devices) > 10:  # Too many devices
            score -= 15

        # Account age (older = more trusted)
        account_age_days = (datetime.utcnow() - self.created_at).days
        if account_age_days > 365:
            score += 10
        elif account_age_days > 90:
            score += 5

        self.trust_score = max(0, min(100, score))


@dataclass
class AccessContext:
    """Access request context"""

    user: User
    device: Device
    resource: str
    action: str  # read, write, execute, delete
    source_ip: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    risk_level: int = 0

    def calculate_risk(self) -> int:
        """Calculate risk score for this access request"""
        risk = 0

        # Low trust scores increase risk
        if self.user.trust_score < 50:
            risk += 20
        if self.device.trust_score < 50:
            risk += 20

        # Failed login attempts
        if self.user.failed_login_attempts > 0:
            risk += self.user.failed_login_attempts * 5

        # Unknown device
        if self.device.device_id not in self.user.devices:
            risk += 15

        # Suspicious IP (example - would check against threat intel)
        if self.source_ip.startswith("10."):  # Private IP is safer
            risk -= 5
        else:
            risk += 10  # Public IP is riskier

        # Time-based (access outside business hours)
        hour = self.timestamp.hour
        if hour < 6 or hour > 22:  # Outside 6 AM - 10 PM
            risk += 10

        # Sensitive actions
        if self.action in ["delete", "execute"]:
            risk += 15

        self.risk_level = max(0, min(100, risk))
        return self.risk_level


@dataclass
class AccessPolicy:
    """Zero-trust access policy"""

    policy_id: str
    name: str
    resource_pattern: str  # Regex pattern for resources
    allowed_roles: List[str]
    required_trust_score: int = 50
    require_mfa: bool = False
    allowed_device_types: List[str] = field(default_factory=lambda: ["workstation", "mobile"])
    allowed_actions: List[str] = field(default_factory=lambda: ["read"])
    time_restrictions: Optional[Dict[str, Any]] = None
    ip_whitelist: Optional[List[str]] = None

    def matches_resource(self, resource: str) -> bool:
        """Check if policy applies to resource"""
        import re

        return bool(re.match(self.resource_pattern, resource))

    def check_compliance(self, context: AccessContext) -> Tuple[bool, List[str]]:
        """Check if access request complies with policy"""
        violations = []

        # Check role
        if not any(role in self.allowed_roles for role in context.user.roles):
            violations.append(f"User role not allowed. Required: {self.allowed_roles}")

        # Check trust scores
        if context.user.trust_score < self.required_trust_score:
            violations.append(
                f"User trust score too low: {context.user.trust_score} < {self.required_trust_score}"
            )
        if context.device.trust_score < self.required_trust_score:
            violations.append(
                f"Device trust score too low: {context.device.trust_score} < {self.required_trust_score}"
            )

        # Check MFA
        if self.require_mfa and not context.user.mfa_enabled:
            violations.append("MFA required but not enabled")

        # Check device type
        if context.device.device_type not in self.allowed_device_types:
            violations.append(f"Device type not allowed: {context.device.device_type}")

        # Check action
        if context.action not in self.allowed_actions:
            violations.append(f"Action not allowed: {context.action}")

        # Check IP whitelist
        if self.ip_whitelist and context.source_ip not in self.ip_whitelist:
            violations.append(f"IP not whitelisted: {context.source_ip}")

        return len(violations) == 0, violations


class ZeroTrustEngine:
    """Main Zero-Trust enforcement engine"""

    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = data_dir or Path.home() / ".ava" / "zero_trust"
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.users: Dict[str, User] = {}
        self.devices: Dict[str, Device] = {}
        self.policies: Dict[str, AccessPolicy] = {}
        self.access_log: List[Dict[str, Any]] = []

        self.load_state()
        self.initialize_default_policies()

    def load_state(self):
        """Load persisted state"""
        state_file = self.data_dir / "ztna_state.json"
        if state_file.exists():
            try:
                with open(state_file, "r") as f:
                    json.load(f)
                logger.info("Zero-Trust state loaded")
            except Exception as e:
                logger.error(f"Failed to load state: {e}")

    def save_state(self):
        """Persist state to disk"""
        state_file = self.data_dir / "ztna_state.json"
        try:
            data = {
                "users": {
                    uid: {
                        "user_id": u.user_id,
                        "username": u.username,
                        "email": u.email,
                        "roles": u.roles,
                        "trust_score": u.trust_score,
                        "mfa_enabled": u.mfa_enabled,
                    }
                    for uid, u in self.users.items()
                },
                "devices": {
                    did: {
                        "device_id": d.device_id,
                        "device_type": d.device_type,
                        "owner": d.owner,
                        "trust_score": d.trust_score,
                    }
                    for did, d in self.devices.items()
                },
            }
            with open(state_file, "w") as f:
                json.dump(data, f, indent=2)
            logger.info("Zero-Trust state saved")
        except Exception as e:
            logger.error(f"Failed to save state: {e}")

    def initialize_default_policies(self):
        """Create default access policies"""
        # Admin access policy
        self.add_policy(
            AccessPolicy(
                policy_id="admin_full_access",
                name="Admin Full Access",
                resource_pattern=r".*",
                allowed_roles=["admin"],
                required_trust_score=75,
                require_mfa=True,
                allowed_actions=["read", "write", "execute", "delete"],
            )
        )

        # User read-only policy
        self.add_policy(
            AccessPolicy(
                policy_id="user_read_only",
                name="User Read-Only Access",
                resource_pattern=r"/data/public/.*",
                allowed_roles=["user", "admin"],
                required_trust_score=50,
                allowed_actions=["read"],
            )
        )

        # Developer access policy
        self.add_policy(
            AccessPolicy(
                policy_id="dev_access",
                name="Developer Access",
                resource_pattern=r"/code/.*",
                allowed_roles=["developer", "admin"],
                required_trust_score=60,
                require_mfa=True,
                allowed_actions=["read", "write", "execute"],
            )
        )

    def register_user(self, user: User):
        """Register a new user"""
        self.users[user.user_id] = user
        user.update_trust_score()
        logger.info(f"User registered: {user.username} (trust: {user.trust_score})")
        self.save_state()

    def register_device(self, device: Device):
        """Register a new device"""
        self.devices[device.device_id] = device
        device.update_trust_score()
        logger.info(f"Device registered: {device.device_id} (trust: {device.trust_score})")
        self.save_state()

    def add_policy(self, policy: AccessPolicy):
        """Add an access policy"""
        self.policies[policy.policy_id] = policy
        logger.info(f"Policy added: {policy.name}")

    def verify_access(self, context: AccessContext) -> Tuple[bool, str, List[str]]:
        """
        Verify access request against zero-trust policies
        Returns: (allowed, reason, policy_violations)
        """
        # Update trust scores
        context.user.update_trust_score()
        context.device.update_trust_score()

        # Calculate risk
        context.calculate_risk()

        # Find applicable policies
        applicable_policies = [
            policy for policy in self.policies.values() if policy.matches_resource(context.resource)
        ]

        if not applicable_policies:
            reason = f"No policy matches resource: {context.resource}"
            logger.warning(f"Access DENIED: {reason}")
            self.log_access(context, False, reason)
            return False, reason, [reason]

        # Check all applicable policies
        all_violations = []
        for policy in applicable_policies:
            compliant, violations = policy.check_compliance(context)
            if compliant:
                reason = f"Access granted via policy: {policy.name}"
                logger.info(f"Access GRANTED: {context.user.username} -> {context.resource}")
                self.log_access(context, True, reason)
                return True, reason, []
            all_violations.extend(violations)

        # All policies failed
        reason = "Access denied: Policy violations found"
        logger.warning(f"Access DENIED: {reason} - {all_violations}")
        self.log_access(context, False, reason)
        return False, reason, all_violations

    def log_access(self, context: AccessContext, granted: bool, reason: str):
        """Log access attempt"""
        log_entry = {
            "timestamp": context.timestamp.isoformat(),
            "user": context.user.username,
            "device": context.device.device_id,
            "resource": context.resource,
            "action": context.action,
            "granted": granted,
            "reason": reason,
            "user_trust": context.user.trust_score,
            "device_trust": context.device.trust_score,
            "risk_level": context.risk_level,
            "source_ip": context.source_ip,
        }
        self.access_log.append(log_entry)

        # Save to file
        log_file = self.data_dir / f"access_log_{datetime.utcnow().strftime('%Y%m%d')}.jsonl"
        try:
            with open(log_file, "a") as f:
                f.write(json.dumps(log_entry) + "\n")
        except Exception as e:
            logger.error(f"Failed to write access log: {e}")

    def get_access_statistics(self) -> Dict[str, Any]:
        """Get access statistics"""
        total_requests = len(self.access_log)
        granted = sum(1 for log in self.access_log if log["granted"])
        denied = total_requests - granted

        # Average trust scores
        avg_user_trust = sum(log["user_trust"] for log in self.access_log) / max(total_requests, 1)
        avg_device_trust = sum(log["device_trust"] for log in self.access_log) / max(
            total_requests, 1
        )
        avg_risk = sum(log["risk_level"] for log in self.access_log) / max(total_requests, 1)

        return {
            "total_requests": total_requests,
            "granted": granted,
            "denied": denied,
            "grant_rate": granted / max(total_requests, 1) * 100,
            "avg_user_trust": avg_user_trust,
            "avg_device_trust": avg_device_trust,
            "avg_risk_level": avg_risk,
            "total_users": len(self.users),
            "total_devices": len(self.devices),
            "total_policies": len(self.policies),
        }


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    # Demo
    zt = ZeroTrustEngine()

    # Register demo user and device
    user = User(
        user_id="user_001",
        username="alice",
        email="alice@example.com",
        roles=["developer"],
        mfa_enabled=True,
    )
    zt.register_user(user)

    device = Device(
        device_id="dev_001",
        device_type="workstation",
        os="Linux",
        fingerprint="abc123",
        owner="alice",
        security_posture={
            "antivirus_enabled": True,
            "firewall_enabled": True,
            "updated_os": True,
            "mfa_enabled": True,
        },
    )
    zt.register_device(device)

    # Test access requests
    print("\n🔐 Zero-Trust Access Control Demo\n")

    # Test 1: Developer accessing code (should succeed)
    context1 = AccessContext(
        user=user, device=device, resource="/code/main.py", action="read", source_ip="10.0.0.1"
    )
    allowed, reason, violations = zt.verify_access(context1)
    print(f"Test 1 - Read code: {'✅ GRANTED' if allowed else '❌ DENIED'}")
    print(f"  Reason: {reason}")

    # Test 2: Developer trying admin action (should fail)
    context2 = AccessContext(
        user=user, device=device, resource="/admin/users", action="delete", source_ip="10.0.0.1"
    )
    allowed, reason, violations = zt.verify_access(context2)
    print(f"\nTest 2 - Delete admin resource: {'✅ GRANTED' if allowed else '❌ DENIED'}")
    print(f"  Reason: {reason}")
    if violations:
        print(f"  Violations: {violations}")

    # Statistics
    print("\n📊 Access Statistics:")
    stats = zt.get_access_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")
