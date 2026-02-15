"""
AVA gRPC Authentication & Authorization System
Erweiterte Authentifizierung mit JWT, API-Keys und RBAC
"""

import os
import time
import hashlib
import secrets
from typing import Optional, Dict, Set, List
from datetime import datetime, timedelta
from enum import Enum

import grpc
from grpc import aio

try:
    import jwt
    JWT_AVAILABLE = True
except ImportError:
    JWT_AVAILABLE = False

from ava.core.logging import logger


# ============================================================================
# ROLE-BASED ACCESS CONTROL (RBAC)
# ============================================================================

class Role(str, Enum):
    """Benutzerrollen für RBAC."""
    ADMIN = "admin"
    USER = "user"
    SERVICE = "service"
    READONLY = "readonly"


class Permission(str, Enum):
    """Berechtigungen für einzelne Operations."""
    READ_WELLBEING = "read:wellbeing"
    WRITE_WELLBEING = "write:wellbeing"
    READ_TASKS = "read:tasks"
    WRITE_TASKS = "write:tasks"
    SYNC_DATA = "sync:data"
    ADMIN_ACCESS = "admin:*"


# Rollen-Berechtigungsmapping
ROLE_PERMISSIONS: Dict[Role, Set[Permission]] = {
    Role.ADMIN: {
        Permission.READ_WELLBEING,
        Permission.WRITE_WELLBEING,
        Permission.READ_TASKS,
        Permission.WRITE_TASKS,
        Permission.SYNC_DATA,
        Permission.ADMIN_ACCESS,
    },
    Role.USER: {
        Permission.READ_WELLBEING,
        Permission.WRITE_WELLBEING,
        Permission.READ_TASKS,
        Permission.WRITE_TASKS,
        Permission.SYNC_DATA,
    },
    Role.SERVICE: {
        Permission.SYNC_DATA,
        Permission.READ_TASKS,
    },
    Role.READONLY: {
        Permission.READ_WELLBEING,
        Permission.READ_TASKS,
    },
}

# RPC-Methoden zu Berechtigungen
METHOD_PERMISSIONS: Dict[str, Permission] = {
    "/ava.v1.AVAService/GetWellbeingScore": Permission.READ_WELLBEING,
    "/ava.v1.AVAService/RecordMood": Permission.WRITE_WELLBEING,
    "/ava.v1.AVAService/CreateTask": Permission.WRITE_TASKS,
    "/ava.v1.AVAService/ListTasks": Permission.READ_TASKS,
    "/ava.v1.AVAService/UpdateTask": Permission.WRITE_TASKS,
    "/ava.v1.AVAService/SyncData": Permission.SYNC_DATA,
}


# ============================================================================
# API KEY MANAGEMENT
# ============================================================================

class APIKey:
    """API-Key mit Metadaten."""
    
    def __init__(
        self,
        key_id: str,
        key_hash: str,
        role: Role,
        owner: str,
        expires_at: Optional[datetime] = None,
        rate_limit: int = 1000,
    ):
        self.key_id = key_id
        self.key_hash = key_hash
        self.role = role
        self.owner = owner
        self.created_at = datetime.now()
        self.expires_at = expires_at
        self.rate_limit = rate_limit
        self.active = True
        self.last_used = None
    
    def is_valid(self) -> bool:
        """Prüfe ob Key noch gültig ist."""
        if not self.active:
            return False
        
        if self.expires_at and datetime.now() > self.expires_at:
            return False
        
        return True
    
    def verify(self, key: str) -> bool:
        """Verifiziere einen Key gegen Hash."""
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        return key_hash == self.key_hash
    
    def update_last_used(self):
        """Update last-used timestamp."""
        self.last_used = datetime.now()


class APIKeyStore:
    """Speicher für API-Keys (in Produktion: DB oder Vault)."""
    
    def __init__(self):
        self.keys: Dict[str, APIKey] = {}
        self._load_default_keys()
    
    def _load_default_keys(self):
        """Lade Standard-Admin-Keys aus Env."""
        admin_key = os.getenv("AVA_ADMIN_API_KEY")
        if admin_key:
            self.create_key(
                key=admin_key,
                role=Role.ADMIN,
                owner="system",
                expires_at=None
            )
    
    def create_key(
        self,
        key: Optional[str] = None,
        role: Role = Role.USER,
        owner: str = "anonymous",
        expires_at: Optional[datetime] = None,
        rate_limit: int = 1000,
    ) -> tuple[str, str]:
        """
        Erstelle einen neuen API-Key.
        Returns: (key_id, key_secret)
        """
        if key is None:
            key = secrets.token_urlsafe(32)
        
        key_id = secrets.token_hex(16)
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        
        api_key = APIKey(
            key_id=key_id,
            key_hash=key_hash,
            role=role,
            owner=owner,
            expires_at=expires_at,
            rate_limit=rate_limit,
        )
        
        self.keys[key_id] = api_key
        logger.info(f"✅ API Key created: {key_id} for {owner} (role: {role})")
        
        return key_id, key
    
    def verify_key(self, key: str) -> Optional[APIKey]:
        """Verifiziere einen API-Key."""
        for api_key in self.keys.values():
            if api_key.is_valid() and api_key.verify(key):
                api_key.update_last_used()
                return api_key
        return None
    
    def revoke_key(self, key_id: str) -> bool:
        """Widerrufe einen API-Key."""
        if key_id in self.keys:
            self.keys[key_id].active = False
            logger.info(f"🔒 API Key revoked: {key_id}")
            return True
        return False


# ============================================================================
# JWT TOKEN AUTHENTICATION
# ============================================================================

class JWTAuthenticator:
    """JWT-basierte Authentifizierung."""
    
    def __init__(self, secret_key: Optional[str] = None):
        if not JWT_AVAILABLE:
            logger.warning("⚠️  PyJWT not installed, JWT auth disabled")
            self.enabled = False
            return
        
        self.secret_key = secret_key or os.getenv("AVA_JWT_SECRET")
        if not self.secret_key:
            logger.warning("⚠️  No JWT secret configured, JWT auth disabled")
            self.enabled = False
            return
        
        self.enabled = True
        self.algorithm = "HS256"
        self.token_expiry = 3600  # 1 hour
    
    def create_token(self, user_id: str, role: Role, metadata: Optional[Dict] = None) -> str:
        """Erstelle ein JWT-Token."""
        if not self.enabled:
            raise RuntimeError("JWT authentication not enabled")
        
        payload = {
            "sub": user_id,
            "role": role.value,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(seconds=self.token_expiry),
        }
        
        if metadata:
            payload["metadata"] = metadata
        
        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
        return token
    
    def verify_token(self, token: str) -> Optional[Dict]:
        """Verifiziere und dekodiere ein JWT-Token."""
        if not self.enabled:
            return None
        
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("🚨 JWT token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"🚨 Invalid JWT token: {e}")
            return None


# ============================================================================
# ADVANCED AUTH INTERCEPTOR
# ============================================================================

class AdvancedAuthInterceptor(aio.ServerInterceptor):
    """
    Erweiterter Auth-Interceptor mit:
    - API-Key-Support
    - JWT-Token-Support
    - RBAC (Role-Based Access Control)
    - Rate-Limiting pro Key
    """
    
    def __init__(
        self,
        api_key_store: APIKeyStore,
        jwt_authenticator: Optional[JWTAuthenticator] = None,
        enable_rbac: bool = True,
    ):
        self.api_key_store = api_key_store
        self.jwt_authenticator = jwt_authenticator
        self.enable_rbac = enable_rbac
        
        # Rate-Limiting
        self.request_counts: Dict[str, List[float]] = {}
        self.rate_window = 60  # 1 minute
    
    async def intercept_service(self, continuation, handler_call_details):
        """Interceptor-Logik."""
        
        method = handler_call_details.method
        
        # Health-Check ohne Auth
        if method.endswith("HealthCheck"):
            return await continuation(handler_call_details)
        
        # Metadata extrahieren
        metadata = dict(handler_call_details.invocation_metadata)
        auth_header = metadata.get("authorization", "")
        
        # Authentifizierung
        role, user_id = await self._authenticate(auth_header)
        
        if not role:
            logger.warning(f"🚨 Authentication failed for {method}")
            return grpc.unary_unary_rpc_method_handler(
                lambda req, ctx: ctx.abort(
                    grpc.StatusCode.UNAUTHENTICATED,
                    "Authentication failed"
                )
            )
        
        # RBAC-Prüfung
        if self.enable_rbac and not self._check_permission(method, role):
            logger.warning(f"🚨 Authorization failed: {user_id} lacks permission for {method}")
            return grpc.unary_unary_rpc_method_handler(
                lambda req, ctx: ctx.abort(
                    grpc.StatusCode.PERMISSION_DENIED,
                    "Insufficient permissions"
                )
            )
        
        # Rate-Limiting prüfen
        if not self._check_rate_limit(user_id):
            logger.warning(f"🚨 Rate limit exceeded for {user_id}")
            return grpc.unary_unary_rpc_method_handler(
                lambda req, ctx: ctx.abort(
                    grpc.StatusCode.RESOURCE_EXHAUSTED,
                    "Rate limit exceeded"
                )
            )
        
        # Authentifiziert & autorisiert
        logger.debug(f"✅ Authenticated: {user_id} ({role}) → {method}")
        return await continuation(handler_call_details)
    
    async def _authenticate(self, auth_header: str) -> tuple[Optional[Role], Optional[str]]:
        """
        Authentifiziere via API-Key oder JWT.
        Returns: (role, user_id) oder (None, None)
        """
        if not auth_header.startswith("Bearer "):
            return None, None
        
        token = auth_header[7:]  # Strip "Bearer "
        
        # 1. Versuche API-Key
        api_key = self.api_key_store.verify_key(token)
        if api_key:
            return api_key.role, api_key.key_id
        
        # 2. Versuche JWT
        if self.jwt_authenticator and self.jwt_authenticator.enabled:
            payload = self.jwt_authenticator.verify_token(token)
            if payload:
                role_str = payload.get("role")
                user_id = payload.get("sub")
                try:
                    role = Role(role_str)
                    return role, user_id
                except ValueError:
                    pass
        
        return None, None
    
    def _check_permission(self, method: str, role: Role) -> bool:
        """Prüfe ob Rolle die Berechtigung für Methode hat."""
        required_permission = METHOD_PERMISSIONS.get(method)
        
        if not required_permission:
            # Methode nicht in MAP → erlauben (oder blocken, je nach Policy)
            return True
        
        allowed_permissions = ROLE_PERMISSIONS.get(role, set())
        
        # Admin hat immer Zugriff
        if Permission.ADMIN_ACCESS in allowed_permissions:
            return True
        
        return required_permission in allowed_permissions
    
    def _check_rate_limit(self, user_id: str) -> bool:
        """Simple Rate-Limiting-Prüfung."""
        now = time.time()
        
        if user_id not in self.request_counts:
            self.request_counts[user_id] = []
        
        # Alte Requests entfernen
        self.request_counts[user_id] = [
            ts for ts in self.request_counts[user_id]
            if now - ts < self.rate_window
        ]
        
        # Limit prüfen (1000 req/min)
        if len(self.request_counts[user_id]) >= 1000:
            return False
        
        self.request_counts[user_id].append(now)
        return True


# ============================================================================
# AUDIT LOGGER
# ============================================================================

class AuditLogger:
    """Audit-Log für alle authentifizierten Requests."""
    
    def __init__(self, log_file: str = "/var/log/ava/grpc_audit.log"):
        self.log_file = log_file
    
    def log_request(
        self,
        user_id: str,
        role: str,
        method: str,
        status: str,
        duration_ms: float,
        client_ip: Optional[str] = None,
    ):
        """Logge einen Request."""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "role": role,
            "method": method,
            "status": status,
            "duration_ms": duration_ms,
            "client_ip": client_ip,
        }
        
        logger.info(f"📋 AUDIT: {entry}")
        
        # In Produktion: in File/DB schreiben
        # with open(self.log_file, "a") as f:
        #     f.write(json.dumps(entry) + "\n")
