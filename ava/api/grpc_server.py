"""
AVA gRPC Secure Server - Production-Ready Implementation
Basierend auf Security-Best-Practices aus C++/gRPC-Hardening
"""

import asyncio
import signal
import time
import os
from concurrent import futures
from typing import Optional

import grpc
from grpc import aio

# Proto-Generierte Klassen (nach Proto-Compilation verfügbar)
# from ava.api.proto import ava_service_pb2, ava_service_pb2_grpc

from ava.core.logging import logger
from ava.db.pool import DatabasePool
from ava.sync.manager import SyncQueue
from ava.tasks.scheduler import TaskScheduler

# Production Features
try:
    from ava.config.vault import get_secret_manager
    VAULT_AVAILABLE = True
except ImportError:
    VAULT_AVAILABLE = False
    logger.warning("⚠️  Vault integration not available")

try:
    from ava.monitoring.grpc_metrics import get_metrics, MetricsInterceptor
    from ava.api.grpc_auth import (
        AdvancedAuthInterceptor, APIKeyStore, JWTAuthenticator, VaultConfig
    )
    ADVANCED_FEATURES = True
except ImportError:
    ADVANCED_FEATURES = False
    logger.warning("⚠️  Advanced features not available")


# ============================================================================
# CONFIGURATION
# ============================================================================

def load_config():
    """Lade Konfiguration aus Vault oder Environment."""
    
    # Versuche Vault zuerst
    if VAULT_AVAILABLE:
        try:
            secret_manager = get_secret_manager()
            return {
                'bind_address': secret_manager.get_bind_address(),
                'bind_port': secret_manager.get_bind_port(),
                'cert_dir': secret_manager.get_cert_dir(),
                'api_key': secret_manager.get_api_key(),
                'jwt_secret': secret_manager.get_jwt_secret(),
            }
        except Exception as e:
            logger.warning(f"⚠️  Failed to load from Vault: {e}, falling back to env")
    
    # Fallback: Environment
    return {
        'bind_address': os.getenv("AVA_GRPC_BIND", "127.0.0.1"),
        'bind_port': int(os.getenv("AVA_GRPC_PORT", "50051")),
        'cert_dir': os.getenv("AVA_CERT_DIR", "/workspaces/AVA/certs"),
        'api_key': os.getenv("AVA_GRPC_TOKEN", "super-secret-token-change-me"),
        'jwt_secret': os.getenv("AVA_JWT_SECRET"),
    }


config = load_config()

# TLS/mTLS Zertifikatpfade
CERT_DIR = config['cert_dir']
SERVER_CERT = os.path.join(CERT_DIR, "server.crt")
SERVER_KEY = os.path.join(CERT_DIR, "server.key")
CA_CERT = os.path.join(CERT_DIR, "ca.crt")

# Server-Konfiguration
BIND_ADDRESS = config['bind_address']
BIND_PORT = config['bind_port']

# Hardening Limits
MAX_MESSAGE_SIZE = 4 * 1024 * 1024  # 4 MiB
KEEPALIVE_TIME_MS = 60_000  # 60s
KEEPALIVE_TIMEOUT_MS = 20_000  # 20s
MAX_CONNECTION_IDLE_MS = 300_000  # 5 min
MAX_CONNECTION_AGE_MS = 3600_000  # 1 hour


# ============================================================================
# AUTHENTICATION INTERCEPTOR
# ============================================================================

class AuthInterceptor(grpc.aio.ServerInterceptor):
    """
    gRPC Server Interceptor für Token-basierte Authentifizierung.
    Prüft Authorization-Header in Metadata.
    """

    async def intercept_service(self, continuation, handler_call_details):
        """Interceptor-Logik für jeden eingehenden RPC."""
        
        # Health-Check ohne Auth zulassen (Monitoring)
        if handler_call_details.method.endswith("HealthCheck"):
            return await continuation(handler_call_details)
        
        # Metadata extrahieren
        metadata = dict(handler_call_details.invocation_metadata)
        auth_header = metadata.get(AUTH_HEADER, "")
        
        # Token validieren
        if not auth_header.startswith(BEARER_PREFIX):
            logger.warning(f"🚨 Unauthorized access attempt: Missing/Invalid Bearer token")
            return grpc.unary_unary_rpc_method_handler(
                lambda request, context: self._unauthenticated_response(context)
            )
        
        token = auth_header[len(BEARER_PREFIX):]
        if token != AUTH_TOKEN:
            logger.warning(f"🚨 Unauthorized access attempt: Invalid token")
            return grpc.unary_unary_rpc_method_handler(
                lambda request, context: self._unauthenticated_response(context)
            )
        
        # Token gültig → weitergeben
        return await continuation(handler_call_details)
    
    def _unauthenticated_response(self, context):
        """Returniere UNAUTHENTICATED-Status."""
        context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid or missing authentication token")


# ============================================================================
# RATE-LIMITING INTERCEPTOR
# ============================================================================

class RateLimitInterceptor(grpc.aio.ServerInterceptor):
    """
    Einfaches Rate-Limiting (Token-Bucket-Prinzip).
    Limitiert Anfragen pro Client-IP.
    """
    
    def __init__(self, max_requests_per_minute: int = 100):
        self.max_requests = max_requests_per_minute
        self.client_requests = {}  # {client_ip: [(timestamp, ...), ...]}
        self.window_seconds = 60
        
    async def intercept_service(self, continuation, handler_call_details):
        """Rate-Limiting-Logik."""
        
        # Client-IP extrahieren (aus Peer-Info)
        peer = handler_call_details.invocation_metadata
        client_ip = "unknown"
        for key, value in peer:
            if key == "x-forwarded-for":
                client_ip = value.split(",")[0].strip()
                break
        
        # Anfragen tracken
        now = time.time()
        if client_ip not in self.client_requests:
            self.client_requests[client_ip] = []
        
        # Alte Einträge entfernen
        self.client_requests[client_ip] = [
            ts for ts in self.client_requests[client_ip]
            if now - ts < self.window_seconds
        ]
        
        # Rate-Limit prüfen
        if len(self.client_requests[client_ip]) >= self.max_requests:
            logger.warning(f"🚨 Rate limit exceeded for {client_ip}")
            return grpc.unary_unary_rpc_method_handler(
                lambda request, context: context.abort(
                    grpc.StatusCode.RESOURCE_EXHAUSTED,
                    "Rate limit exceeded"
                )
            )
        
        # Request zählen
        self.client_requests[client_ip].append(now)
        return await continuation(handler_call_details)


# ============================================================================
# gRPC SERVICE IMPLEMENTATION
# ============================================================================

# TODO: Nach Proto-Compilation auskommentieren
# class AVAServiceImplementation(ava_service_pb2_grpc.AVAServiceServicer):
class AVAServiceImplementation:
    """
    Implementierung des AVA gRPC Service.
    Stellt alle AVA-Funktionen über gRPC bereit.
    """
    
    def __init__(self, db_pool: DatabasePool, sync_queue: SyncQueue, task_scheduler: TaskScheduler):
        self.db_pool = db_pool
        self.sync_queue = sync_queue
        self.task_scheduler = task_scheduler
        self.start_time = time.time()
    
    async def HealthCheck(self, request, context):
        """Health-Check-Endpoint für Monitoring."""
        # return ava_service_pb2.HealthCheckResponse(
        #     status="healthy",
        #     version="2.0.0",
        #     uptime_seconds=int(time.time() - self.start_time),
        #     component_status={
        #         "database": "healthy",
        #         "sync": "healthy",
        #         "tasks": "healthy"
        #     }
        # )
        logger.info("Health check requested")
        return None  # Placeholder bis Proto kompiliert ist
    
    async def GetWellbeingScore(self, request, context):
        """Wellbeing Score abrufen."""
        logger.info(f"Wellbeing score requested for user: {request.user_id}")
        # TODO: Implementierung
        return None
    
    async def RecordMood(self, request, context):
        """Mood-Eintrag speichern."""
        logger.info(f"Mood recorded: {request.mood_level} for user {request.user_id}")
        # TODO: Implementierung
        return None
    
    async def CreateTask(self, request, context):
        """Task erstellen."""
        logger.info(f"Task created: {request.title}")
        # TODO: Implementierung
        return None
    
    async def ListTasks(self, request, context):
        """Tasks auflisten."""
        logger.info(f"Tasks listed for user: {request.user_id}")
        # TODO: Implementierung
        return None


# ============================================================================
# SECURE gRPC SERVER
# ============================================================================

class SecureGRPCServer:
    """
    Production-ready gRPC Server mit:
    - TLS/mTLS Verschlüsselung
    - Token-basierter Authentifizierung
    - Rate-Limiting
    - Resource-Limits
    - Graceful Shutdown
    """
    
    def __init__(self):
        self.server: Optional[grpc.aio.Server] = None
        self.db_pool: Optional[DatabasePool] = None
        self.sync_queue: Optional[SyncQueue] = None
        self.task_scheduler: Optional[TaskScheduler] = None
        self._shutdown_event = asyncio.Event()
        
    def _load_credentials(self) -> grpc.ServerCredentials:
        """
        TLS/mTLS-Credentials laden.
        Falls Zertifikate fehlen, Fallback auf Insecure (nur Dev!).
        """
        if not all(os.path.exists(f) for f in [SERVER_CERT, SERVER_KEY, CA_CERT]):
            logger.warning("⚠️  Missing TLS certificates! Falling back to INSECURE mode (DEV ONLY!)")
            logger.warning(f"   Expected certs in: {CERT_DIR}")
            return None
        
        # Server-Zertifikat & Schlüssel laden
        with open(SERVER_KEY, "rb") as f:
            server_key = f.read()
        with open(SERVER_CERT, "rb") as f:
            server_cert = f.read()
        with open(CA_CERT, "rb") as f:
            ca_cert = f.read()
        
        # mTLS aktivieren (Client-Zertifikat erforderlich)
        credentials = grpc.ssl_server_credentials(
            [(server_key, server_cert)],
            root_certificates=ca_cert,
            require_client_auth=True  # mTLS!
        )
        
        logger.info("✅ TLS/mTLS credentials loaded successfully")
        return credentials
    
    def _setup_server_options(self) -> list:
        """
        Server-Optionen für Hardening konfigurieren.
        """
        return [
            # Message-Size-Limits
            ("grpc.max_send_message_length", MAX_MESSAGE_SIZE),
            ("grpc.max_receive_message_length", MAX_MESSAGE_SIZE),
            
            # Keepalive (verhindert hängende Connections)
            ("grpc.keepalive_time_ms", KEEPALIVE_TIME_MS),
            ("grpc.keepalive_timeout_ms", KEEPALIVE_TIMEOUT_MS),
            ("grpc.http2.min_ping_interval_without_data_ms", 30_000),
            ("grpc.http2.max_pings_without_data", 0),
            
            # Connection-Limits (verhindert Ressourcen-Exhaustion)
            ("grpc.max_connection_idle_ms", MAX_CONNECTION_IDLE_MS),
            ("grpc.max_connection_age_ms", MAX_CONNECTION_AGE_MS),
            
            # Thread-Pool-Größe
            ("grpc.max_concurrent_streams", 100),
        ]
    
    async def setup(self):
        """Server-Komponenten initialisieren."""
        logger.info("🔧 Initializing AVA Secure gRPC Server...")
        
        # Datenbank
        self.db_pool = DatabasePool("sqlite:///ava.db")
        self.db_pool.initialize()
        
        # Sync Queue
        self.sync_queue = SyncQueue()
        
        # Task Scheduler
        self.task_scheduler = TaskScheduler()
        
        logger.info("✅ Components initialized")
    
    async def start(self):
        """Server starten."""
        # Credentials laden
        credentials = self._load_credentials()
        
        # Service-Implementierung
        service = AVAServiceImplementation(
            self.db_pool,
            self.sync_queue,
            self.task_scheduler
        )
        
        # Server erstellen mit Interceptors
        self.server = grpc.aio.server(
            futures.ThreadPoolExecutor(max_workers=10),
            interceptors=[
                AuthInterceptor(),
                RateLimitInterceptor(max_requests_per_minute=100),
            ],
            options=self._setup_server_options()
        )
        
        # Service registrieren
        # ava_service_pb2_grpc.add_AVAServiceServicer_to_server(service, self.server)
        
        # Server-Adresse binden
        bind_addr = f"{BIND_ADDRESS}:{BIND_PORT}"
        
        if credentials:
            self.server.add_secure_port(bind_addr, credentials)
            logger.info(f"🔒 Secure gRPC Server listening on {bind_addr} (TLS/mTLS)")
        else:
            self.server.add_insecure_port(bind_addr)
            logger.warning(f"⚠️  INSECURE gRPC Server listening on {bind_addr} (DEV ONLY!)")
        
        # Server starten
        await self.server.start()
        logger.info("✅ gRPC Server started successfully")
        
        # Signal-Handler registrieren
        self._setup_signal_handlers()
        
        # Warten bis Shutdown
        await self._shutdown_event.wait()
    
    def _setup_signal_handlers(self):
        """Signal-Handler für graceful shutdown."""
        loop = asyncio.get_event_loop()
        
        for sig in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(
                sig,
                lambda s=sig: asyncio.create_task(self._shutdown(s))
            )
    
    async def _shutdown(self, sig):
        """Graceful shutdown."""
        logger.info(f"🛑 Shutdown signal received: {sig.name}")
        
        # Server stoppen (graceful period)
        if self.server:
            logger.info("Shutting down gRPC server...")
            await self.server.stop(grace=10)  # 10s grace period
        
        # Komponenten aufräumen
        if self.db_pool:
            logger.info("Closing database connections...")
            # self.db_pool.close()  # Implementierung hinzufügen
        
        logger.info("✅ Shutdown complete")
        self._shutdown_event.set()


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

async def main():
    """Main entry point für gRPC Server."""
    server = SecureGRPCServer()
    await server.setup()
    await server.start()


if __name__ == "__main__":
    asyncio.run(main())
