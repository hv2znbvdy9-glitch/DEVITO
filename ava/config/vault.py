"""
AVA Vault Integration - Secret Management
Automatisches Laden von Secrets aus HashiCorp Vault
"""

import os
import base64
from typing import Optional, Dict, Any
from pathlib import Path

try:
    import hvac
    HVAC_AVAILABLE = True
except ImportError:
    HVAC_AVAILABLE = False

from ava.core.logging import logger


class VaultConfig:
    """Vault-Konfiguration."""
    
    def __init__(self):
        self.addr = os.getenv("VAULT_ADDR", "http://127.0.0.1:8200")
        self.token = os.getenv("VAULT_TOKEN")
        self.role_id = os.getenv("AVA_VAULT_ROLE_ID")
        self.secret_id = os.getenv("AVA_VAULT_SECRET_ID")
        self.mount = os.getenv("AVA_VAULT_MOUNT", "secret")
        self.path = os.getenv("AVA_VAULT_PATH", "ava/grpc")
        self.namespace = os.getenv("VAULT_NAMESPACE")  # Für Vault Enterprise


class VaultClient:
    """HashiCorp Vault Client für Secret Management."""
    
    def __init__(self, config: Optional[VaultConfig] = None):
        """
        Initialisiere Vault Client.
        
        Args:
            config: Vault-Konfiguration (oder aus Env)
        """
        if not HVAC_AVAILABLE:
            raise ImportError(
                "hvac library not installed. Install with: pip install hvac"
            )
        
        self.config = config or VaultConfig()
        self.client: Optional[hvac.Client] = None
        self._authenticated = False
    
    def connect(self) -> bool:
        """
        Verbindung zu Vault herstellen und authentifizieren.
        
        Returns:
            True wenn erfolgreich
        """
        try:
            # Client erstellen
            self.client = hvac.Client(
                url=self.config.addr,
                namespace=self.config.namespace
            )
            
            # Authentifizierung
            if self.config.token:
                # Token-Auth (für Dev/Testing)
                self.client.token = self.config.token
                logger.info("🔐 Vault: Token authentication")
            
            elif self.config.role_id and self.config.secret_id:
                # AppRole-Auth (für Production)
                auth_response = self.client.auth.approle.login(
                    role_id=self.config.role_id,
                    secret_id=self.config.secret_id
                )
                self.client.token = auth_response["auth"]["client_token"]
                logger.info("🔐 Vault: AppRole authentication")
            
            else:
                logger.error("❌ No Vault credentials found")
                return False
            
            # Verbindung testen
            if self.client.is_authenticated():
                self._authenticated = True
                logger.info(f"✅ Vault connected: {self.config.addr}")
                return True
            else:
                logger.error("❌ Vault authentication failed")
                return False
        
        except Exception as e:
            logger.error(f"❌ Vault connection failed: {e}")
            return False
    
    def get_secret(self, path: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Secret aus Vault abrufen.
        
        Args:
            path: Secret-Pfad (relativ zu mount/base_path)
        
        Returns:
            Secret-Daten oder None
        """
        if not self._authenticated:
            logger.warning("⚠️  Not authenticated to Vault")
            return None
        
        try:
            full_path = path or self.config.path
            
            # KV v2 Engine
            secret = self.client.secrets.kv.v2.read_secret_version(
                path=full_path,
                mount_point=self.config.mount
            )
            
            return secret["data"]["data"]
        
        except Exception as e:
            logger.error(f"❌ Failed to read secret from {full_path}: {e}")
            return None
    
    def get_grpc_config(self) -> Optional[Dict[str, str]]:
        """
        gRPC-Konfiguration aus Vault laden.
        
        Returns:
            Dict mit API-Key, JWT-Secret, etc.
        """
        secrets = self.get_secret()
        if not secrets:
            return None
        
        return {
            "api_key": secrets.get("api_key"),
            "jwt_secret": secrets.get("jwt_secret"),
            "grpc_bind": secrets.get("grpc_bind", "127.0.0.1"),
            "grpc_port": secrets.get("grpc_port", "50051"),
        }
    
    def get_tls_certificates(self, output_dir: str = "/tmp/ava_certs") -> Optional[str]:
        """
        TLS-Zertifikate aus Vault laden und in Dateien schreiben.
        
        Args:
            output_dir: Ziel-Verzeichnis für Zertifikate
        
        Returns:
            Pfad zum Zertifikats-Verzeichnis oder None
        """
        try:
            # TLS-Secrets abrufen
            tls_secrets = self.get_secret(f"{self.config.path}/tls")
            if not tls_secrets:
                logger.warning("⚠️  No TLS secrets found in Vault")
                return None
            
            # Verzeichnis erstellen
            cert_dir = Path(output_dir)
            cert_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            
            # Zertifikate decodieren und schreiben
            for name, b64_data in tls_secrets.items():
                if not b64_data:
                    continue
                
                # Base64 decodieren
                cert_data = base64.b64decode(b64_data)
                
                # Dateiname mappen
                filename_map = {
                    "server_cert": "server.crt",
                    "server_key": "server.key",
                    "ca_cert": "ca.crt",
                    "client_cert": "client.crt",
                    "client_key": "client.key",
                }
                
                filename = filename_map.get(name, f"{name}.pem")
                filepath = cert_dir / filename
                
                # Schreiben
                filepath.write_bytes(cert_data)
                
                # Permissions (Keys müssen 600 sein)
                if "key" in filename:
                    filepath.chmod(0o600)
                else:
                    filepath.chmod(0o644)
                
                logger.debug(f"✅ Wrote certificate: {filepath}")
            
            logger.info(f"✅ TLS certificates loaded from Vault: {cert_dir}")
            return str(cert_dir)
        
        except Exception as e:
            logger.error(f"❌ Failed to load TLS certificates: {e}")
            return None
    
    def renew_token(self) -> bool:
        """
        Token erneuern (falls TTL abläuft).
        
        Returns:
            True wenn erfolgreich
        """
        if not self._authenticated:
            return False
        
        try:
            self.client.auth.token.renew_self()
            logger.info("✅ Vault token renewed")
            return True
        except Exception as e:
            logger.error(f"❌ Token renewal failed: {e}")
            return False


class VaultSecretManager:
    """
    High-Level Secret Manager mit Caching und Auto-Renewal.
    """
    
    def __init__(self, config: Optional[VaultConfig] = None):
        self.vault = VaultClient(config)
        self._cache: Dict[str, Any] = {}
        self._cert_dir: Optional[str] = None
    
    def initialize(self) -> bool:
        """
        Vault-Verbindung initialisieren und Secrets laden.
        
        Returns:
            True wenn erfolgreich
        """
        # Verbinden
        if not self.vault.connect():
            logger.warning("⚠️  Vault not available, falling back to environment variables")
            return False
        
        # Secrets laden
        grpc_config = self.vault.get_grpc_config()
        if grpc_config:
            self._cache.update(grpc_config)
            logger.info("✅ Secrets loaded from Vault")
        
        # TLS-Zertifikate laden
        self._cert_dir = self.vault.get_tls_certificates()
        
        return True
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Secret abrufen (mit Fallback auf Env-Var).
        
        Args:
            key: Secret-Name
            default: Fallback-Wert
        
        Returns:
            Secret-Wert
        """
        # Aus Cache
        if key in self._cache:
            return self._cache[key]
        
        # Aus Environment
        env_key = f"AVA_{key.upper()}"
        return os.getenv(env_key, default)
    
    def get_api_key(self) -> Optional[str]:
        """API-Key abrufen."""
        return self.get("api_key", os.getenv("AVA_GRPC_TOKEN"))
    
    def get_jwt_secret(self) -> Optional[str]:
        """JWT-Secret abrufen."""
        return self.get("jwt_secret", os.getenv("AVA_JWT_SECRET"))
    
    def get_cert_dir(self) -> str:
        """Zertifikats-Verzeichnis abrufen."""
        if self._cert_dir:
            return self._cert_dir
        
        return os.getenv("AVA_CERT_DIR", "./certs")
    
    def get_bind_address(self) -> str:
        """Bind-Adresse abrufen."""
        return self.get("grpc_bind", "127.0.0.1")
    
    def get_bind_port(self) -> int:
        """Bind-Port abrufen."""
        return int(self.get("grpc_port", 50051))


# Globale Instanz
_secret_manager: Optional[VaultSecretManager] = None


def get_secret_manager() -> VaultSecretManager:
    """
    Globalen Secret Manager abrufen (Singleton).
    
    Returns:
        VaultSecretManager-Instanz
    """
    global _secret_manager
    
    if _secret_manager is None:
        _secret_manager = VaultSecretManager()
        
        # Versuche Vault zu initialisieren
        if HVAC_AVAILABLE:
            _secret_manager.initialize()
        else:
            logger.warning("⚠️  hvac not installed, using environment variables only")
    
    return _secret_manager
