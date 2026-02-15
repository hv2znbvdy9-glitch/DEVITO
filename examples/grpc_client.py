#!/usr/bin/env python3
"""
AVA gRPC Client Beispiel

Demonstriert die Verwendung des sicheren gRPC-Clients mit TLS/mTLS
und Token-basierter Authentifizierung.
"""

import os
import sys
import grpc
from pathlib import Path

# Proto-Import (nach Compilation)
try:
    from ava.api.proto import ava_service_pb2, ava_service_pb2_grpc
except ImportError:
    print("❌ Proto-Dateien nicht kompiliert!")
    print("   Bitte ausführen: make proto-compile")
    sys.exit(1)


class AVASecureClient:
    """Sicherer gRPC-Client für AVA."""
    
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 50051,
        cert_dir: str = "./certs",
        api_key: str = None,
        insecure: bool = False,
    ):
        """
        Initialisiere AVA gRPC Client.
        
        Args:
            host: Server-Hostname/IP
            port: Server-Port
            cert_dir: Pfad zu TLS-Zertifikaten
            api_key: API-Key für Authentifizierung
            insecure: Falls True, keine TLS-Verschlüsselung (nur Dev!)
        """
        self.host = host
        self.port = port
        self.cert_dir = Path(cert_dir)
        self.api_key = api_key or os.getenv("AVA_API_KEY")
        self.insecure = insecure
        self.channel = None
        self.stub = None
    
    def _load_credentials(self) -> grpc.ChannelCredentials:
        """Lade TLS/mTLS-Credentials."""
        ca_cert_path = self.cert_dir / "ca.crt"
        client_cert_path = self.cert_dir / "client.crt"
        client_key_path = self.cert_dir / "client.key"
        
        # Prüfe ob Dateien existieren
        if not ca_cert_path.exists():
            raise FileNotFoundError(f"CA certificate not found: {ca_cert_path}")
        
        # CA-Cert laden
        with open(ca_cert_path, "rb") as f:
            ca_cert = f.read()
        
        # Client-Cert & Key für mTLS (optional)
        client_cert = None
        client_key = None
        
        if client_cert_path.exists() and client_key_path.exists():
            with open(client_cert_path, "rb") as f:
                client_cert = f.read()
            with open(client_key_path, "rb") as f:
                client_key = f.read()
            print("✅ mTLS aktiviert (Client-Cert geladen)")
        else:
            print("⚠️  Nur TLS (kein Client-Cert gefunden)")
        
        return grpc.ssl_channel_credentials(
            root_certificates=ca_cert,
            private_key=client_key,
            certificate_chain=client_cert,
        )
    
    def connect(self):
        """Verbindung zum Server aufbauen."""
        address = f"{self.host}:{self.port}"
        
        if self.insecure:
            print(f"⚠️  INSECURE CONNECTION zu {address}")
            self.channel = grpc.insecure_channel(address)
        else:
            credentials = self._load_credentials()
            
            # Channel-Optionen
            options = [
                # SAN-Override für Self-Signed Certs
                ("grpc.ssl_target_name_override", "ava-grpc-server"),
                # Keepalive
                ("grpc.keepalive_time_ms", 60000),
                ("grpc.keepalive_timeout_ms", 20000),
            ]
            
            print(f"🔒 Sichere Verbindung zu {address}")
            self.channel = grpc.secure_channel(address, credentials, options=options)
        
        # Stub erstellen
        self.stub = ava_service_pb2_grpc.AVAServiceStub(self.channel)
        print("✅ Verbindung hergestellt")
    
    def _get_metadata(self):
        """Authentifizierungs-Metadata erstellen."""
        if not self.api_key:
            print("⚠️  Kein API-Key gesetzt, Request könnte fehlschlagen")
            return []
        
        return [("authorization", f"Bearer {self.api_key}")]
    
    def health_check(self):
        """Health-Check durchführen."""
        request = ava_service_pb2.HealthCheckRequest(service="ava")
        
        try:
            response = self.stub.HealthCheck(request, metadata=self._get_metadata())
            print(f"✅ Health-Check OK: Status={response.status}, Version={response.version}")
            print(f"   Uptime: {response.uptime_seconds}s")
            
            if response.component_status:
                print("   Components:")
                for component, status in response.component_status.items():
                    print(f"     - {component}: {status}")
            
            return response
        except grpc.RpcError as e:
            print(f"❌ Health-Check failed: {e.code()} - {e.details()}")
            return None
    
    def get_wellbeing_score(self, user_id: str):
        """Wellbeing-Score abrufen."""
        request = ava_service_pb2.WellbeingRequest(
            user_id=user_id,
            timestamp=int(__import__("time").time())
        )
        
        try:
            response = self.stub.GetWellbeingScore(request, metadata=self._get_metadata())
            print(f"✅ Wellbeing Score: {response.score:.2f}")
            print(f"   Status: {response.status}")
            
            if response.metrics:
                print("   Metrics:")
                for key, value in response.metrics.items():
                    print(f"     - {key}: {value:.2f}")
            
            return response
        except grpc.RpcError as e:
            print(f"❌ GetWellbeingScore failed: {e.code()} - {e.details()}")
            return None
    
    def record_mood(self, user_id: str, mood_level: int, notes: str = ""):
        """Mood-Eintrag erstellen."""
        request = ava_service_pb2.MoodRequest(
            user_id=user_id,
            mood_level=mood_level,
            notes=notes,
            timestamp=int(__import__("time").time())
        )
        
        try:
            response = self.stub.RecordMood(request, metadata=self._get_metadata())
            print(f"✅ Mood recorded: {response.message}")
            return response
        except grpc.RpcError as e:
            print(f"❌ RecordMood failed: {e.code()} - {e.details()}")
            return None
    
    def list_tasks(self, user_id: str, status_filter: str = "", limit: int = 10):
        """Tasks auflisten."""
        request = ava_service_pb2.ListTasksRequest(
            user_id=user_id,
            status_filter=status_filter,
            limit=limit,
            offset=0
        )
        
        try:
            response = self.stub.ListTasks(request, metadata=self._get_metadata())
            print(f"✅ Tasks: {response.total_count} total")
            
            for task in response.tasks:
                print(f"   - [{task.status}] {task.title}")
            
            return response
        except grpc.RpcError as e:
            print(f"❌ ListTasks failed: {e.code()} - {e.details()}")
            return None
    
    def close(self):
        """Verbindung schließen."""
        if self.channel:
            self.channel.close()
            print("✅ Verbindung geschlossen")


def main():
    """Demo-Client."""
    import argparse
    
    parser = argparse.ArgumentParser(description="AVA gRPC Client")
    parser.add_argument("--host", default="127.0.0.1", help="Server host")
    parser.add_argument("--port", type=int, default=50051, help="Server port")
    parser.add_argument("--cert-dir", default="./certs", help="Certificate directory")
    parser.add_argument("--api-key", help="API Key (or set AVA_API_KEY env)")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS (dev only!)")
    parser.add_argument("--user-id", default="demo-user", help="User ID for requests")
    
    args = parser.parse_args()
    
    # Client initialisieren
    client = AVASecureClient(
        host=args.host,
        port=args.port,
        cert_dir=args.cert_dir,
        api_key=args.api_key,
        insecure=args.insecure,
    )
    
    try:
        # Verbinden
        client.connect()
        
        print("\n" + "="*60)
        print("AVA gRPC Client Demo")
        print("="*60 + "\n")
        
        # 1. Health-Check
        print("1️⃣  Health Check")
        print("-" * 60)
        client.health_check()
        
        # 2. Wellbeing Score
        print("\n2️⃣  Wellbeing Score")
        print("-" * 60)
        client.get_wellbeing_score(args.user_id)
        
        # 3. Mood aufzeichnen
        print("\n3️⃣  Record Mood")
        print("-" * 60)
        client.record_mood(args.user_id, mood_level=8, notes="Feeling great today!")
        
        # 4. Tasks auflisten
        print("\n4️⃣  List Tasks")
        print("-" * 60)
        client.list_tasks(args.user_id)
        
        print("\n" + "="*60)
        print("✅ Demo abgeschlossen!")
        print("="*60)
        
    except Exception as e:
        print(f"❌ Fehler: {e}")
        import traceback
        traceback.print_exc()
    finally:
        client.close()


if __name__ == "__main__":
    main()
