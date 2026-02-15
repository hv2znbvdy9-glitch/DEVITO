# AVA gRPC Secure Server

Production-ready gRPC Server mit TLS/mTLS, RBAC, Rate-Limiting und Audit-Logging.

## 🚀 Schnellstart

### 1. Setup

```bash
# Dependencies installieren
make install-dev

# Proto-Dateien kompilieren
make proto-compile

# Zertifikate generieren (Dev)
make grpc-certs
```

### 2. Server starten

```bash
# API-Key setzen
export AVA_ADMIN_API_KEY="ava-secret-$(openssl rand -hex 24)"

# Zertifikats-Pfad
export AVA_CERT_DIR="./certs"

# Server starten
python -m ava.api.grpc_server
```

### 3. Client-Test

```python
import grpc
from ava.api.proto import ava_service_pb2, ava_service_pb2_grpc

# TLS-Credentials
with open("certs/ca.crt", "rb") as f:
    ca_cert = f.read()
with open("certs/client.crt", "rb") as f:
    client_cert = f.read()
with open("certs/client.key", "rb") as f:
    client_key = f.read()

credentials = grpc.ssl_channel_credentials(
    root_certificates=ca_cert,
    private_key=client_key,
    certificate_chain=client_cert
)

# Verbinden
channel = grpc.secure_channel(
    "127.0.0.1:50051",
    credentials,
    options=[("grpc.ssl_target_name_override", "ava-grpc-server")]
)

stub = ava_service_pb2_grpc.AVAServiceStub(channel)

# Authentifizierung
metadata = [("authorization", f"Bearer {API_KEY}")]

# Health-Check
response = stub.HealthCheck(
    ava_service_pb2.HealthCheckRequest(service="ava"),
    metadata=metadata
)
print(f"Status: {response.status}")
```

## 📚 Dokumentation

- **[Vollständige Sicherheitsdokumentation](../../docs/GRPC_SECURITY.md)**
- **[Proto-Definitionen](proto/ava_service.proto)**

## 🔐 Sicherheitsfeatures

✅ TLS/mTLS-Verschlüsselung  
✅ Token-basierte Authentifizierung (API-Key/JWT)  
✅ Role-Based Access Control (RBAC)  
✅ Rate-Limiting (1000 req/min)  
✅ Message-Size-Limits (4 MiB)  
✅ Connection-Limits (Keepalive, Max-Age)  
✅ Graceful Shutdown  
✅ Audit-Logging  
✅ Gezieltes Binding (nicht `0.0.0.0`)

## 🏗️ Architektur

```
ava/api/
├── grpc_server.py       # Hauptserver mit TLS/mTLS
├── grpc_auth.py         # Auth-Interceptors & RBAC
├── proto/
│   ├── ava_service.proto        # Proto-Definitionen
│   ├── ava_service_pb2.py       # Generierte Messages
│   └── ava_service_pb2_grpc.py  # Generierte Stubs
└── README.md            # Diese Datei
```

## 🔧 Konfiguration

### Umgebungsvariablen

| Variable | Default | Beschreibung |
|----------|---------|--------------|
| `AVA_CERT_DIR` | `./certs` | Pfad zu TLS-Zertifikaten |
| `AVA_GRPC_BIND` | `127.0.0.1` | Bind-Adresse |
| `AVA_GRPC_PORT` | `50051` | Port |
| `AVA_GRPC_TOKEN` | - | Statischer Auth-Token |
| `AVA_ADMIN_API_KEY` | - | Admin API-Key |
| `AVA_JWT_SECRET` | - | JWT-Secret (min. 256 bit) |

### Production

**NIEMALS in Production**:
- `0.0.0.0` als Bind-Adresse
- Insecure-Credentials
- Self-signed Certificates (nur Dev!)
- Secrets im Code/Env (nutze Vault!)

**Immer in Production**:
- Echte TLS-Zertifikate (Let's Encrypt, PKI, Cloud-CA)
- mTLS aktiviert
- Firewall konfiguriert
- Non-Root-User
- Resource-Limits
- Monitoring & Alerting

## 📊 Monitoring

```bash
# Server-Logs
tail -f /var/log/ava/grpc.log

# Audit-Logs
tail -f /var/log/ava/grpc_audit.log

# Health-Check
grpc_health_probe -addr=localhost:50051
```

## 🐛 Troubleshooting

### "SSL_ERROR_SSL" oder "certificate verify failed"

**Problem**: Client kann Server-Cert nicht verifizieren

**Lösung**:
```python
# CA-Cert explizit laden
credentials = grpc.ssl_channel_credentials(
    root_certificates=ca_cert  # ← Wichtig!
)

# SAN-Override für Self-Signed Certs
options = [("grpc.ssl_target_name_override", "ava-grpc-server")]
```

### "UNAUTHENTICATED" Error

**Problem**: Token fehlt oder ungültig

**Lösung**:
```python
# Metadata korrekt setzen
metadata = [("authorization", f"Bearer {token}")]  # ← "Bearer " mit Leerzeichen!
stub.Method(request, metadata=metadata)
```

### "PERMISSION_DENIED" Error

**Problem**: User hat keine Berechtigung für Methode

**Lösung**: Rolle prüfen und anpassen (siehe `ROLE_PERMISSIONS` in `grpc_auth.py`)

### "connection refused"

**Problem**: Server läuft nicht oder auf anderer Adresse

**Lösung**:
```bash
# Server-Adresse prüfen
netstat -tlnp | grep 50051

# Firewall prüfen
sudo iptables -L | grep 50051
```

## 🧪 Testing

```bash
# Unit-Tests
pytest tests/api/test_grpc_server.py

# Load-Testing (mit ghz)
ghz --insecure \
    --proto ava/api/proto/ava_service.proto \
    --call ava.v1.AVAService/HealthCheck \
    -d '{"service":"ava"}' \
    -n 10000 \
    -c 100 \
    localhost:50051
```

## 📝 Lizenz

Siehe [LICENSE](../../LICENSE)
