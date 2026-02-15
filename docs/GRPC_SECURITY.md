# AVA gRPC Secure Server - Sicherheitsdokumentation

## 🔒 Übersicht

Diese Dokumentation beschreibt die Sicherheitsfeatures des AVA gRPC-Servers, basierend auf Best Practices aus dem C++/gRPC-Hardening-Leitfaden.

## 📋 Inhaltsverzeichnis

1. [Sicherheitsfeatures](#sicherheitsfeatures)
2. [Quick Start](#quick-start)
3. [Authentifizierung & Autorisierung](#authentifizierung--autorisierung)
4. [TLS/mTLS-Konfiguration](#tlsmtls-konfiguration)
5. [Rate-Limiting & DDoS-Schutz](#rate-limiting--ddos-schutz)
6. [Audit-Logging](#audit-logging)
7. [Production Deployment](#production-deployment)
8. [Sicherheits-Checkliste](#sicherheits-checkliste)
9. [Bekannte Schwachstellen & Mitigationen](#bekannte-schwachstellen--mitigationen)

---

## 🛡️ Sicherheitsfeatures

Der AVA gRPC-Server implementiert folgende Sicherheitsmaßnahmen:

### ✅ Implementiert

- **TLS/mTLS-Verschlüsselung**: Alle Verbindungen sind verschlüsselt
- **Token-basierte Authentifizierung**: Bearer-Token (API-Key oder JWT)
- **Role-Based Access Control (RBAC)**: Feinkörnige Berechtigungskontrolle
- **Rate-Limiting**: Schutz vor Request-Flooding
- **Message-Size-Limits**: Schutz vor Memory-Exhaustion (4 MiB)
- **Connection-Limits**: Keepalive, Max-Idle, Max-Age
- **Graceful Shutdown**: Sauberes Beenden mit Signal-Handling
- **Audit-Logging**: Protokollierung aller Zugriffe
- **Gezieltes Binding**: Nicht auf `0.0.0.0` (Standard: `127.0.0.1`)

### ⚠️ Empfohlen (zusätzlich)

- **Service Mesh** (Envoy/Istio): Für Traffic-Management & Observability
- **API Gateway**: Zentraler Entry-Point mit WAF
- **SPIFFE/SPIRE**: Für automatische Zertifikatsverwaltung
- **OPA (Open Policy Agent)**: Für deklarative Authorization
- **Distributed Tracing**: Jaeger/Zipkin für Request-Verfolgung

---

## 🚀 Quick Start

### 1. Dependencies installieren

```bash
# Mit pip
pip install -e ".[dev]"

# Oder mit Make
make install-dev
```

### 2. Proto-Dateien kompilieren

```bash
make proto-compile
```

Dies generiert:
- `ava/api/proto/ava_service_pb2.py` (Message-Definitionen)
- `ava/api/proto/ava_service_pb2_grpc.py` (Service-Stubs)

### 3. TLS-Zertifikate generieren (Dev)

```bash
make grpc-certs
```

**⚠️ ACHTUNG**: Für Produktion echte Zertifikate verwenden!

Erstellt in `./certs/`:
- `ca.crt` / `ca.key` (Certificate Authority)
- `server.crt` / `server.key` (Server-Zertifikat)
- `client.crt` / `client.key` (Client-Zertifikat für mTLS)

### 4. API-Key erstellen

```bash
export AVA_ADMIN_API_KEY="ava-secret-$(openssl rand -hex 24)"
echo "Your API Key: $AVA_ADMIN_API_KEY"
```

### 5. Server starten

```bash
# Mit TLS (empfohlen)
export AVA_CERT_DIR="./certs"
export AVA_GRPC_TOKEN="$AVA_ADMIN_API_KEY"
python -m ava.api.grpc_server

# INSECURE (nur Dev!)
export AVA_CERT_DIR="/nonexistent"  # Fallback zu Insecure
python -m ava.api.grpc_server
```

### 6. Client-Test

```python
import grpc
from ava.api.proto import ava_service_pb2, ava_service_pb2_grpc

# TLS-Credentials laden
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

# Verbindung mit Auth
channel = grpc.secure_channel(
    "127.0.0.1:50051",
    credentials,
    options=[
        ("grpc.ssl_target_name_override", "ava-grpc-server"),
    ]
)

stub = ava_service_pb2_grpc.AVAServiceStub(channel)

# Auth-Metadata
metadata = [("authorization", f"Bearer {API_KEY}")]

# Health-Check
response = stub.HealthCheck(
    ava_service_pb2.HealthCheckRequest(service="ava"),
    metadata=metadata
)
print(f"Status: {response.status}")
```

---

## 🔐 Authentifizierung & Autorisierung

### Auth-Mechanismen

Der Server unterstützt zwei Auth-Mechanismen (beide via `Authorization: Bearer <token>`):

#### 1. API-Keys

**Vorteile**: Einfach, für Service-to-Service, langlebig  
**Nachteile**: Keine User-Identity, manuelles Rotation

**Verwendung**:
```python
from ava.api.grpc_auth import APIKeyStore

store = APIKeyStore()
key_id, key_secret = store.create_key(
    role=Role.USER,
    owner="alice",
    expires_at=datetime.now() + timedelta(days=90),
    rate_limit=1000
)

print(f"API Key: {key_secret}")
print(f"Key ID: {key_id}")
```

**Client**:
```python
metadata = [("authorization", f"Bearer {key_secret}")]
response = stub.ListTasks(request, metadata=metadata)
```

#### 2. JWT-Tokens

**Vorteile**: Self-contained, User-Identity, Auto-Expiry  
**Nachteile**: Komplexer, Secret-Management erforderlich

**Server-Konfiguration**:
```bash
export AVA_JWT_SECRET="your-secret-key-min-256-bit"
```

**Token-Erstellung**:
```python
from ava.api.grpc_auth import JWTAuthenticator

jwt_auth = JWTAuthenticator(secret_key="your-secret")
token = jwt_auth.create_token(
    user_id="alice",
    role=Role.USER,
    metadata={"email": "alice@example.com"}
)
```

**Client**: Identisch zu API-Key

### Role-Based Access Control (RBAC)

Rollen:
- `ADMIN`: Voller Zugriff auf alle Endpoints
- `USER`: Standard-Benutzer (Wellbeing, Tasks, Sync)
- `SERVICE`: Service-Accounts (nur Sync, Read-Tasks)
- `READONLY`: Nur Leserechte

**Anpassen**:
```python
# In ava/api/grpc_auth.py
ROLE_PERMISSIONS[Role.CUSTOM] = {
    Permission.READ_WELLBEING,
    Permission.WRITE_TASKS,
}

METHOD_PERMISSIONS["/ava.v1.AVAService/CustomMethod"] = Permission.CUSTOM_PERM
```

---

## 🔒 TLS/mTLS-Konfiguration

### Entwicklung (Self-Signed)

```bash
make grpc-certs
export AVA_CERT_DIR="./certs"
```

### Produktion

**Option 1: Let's Encrypt** (öffentliche Domains)
```bash
certbot certonly --standalone -d grpc.ava-system.com
export AVA_CERT_DIR="/etc/letsencrypt/live/grpc.ava-system.com"
```

**Option 2: Internal PKI**
```bash
# Mit Vault PKI
vault write pki/issue/ava-server common_name=ava-grpc.internal ttl=720h
```

**Option 3: Cloud-Provider**
- **AWS**: ACM Private CA + AWS Certificate Manager
- **Azure**: Azure Key Vault Certificates
- **GCP**: Certificate Authority Service

### mTLS erzwingen

In `ava/api/grpc_server.py` ist mTLS standardmäßig aktiv:

```python
credentials = grpc.ssl_server_credentials(
    [(server_key, server_cert)],
    root_certificates=ca_cert,
    require_client_auth=True  # ← Client-Cert erforderlich!
)
```

**Client muss Zertifikat bereitstellen**:
```python
credentials = grpc.ssl_channel_credentials(
    root_certificates=ca_cert,
    private_key=client_key,      # ← Client-Key
    certificate_chain=client_cert # ← Client-Cert
)
```

### Zertifikats-Rotation

**Best Practices**:
1. Zertifikate alle 90 Tage erneuern
2. Graceful-Reload ohne Downtime
3. Monitoring von Ablaufdaten

**Rotation-Script**:
```bash
#!/bin/bash
# rotate_certs.sh

# Neue Certs generieren
certbot renew

# Server neuladen (Graceful)
pkill -SIGHUP -f "ava.api.grpc_server"
```

---

## 🚦 Rate-Limiting & DDoS-Schutz

### Implementierte Limits

**Server-Level** (`ava/api/grpc_server.py`):
```python
MAX_MESSAGE_SIZE = 4 * 1024 * 1024  # 4 MiB
KEEPALIVE_TIME_MS = 60_000          # 60s
KEEPALIVE_TIMEOUT_MS = 20_000       # 20s
MAX_CONNECTION_IDLE_MS = 300_000    # 5 min
MAX_CONNECTION_AGE_MS = 3600_000    # 1 hour
```

**User-Level** (`RateLimitInterceptor`):
- Default: 1000 Requests/Minute pro User
- Konfigurierbar pro API-Key

### Erweiterte Maßnahmen

**1. IP-basiertes Rate-Limiting**:
```python
# In Zukunft: Redis-backed Limiter
from redis import Redis
from limits import RateLimitItemPerMinute
from limits.storage import RedisStorage

storage = RedisStorage("redis://localhost:6379")
limiter = RateLimitItemPerMinute(100, namespace="grpc")
```

**2. Circuit Breaker**:
```python
# Bei zu vielen Fehlern: Verbindung trennen
if error_rate > 0.5:
    context.abort(grpc.StatusCode.UNAVAILABLE, "Circuit breaker open")
```

**3. Load Shedding**:
```python
# Bei Überlast: Anfragen ablehnen
if active_requests > MAX_CONCURRENT:
    context.abort(grpc.StatusCode.RESOURCE_EXHAUSTED, "Server overloaded")
```

---

## 📊 Audit-Logging

### Was wird geloggt?

Jeder Request wird mit folgenden Daten protokolliert:
- Timestamp (UTC)
- User-ID / API-Key-ID
- Rolle
- RPC-Methode
- Status (OK, PERMISSION_DENIED, etc.)
- Dauer (ms)
- Client-IP (falls verfügbar)

### Log-Format

```json
{
  "timestamp": "2026-02-15T10:23:45.123Z",
  "user_id": "alice",
  "role": "user",
  "method": "/ava.v1.AVAService/CreateTask",
  "status": "OK",
  "duration_ms": 42.5,
  "client_ip": "10.0.1.42"
}
```

### Konfiguration

**In `ava/api/grpc_auth.py`**:
```python
audit_logger = AuditLogger(log_file="/var/log/ava/grpc_audit.log")
audit_logger.log_request(...)
```

**Empfehlungen**:
- Logs an zentrales SIEM weiterleiten (ELK, Splunk, Datadog)
- Retention: Min. 90 Tage (DSGVO: bis zu 6 Monate)
- Verschlüsselung: Logs verschlüsseln (at-rest)
- Alerting: Bei kritischen Events (PERMISSION_DENIED, etc.)

---

## 🚀 Production Deployment

### Systemd Service

`/etc/systemd/system/ava-grpc.service`:
```ini
[Unit]
Description=AVA gRPC Secure Server
After=network.target

[Service]
Type=simple
User=ava
Group=ava
WorkingDirectory=/opt/ava
Environment="AVA_CERT_DIR=/etc/ava/certs"
Environment="AVA_GRPC_BIND=127.0.0.1"
Environment="AVA_GRPC_PORT=50051"
EnvironmentFile=/etc/ava/grpc.env
ExecStart=/opt/ava/venv/bin/python -m ava.api.grpc_server
Restart=on-failure
RestartSec=10

# Security Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/ava
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictNamespaces=true

[Install]
WantedBy=multi-user.target
```

### Docker Deployment

**Dockerfile.grpc**:
```dockerfile
FROM python:3.11-slim

# Non-Root-User
RUN useradd -m -s /bin/bash ava

WORKDIR /app
COPY . .
RUN pip install .

# Certs (aus Secret-Mount)
VOLUME /certs

USER ava
EXPOSE 50051

CMD ["python", "-m", "ava.api.grpc_server"]
```

**docker-compose.yml**:
```yaml
services:
  ava-grpc:
    build:
      context: .
      dockerfile: Dockerfile.grpc
    ports:
      - "127.0.0.1:50051:50051"  # Nur localhost!
    volumes:
      - ./certs:/certs:ro
      - ./logs:/var/log/ava
    environment:
      - AVA_CERT_DIR=/certs
      - AVA_GRPC_TOKEN=${AVA_GRPC_TOKEN}
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ava-grpc
spec:
  replicas: 3
  selector:
    matchLabels:
      app: ava-grpc
  template:
    metadata:
      labels:
        app: ava-grpc
    spec:
      containers:
      - name: ava-grpc
        image: ava-grpc:latest
        ports:
        - containerPort: 50051
        env:
        - name: AVA_CERT_DIR
          value: /certs
        volumeMounts:
        - name: certs
          mountPath: /certs
          readOnly: true
        securityContext:
          runAsNonRoot: true
          runAsUser: 1000
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
        resources:
          limits:
            memory: "512Mi"
            cpu: "500m"
          requests:
            memory: "256Mi"
            cpu: "250m"
      volumes:
      - name: certs
        secret:
          secretName: ava-grpc-tls
---
apiVersion: v1
kind: Service
metadata:
  name: ava-grpc
spec:
  type: ClusterIP  # Nicht external!
  selector:
    app: ava-grpc
  ports:
  - port: 50051
    targetPort: 50051
```

### Monitoring

**Prometheus Metrics** (zu implementieren):
```python
from prometheus_client import Counter, Histogram

grpc_requests_total = Counter(
    "ava_grpc_requests_total",
    "Total gRPC requests",
    ["method", "status"]
)

grpc_request_duration = Histogram(
    "ava_grpc_request_duration_seconds",
    "gRPC request duration",
    ["method"]
)
```

**Health-Check**:
```bash
grpc_health_probe -addr=localhost:50051
```

---

## ✅ Sicherheits-Checkliste

### Pre-Production

- [ ] **TLS/mTLS aktiv** mit echten Zertifikaten
- [ ] **Nicht auf `0.0.0.0` binden** (nur internes Interface)
- [ ] **Firewall konfiguriert** (nur benötigte Quell-IPs)
- [ ] **API-Keys generiert** und sicher gespeichert (Vault)
- [ ] **Rate-Limits getestet** (Load-Testing)
- [ ] **Audit-Logging aktiviert** und an SIEM weitergeleitet
- [ ] **Secret-Rotation etabliert** (Certs, Tokens, Keys)
- [ ] **Non-Root-User** (systemd, Docker, K8s)
- [ ] **Resource-Limits gesetzt** (Memory, CPU, Connections)
- [ ] **Monitoring & Alerting** konfiguriert
- [ ] **Backup & Recovery** getestet
- [ ] **Incident-Response-Plan** dokumentiert

### Runtime

- [ ] **Zertifikate überwachen** (Ablaufdatum)
- [ ] **Logs regelmäßig prüfen** (Anomalien)
- [ ] **Metrics tracken** (Latenz, Error-Rate)
- [ ] **Dependency-Updates** (CVE-Scanning)
- [ ] **Pen-Testing** (jährlich)
- [ ] **Security-Patches** zeitnah einspielen

---

## 🐛 Bekannte Schwachstellen & Mitigationen

### 1. **Unsichere InsecureServerCredentials**

**Problem**: Fallback auf Insecure-Mode, wenn Certs fehlen

**Mitigation**:
```python
# In Production: Niemals Insecure zulassen
if not credentials:
    raise RuntimeError("TLS certificates required in production!")
```

### 2. **0.0.0.0-Binding**

**Problem**: Server auf allen Interfaces erreichbar

**Mitigation**:
```bash
export AVA_GRPC_BIND="127.0.0.1"  # Oder spezifisches Interface
```

### 3. **Fehlende Reflection-Kontrolle**

**Problem**: gRPC-Reflection erlaubt Methoden-Enumeration

**Mitigation**:
```python
# Nur in Dev aktivieren
if os.getenv("AVA_ENV") == "development":
    from grpc_reflection.v1alpha import reflection
    reflection.enable_server_reflection(SERVICE_NAMES, server)
```

### 4. **Statische Secrets im Code**

**Problem**: Secrets hartkodiert

**Mitigation**:
```bash
# Aus Vault/Env laden
export AVA_GRPC_TOKEN=$(vault kv get -field=token secret/ava/grpc)
```

### 5. **Keine Input-Validierung**

**Problem**: Proto-Messages können bösartig sein

**Mitigation**:
```python
def CreateTask(self, request, context):
    # Validierung
    if len(request.title) > 500:
        context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Title too long")
    if not request.title.strip():
        context.abort(grpc.StatusCode.INVALID_ARGUMENT, "Title required")
    # ...
```

### 6. **DoS via Large Messages**

**Problem**: Sehr große Messages können Speicher erschöpfen

**Mitigation**: Bereits implementiert via `MAX_MESSAGE_SIZE = 4 MiB`

### 7. **Connection Exhaustion**

**Problem**: Zu viele offene Verbindungen

**Mitigation**: Bereits implementiert via Keepalive & Max-Age

---

## 📚 Weiterführende Ressourcen

- [gRPC Security Guide](https://grpc.io/docs/guides/security/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)

---

## 📞 Support

Bei Sicherheitsproblemen:
- **Intern**: DevSecOps-Team
- **Extern**: security@ava-system.local (PGP-Key verfügbar)

**Responsible Disclosure**: 90-Tage-Frist für kritische Schwachstellen
