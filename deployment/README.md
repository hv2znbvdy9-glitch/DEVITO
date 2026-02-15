# AVA Production Deployment Guide

Vollständiger Leitfaden für Production-Deployments des AVA gRPC Servers.

## 📋 Übersicht

Dieses Verzeichnis enthält alle Konfigurationen und Skripte für Production-Deployments:

```
deployment/
├── systemd/          # Systemd-Service für dedizierte Server
├── kubernetes/       # Kubernetes-Manifeste für Container-Orchestrierung
├── grafana/          # Grafana-Dashboards
├── docker/           # Docker/Docker-Compose (in Vorbereitung)
└── README.md         # Dieser Leitfaden
```

## 🚀 Deployment-Optionen

### Option 1: Systemd (Dedizierte Server)

**Geeignet für:**
- Dedizierte Linux-Server
- VMs (AWS EC2, Azure VM, GCP Compute)
- On-Premise-Setups

**Vorteile:**
- Einfaches Setup
- Direkte System-Integration
- Geringer Overhead

**Installation:**

```bash
cd deployment/systemd
sudo ./install.sh
```

[Vollständige Dokumentation →](systemd/README.md)

### Option 2: Kubernetes

**Geeignet für:**
- Cloud-Native-Deployments
- Multi-Node-Cluster
- High-Availability-Anforderungen
- Auto-Scaling

**Vorteile:**
- Hohe Verfügbarkeit
- Auto-Scaling
- Service-Mesh-Integration
- Rolling-Updates ohne Downtime

**Installation:**

```bash
cd deployment/kubernetes
kubectl apply -f deployment.yaml
```

[Vollständige Dokumentation →](kubernetes/README.md)

### Option 3: Docker/Docker Compose

**Geeignet für:**
- Entwicklung/Testing
- Kleine Deployments
- Einfache Container-Setups

**Installation:**

```bash
cd deployment/docker
docker-compose up -d
```

*(In Vorbereitung)*

## 🔐 Security Checklist

Vor dem Production-Deployment:

### TLS/mTLS ✅

- [ ] **Let's Encrypt-Zertifikate** generiert
  ```bash
  sudo scripts/setup_letsencrypt.sh --standalone
  ```

- [ ] **Oder**: PKI-Zertifikate von interner CA
- [ ] **Oder**: Cloud-CA-Zertifikate (AWS ACM, Azure Key Vault, GCP CA)
- [ ] **Auto-Renewal konfiguriert**

### Secrets Management ✅

- [ ] **HashiCorp Vault** eingerichtet
  ```bash
  sudo scripts/setup_vault_integration.sh
  ```

- [ ] **Secrets in Vault gespeichert** (nicht in Env-Vars!)
- [ ] **AppRole-Authentifizierung konfiguriert**
- [ ] **Secrets-Rotation etabliert**

### Firewall ✅

- [ ] **Firewall-Regeln aktiviert**
  ```bash
  # iptables
  sudo scripts/setup_firewall.sh setup
  
  # Oder UFW
  sudo scripts/setup_ufw.sh setup
  ```

- [ ] **Nur benötigte IPs zugelassen**
- [ ] **Rate-Limiting aktiviert**
- [ ] **Port 50051 nicht öffentlich** (hinter VPN/Bastion)

### Monitoring ✅

- [ ] **Prometheus Scraping konfiguriert**
- [ ] **Grafana-Dashboard importiert**
  ```bash
  # Dashboard in Grafana importieren
  deployment/grafana/ava-grpc-dashboard.json
  ```

- [ ] **Alerts konfiguriert** (hohe Latenz, Error-Rate, Cert-Expiry)
- [ ] **Log-Aggregation aktiviert** (ELK, Loki, CloudWatch)

### Production Hardening ✅

- [ ] **Non-Root-User** (`ava:ava`)
- [ ] **Read-Only Filesystem** (wo möglich)
- [ ] **Resource-Limits gesetzt**
- [ ] **Systemd-Sandboxing aktiviert**
- [ ] **SELinux/AppArmor konfiguriert**

## 🔧 Konfiguration

### Umgebungsvariablen

#### Systemd: `/etc/ava/grpc.env`

```bash
AVA_GRPC_BIND=127.0.0.1
AVA_GRPC_PORT=50051
AVA_CERT_DIR=/etc/ava/certs
AVA_ENV=production
```

#### Kubernetes: ConfigMap & Secrets

Siehe [kubernetes/deployment.yaml](kubernetes/deployment.yaml)

### Vault-Integration

#### 1. Vault Setup

```bash
# Vault starten (falls dev-mode)
vault server -dev

# Oder exportieren
export VAULT_ADDR=https://vault.company.com
export VAULT_TOKEN=...
```

#### 2. Secrets erstellen

```bash
sudo scripts/setup_vault_integration.sh setup
```

#### 3. Server mit Vault starten

```bash
# Environment aus Vault laden
source /etc/ava/vault.env

# Server starten (lädt Secrets automatisch aus Vault)
systemctl start ava-grpc
```

## 📊 Monitoring

### Metrics-Endpoint

```bash
# Systemd
curl http://localhost:9090/metrics

# Kubernetes
kubectl port-forward -n ava-system svc/ava-grpc-metrics 9090:9090
curl http://localhost:9090/metrics
```

### Wichtige Metriken

| Metrik | Bedeutung | Alert bei |
|--------|-----------|-----------|
| `ava_grpc_requests_total` | Gesamt-Requests | - |
| `ava_grpc_request_duration_seconds` | Request-Latenz | p99 > 1s |
| `ava_grpc_errors_total` | Fehler | Rate > 1% |
| `ava_grpc_active_requests` | Aktive Requests | > 500 |
| `ava_grpc_auth_failures_total` | Auth-Fehler | Spike |
| `ava_grpc_rate_limit_hits_total` | Rate-Limits | Häufig |
| `ava_grpc_tls_cert_expiry_seconds` | Cert-Ablauf | < 7 Tage |

### Grafana-Dashboard

1. Grafana öffnen
2. **Import Dashboard**
3. JSON hochladen: `deployment/grafana/ava-grpc-dashboard.json`
4. Datasource auswählen: Prometheus

**Features:**
- **Request-Rate** (QPS)
- **Latency** (p50, p95, p99)
- **Error-Rate**
- **Success-Rate**
- **Active Connections**
- **Auth-Failures**
- **TLS-Cert-Expiry**

## 🔄 Updates & Rollbacks

### Systemd

```bash
# Code aktualisieren
cd /opt/ava
git pull
/opt/ava/venv/bin/pip install -e .

# Service neu starten
sudo systemctl restart ava-grpc

# Rollback (falls nötig)
cd /opt/ava
git checkout <previous-commit>
sudo systemctl restart ava-grpc
```

### Kubernetes

```bash
# Image aktualisieren
kubectl set image deployment/ava-grpc \
  ava-grpc=ghcr.io/ava-system/ava-grpc:2.1.0 \
  -n ava-system

# Status prüfen
kubectl rollout status deployment/ava-grpc -n ava-system

# Rollback
kubectl rollout undo deployment/ava-grpc -n ava-system
```

## 🧪 Testing

### Health-Check

```bash
# gRPC Health Probe (Systemd)
grpc_health_probe -addr=localhost:50051

# Kubernetes
kubectl exec -n ava-system -it deployment/ava-grpc -- \
  grpc_health_probe -addr=localhost:50051
```

### Load-Testing

```bash
# Mit ghz
ghz --insecure \
  --proto ava/api/proto/ava_service.proto \
  --call ava.v1.AVAService/HealthCheck \
  -d '{"service":"ava"}' \
  -n 10000 -c 100 \
  localhost:50051

# Mit locust
locust -f tests/load/grpc_loadtest.py --host=localhost:50051
```

## 🆘 Troubleshooting

### Service startet nicht

```bash
# Systemd
sudo journalctl -u ava-grpc -n 100 --no-pager

# Kubernetes
kubectl logs -n ava-system -l app=ava-grpc --tail=100
```

### TLS-Fehler

```bash
# Zertifikat prüfen
openssl x509 -in /etc/ava/certs/server.crt -text -noout

# Ablaufdatum
openssl x509 -in /etc/ava/certs/server.crt -noout -enddate
```

### Firewall-Probleme

```bash
# Regeln prüfen
sudo iptables -L AVA_GRPC -n -v

# Oder UFW
sudo ufw status verbose

# Blocked Connections in Logs
sudo grep "AVA_GRPC_BLOCKED" /var/log/kern.log
```

### Secrets nicht geladen

```bash
# Vault-Status
vault status

# Secret abrufen (manuell)
vault kv get secret/ava/grpc

# Logs prüfen
grep -i vault /var/log/ava/grpc.log
```

## 📚 Best Practices

### 1. High Availability

- **Minimum 3 Replicas** (Kubernetes)
- **Load-Balancing** mit gRPC-aware LB
- **Health-Checks** richtig konfigurieren
- **Graceful Shutdown** implementiert

### 2. Security

- **TLS/mTLS immer aktiv** (auch intern!)
- **Secrets in Vault**, nicht in Env/Code
- **Regular Security Audits**
- **Dependency-Scanning** (Renovate, Dependabot)

### 3. Monitoring

- **Structured Logging** (JSON-Format)
- **Metrics für alle Endpoints**
- **Distributed Tracing** (Jaeger/Tempo)
- **Alarms für kritische Metriken**

### 4. Backups

- **Config-Backups** regelmäßig
- **Vault-Snapshots**
- **Database-Backups** (falls zustandsbehaftet)

### 5. Disaster Recovery

- **DR-Plan dokumentiert**
- **Failover getestet**
- **RPO/RTO definiert**
- **Restore-Prozedur validiert**

## 🔗 Weiterführende Links

- [gRPC Production Best Practices](https://grpc.io/docs/guides/performance/)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [HashiCorp Vault Patterns](https://learn.hashicorp.com/vault)
- [Prometheus Best Practices](https://prometheus.io/docs/practices/)
- [Let's Encrypt Documentation](https://letsencrypt.org/docs/)

## 📞 Support

Bei Problemen:

1. **Logs prüfen** (siehe Troubleshooting)
2. **Health-Checks ausführen**
3. **Metrics analysieren**
4. **Issue erstellen** mit Logs/Metrics

**Security-Issues**: security@ava-system.local (responsible disclosure)
