# AVA Adaptive Security Platform - Deployment Guide

## 🚀 Übersicht

Vollständige Production-Ready Deployment-Optionen für AVA Adaptive Security Platform v4.0

**Deployment-Methoden:**
- ✅ Docker Compose (Lokale Entwicklung/Testing)
- ✅ Kubernetes (Cloud/Enterprise Production)
- ✅ Standalone (Einzelserver)

---

## 📋 Voraussetzungen

### Alle Deployments
- Python 3.8+
- 4GB+ RAM
- 10GB+ freier Speicher

### Docker Compose
- Docker 20.10+
- Docker Compose 1.29+

### Kubernetes
- Kubernetes 1.21+
- kubectl installiert
- Helm 3.0+ (optional)
- Persistent Storage (10GB+)

---

## 🐳 Docker Compose Deployment

### Quick Start

```bash
# 1. Repository klonen
git clone <repository-url>
cd AVA

# 2. Production Build & Start
cd deployment/docker
docker-compose -f docker-compose.adaptive.yml up -d

# 3. Status prüfen
docker-compose -f docker-compose.adaptive.yml ps

# 4. Logs anzeigen
docker-compose -f docker-compose.adaptive.yml logs -f orchestrator
```

### Services

Nach dem Start sind folgende Services verfügbar:

| Service | URL | Beschreibung |
|---------|-----|--------------|
| **Orchestrator** | http://localhost:9090 | AVA Hauptsystem |
| **Prometheus** | http://localhost:9091 | Metrics Collection |
| **Grafana** | http://localhost:3000 | Dashboards (admin/ava_security_admin) |

### Useful Commands

```bash
# Alle Container stoppen
docker-compose -f docker-compose.adaptive.yml down

# Container neu starten
docker-compose -f docker-compose.adaptive.yml restart orchestrator

# Volumes löschen (Reset)
docker-compose -f docker-compose.adaptive.yml down -v

# Einzelnen Container logs
docker logs ava-orchestrator -f

# Shell in Container
docker exec -it ava-orchestrator bash

# Metrics prüfen
curl http://localhost:9090/metrics

# Health Check
curl http://localhost:9090/health
```

---

## ☸️ Kubernetes Deployment

### Quick Start

```bash
# 1. Namespace erstellen
kubectl apply -f deployment/k8s/adaptive-security-deployment.yaml

# 2. Status prüfen
kubectl get all -n ava-security

# 3. Logs anzeigen
kubectl logs -n ava-security -l component=orchestrator -f

# 4. Port-Forward für lokalen Zugriff
kubectl port-forward -n ava-security service/ava-orchestrator 9090:9090
```

### Production Deployment

```bash
# 1. Secrets erstellen (optional, für externe Threat Intelligence)
kubectl create secret generic ava-api-keys \
  --from-literal=threat-intel-api-key=YOUR_KEY \
  -n ava-security

# 2. ConfigMap anpassen (optional)
kubectl edit configmap ava-security-config -n ava-security

# 3. Deployment skalieren
kubectl scale deployment ava-adaptive-orchestrator \
  --replicas=3 -n ava-security

# 4. Rolling Update
kubectl set image deployment/ava-adaptive-orchestrator \
  orchestrator=ava-security/adaptive-orchestrator:4.1 \
  -n ava-security

kubectl rollout status deployment/ava-adaptive-orchestrator -n ava-security
```

### Monitoring Integration

**Prometheus Operator:**

```bash
# ServiceMonitor wird automatisch erkannt
kubectl get servicemonitor -n ava-security

# Prüfen ob Targets in Prometheus erscheinen
kubectl port-forward -n monitoring service/prometheus 9090:9090
# Dann öffnen: http://localhost:9090/targets
```

**Grafana Dashboard:**

```bash
# Dashboard importieren (wenn nicht automatisch)
kubectl port-forward -n monitoring service/grafana 3000:3000

# In Grafana UI:
# 1. + -> Import
# 2. Upload deployment/grafana/ava-adaptive-security-dashboard.json
# 3. Prometheus Datasource auswählen
```

### Useful Commands

```bash
# Alle Pods anzeigen
kubectl get pods -n ava-security

# Pod beschreiben
kubectl describe pod <pod-name> -n ava-security

# Container Logs
kubectl logs -n ava-security <pod-name> -c orchestrator

# Pod Shell
kubectl exec -it -n ava-security <pod-name> -- /bin/bash

# Events anzeigen
kubectl get events -n ava-security --sort-by=.metadata.creationTimestamp

# Resources prüfen
kubectl top pods -n ava-security

# Deployment löschen
kubectl delete namespace ava-security
```

---

## 💻 Standalone Deployment

### Installation

```bash
# 1. Dependencies installieren
pip install -r requirements.txt
pip install prometheus-client aiohttp

# 2. AVA installieren
pip install -e .

# 3. Konfiguration (optional)
export AVA_HOME=~/.ava
export LOG_LEVEL=INFO
export METRICS_PORT=9090
```

### Starten

**Interaktiv (Dashboard):**
```bash
python launch_adaptive_security.py dashboard
```

**Background (Monitor):**
```bash
# Screen/Tmux Session
screen -S ava-security
python launch_adaptive_security.py monitor

# Oder als systemd Service (siehe unten)
```

**Metrics Server:**
```bash
# Separates Terminal
python ava/security/metrics_server.py
```

### Systemd Service

Erstelle `/etc/systemd/system/ava-security.service`:

```ini
[Unit]
Description=AVA Adaptive Security Platform
After=network.target

[Service]
Type=simple
User=ava
Group=ava
WorkingDirectory=/opt/ava
Environment="AVA_HOME=/var/lib/ava"
Environment="LOG_LEVEL=INFO"
ExecStart=/usr/bin/python3 /opt/ava/launch_adaptive_security.py monitor
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Aktivieren:
```bash
sudo systemctl daemon-reload
sudo systemctl enable ava-security
sudo systemctl start ava-security
sudo systemctl status ava-security
```

---

## 🔍 Monitoring & Observability

### Prometheus Queries

**Global Security Score:**
```promql
ava_security_global_score
```

**Network Threat Rate:**
```promql
rate(ava_security_network_threats_total[5m])
```

**Cookie Threats by Type:**
```promql
sum by (threat_type) (ava_security_cookie_threats_total)
```

**Mesh Node Health:**
```promql
ava_security_mesh_nodes{state="active"}
```

### Grafana Dashboard

Import: `deployment/grafana/ava-adaptive-security-dashboard.json`

**Features:**
- 20+ Visualisierungen
- Global Security Score (Echtzeit)
- Network Scan Analytics
- Cookie Threat Detection
- Mesh Node Status
- Self-Learning Activity
- Threat Type Distribution

### Alerting Rules

Erstelle `prometheus-alerts.yml`:

```yaml
groups:
  - name: ava_security
    interval: 30s
    rules:
      # Low Security Score
      - alert: LowSecurityScore
        expr: ava_security_global_score < 50
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Security score critically low"
          description: "Global security score is {{ $value }}/100"

      # High Threat Rate
      - alert: HighThreatRate
        expr: rate(ava_security_network_threats_total[5m]) > 10
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High threat detection rate"
          description: "{{ $value }} threats/second detected"

      # Mesh Node Down
      - alert: MeshNodeDown
        expr: ava_security_mesh_nodes{state="active"} < 1
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "No active mesh nodes"
          description: "Security mesh coordination unavailable"
```

---

## 🔐 Security Considerations

### Production Checklist

- [ ] **Secrets Management**: Verwende Kubernetes Secrets, nicht Environment Variables
- [ ] **RBAC**: Minimale Berechtigungen für ServiceAccount
- [ ] **Network Policies**: Restrict ingress/egress traffic
- [ ] **Resource Limits**: Set memory/CPU limits
- [ ] **Non-root User**: Container läuft als User 1000
- [ ] **Read-only Root**: Set `readOnlyRootFilesystem: true`
- [ ] **TLS**: Enable TLS für Metrics/Mesh Kommunikation
- [ ] **Backup**: Regular backups der Pattern-Daten
- [ ] **Monitoring**: Prometheus + Alertmanager konfiguriert
- [ ] **Logs**: Zentrale Log-Aggregation (ELK/Loki)

### Hardening

**Kubernetes:**
```yaml
# Pod Security Context
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  fsGroup: 1000
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL
```

**Docker:**
```bash
# Run with limited capabilities
docker run --cap-drop=ALL --cap-add=NET_ADMIN \
  --read-only --tmpfs /tmp \
  ava-security/adaptive-orchestrator:4.0
```

---

## 📊 Performance Tuning

### Resource Recommendations

**Orchestrator:**
- Dev: 512MB RAM, 0.25 CPU
- Prod: 2GB RAM, 1 CPU
- Enterprise: 4GB RAM, 2 CPU

**Network IDS:**
- Dev: 256MB RAM, 0.1 CPU
- Prod: 1GB RAM, 0.5 CPU
- High Traffic: 2GB RAM, 1 CPU

### Scaling

**Horizontal:**
```bash
# Mehr IDS Nodes (DaemonSet deployed auf alle Nodes)
kubectl label node <node-name> ava-security=enabled

# Oder separate Deployment skalieren
kubectl scale deployment ava-network-ids --replicas=5
```

**Vertical:**
```bash
# Resources anpassen
kubectl set resources deployment ava-adaptive-orchestrator \
  --requests=cpu=500m,memory=1Gi \
  --limits=cpu=2,memory=4Gi
```

### Storage Optimization

```bash
# Pattern Daten komprimieren (periodicaly)
cd $AVA_HOME
tar -czf patterns-backup-$(date +%Y%m%d).tar.gz *.pkl

# Alte Patterns löschen (nach 90 Tagen)
find $AVA_HOME -name "*.pkl" -mtime +90 -delete
```

---

## 🔧 Troubleshooting

### Container startet nicht

```bash
# Logs prüfen
docker logs ava-orchestrator

# Häufige Probleme:
# 1. Port bereits belegt
sudo lsof -i :9090

# 2. Volume Permissions
docker exec ava-orchestrator ls -la /data/ava
sudo chown -R 1000:1000 /path/to/ava-patterns

# 3. Dependencies fehlen
docker exec ava-orchestrator pip list | grep prometheus
```

### Kubernetes Pod CrashLoopBackOff

```bash
# Pod Events
kubectl describe pod <pod-name> -n ava-security

# Logs vom letzten Crash
kubectl logs <pod-name> -n ava-security --previous

# Häufige Probleme:
# 1. PVC nicht gebunden
kubectl get pvc -n ava-security

# 2. ConfigMap fehlt
kubectl get configmap -n ava-security

# 3. Image Pull Error
kubectl get events -n ava-security | grep Failed
```

### Metrics nicht verfügbar

```bash
# Health Check
curl http://localhost:9090/health

# Metrics Endpoint
curl http://localhost:9090/metrics | head -20

# Prometheus Targets
# Öffne http://localhost:9091/targets
# (bei Docker Compose)

# Kubernetes
kubectl port-forward -n ava-security service/ava-orchestrator 9090:9090
curl http://localhost:9090/metrics
```

### Hohe Memory Usage

```bash
# Memory Profiling
docker stats ava-orchestrator

# Pattern Cache leeren
docker exec ava-orchestrator python -c "
from ava.security.adaptive_ids import get_adaptive_ids
ids = get_adaptive_ids()
print(f'Fingerprints: {len(ids.fingerprints)}')
# ids.fingerprints.clear()  # Wenn zu viele
"

# Limits anpassen
docker update --memory 2g ava-orchestrator
```

---

## 🔄 Updates & Rollback

### Docker Compose

```bash
# Pull neues Image
docker-compose -f docker-compose.adaptive.yml pull

# Recreate Container
docker-compose -f docker-compose.adaptive.yml up -d

# Rollback (mit backup)
docker tag ava-security/adaptive-orchestrator:4.0 ava-security/adaptive-orchestrator:4.0-backup
docker-compose -f docker-compose.adaptive.yml down
docker-compose -f docker-compose.adaptive.yml up -d
```

### Kubernetes

```bash
# Rolling Update
kubectl set image deployment/ava-adaptive-orchestrator \
  orchestrator=ava-security/adaptive-orchestrator:4.1 \
  -n ava-security

# Status verfolgen
kubectl rollout status deployment/ava-adaptive-orchestrator -n ava-security

# Rollback
kubectl rollout undo deployment/ava-adaptive-orchestrator -n ava-security

# Zu spezifischer Revision
kubectl rollout history deployment/ava-adaptive-orchestrator -n ava-security
kubectl rollout undo deployment/ava-adaptive-orchestrator --to-revision=2 -n ava-security
```

---

## 📚 Weitere Ressourcen

- **Documentation**: [ADAPTIVE_SECURITY.md](../../ADAPTIVE_SECURITY.md)
- **API Reference**: [docs/api.md](../../docs/api.md)
- **Architecture**: [docs/ARCHITECTURE.md](../../docs/ARCHITECTURE.md)
- **Development**: [docs/DEVELOPMENT.md](../../docs/DEVELOPMENT.md)

---

## 🆘 Support

Bei Problemen:
1. Logs prüfen (siehe Troubleshooting)
2. GitHub Issues: <repository-url>/issues
3. Dokumentation: `docs/` Verzeichnis
