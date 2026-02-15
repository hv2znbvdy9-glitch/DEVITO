# AVA gRPC Kubernetes Deployment

Production-ready Kubernetes-Manifeste für den AVA gRPC Server.

## 📋 Inhalt

- **deployment.yaml**: Hauptdeployment mit allen Komponenten
- **cert-manager.yaml**: Automatische TLS-Zertifikatsverwaltung
- **vault-integration.yaml**: HashiCorp Vault Secret-Injection
- **istio-config.yaml**: Istio Service-Mesh-Konfiguration

## 🚀 Quick Start

### 1. Namespace erstellen

```bash
kubectl apply -f deployment.yaml
```

### 2. Secrets erstellen

#### Option A: Manuell (für Testing)

```bash
# TLS-Zertifikate
kubectl create secret tls ava-grpc-tls \
  --cert=./certs/server.crt \
  --key=./certs/server.key \
  -n ava-system

# CA-Zertifikat hinzufügen
kubectl create secret generic ava-grpc-ca \
  --from-file=ca.crt=./certs/ca.crt \
  -n ava-system

# API-Secrets
kubectl create secret generic ava-grpc-secrets \
  --from-literal=api-key="$(openssl rand -hex 32)" \
  --from-literal=jwt-secret="$(openssl rand -base64 48)" \
  -n ava-system
```

#### Option B: Mit Cert-Manager (empfohlen)

```bash
kubectl apply -f cert-manager.yaml
```

#### Option C: Mit Vault (Production)

```bash
kubectl apply -f vault-integration.yaml
```

### 3. Deployment starten

```bash
kubectl apply -f deployment.yaml
```

### 4. Status prüfen

```bash
# Pods
kubectl get pods -n ava-system

# Services
kubectl get svc -n ava-system

# Logs
kubectl logs -n ava-system -l app=ava-grpc -f

# Health-Check
kubectl exec -n ava-system -it deployment/ava-grpc -- \
  grpc_health_probe -addr=localhost:50051
```

## 🔒 Sicherheitsfeatures

### Pod Security

- **Non-Root**: Alle Container laufen als User 1000
- **Read-Only Filesystem**: Root-FS ist read-only
- **No Privileges**: Keine elevated Capabilities
- **Seccomp**: Runtime-Default-Profil
- **Drop ALL Capabilities**: Nur minimum benötigt

### Network Policies

- **Strict Ingress**: Nur von definierten Namespaces/Pods
- **Egress-Control**: Nur zu DNS, Vault, notwendigen Services
- **Service-Mesh-Ready**: Istio/Linkerd kompatibel

### Resource Limits

```yaml
resources:
  limits:
    memory: "1Gi"
    cpu: "1000m"
  requests:
    memory: "512Mi"
    cpu: "250m"
```

## 📊 Monitoring

### Prometheus Integration

Service-Annotations für Auto-Discovery:

```yaml
annotations:
  prometheus.io/scrape: "true"
  prometheus.io/port: "9090"
  prometheus.io/path: "/metrics"
```

### Metrics-Endpoint

```bash
# Port-Forward
kubectl port-forward -n ava-system svc/ava-grpc-metrics 9090:9090

# Metrics abrufen
curl http://localhost:9090/metrics
```

### Grafana-Dashboard

```bash
kubectl apply -f ../grafana/ava-grpc-dashboard.yaml
```

## 🔄 High Availability

### Replicas

- **Minimum**: 3 Replicas
- **Auto-Scaling**: 3-10 Replicas (CPU/Memory-basiert)
- **Pod Disruption Budget**: Min. 2 verfügbar

### Anti-Affinity

Pods werden auf verschiedene Nodes verteilt:

```yaml
affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
    - weight: 100
      podAffinityTerm:
        topologyKey: kubernetes.io/hostname
```

### Health-Checks

- **Liveness**: gRPC Health-Check (alle 10s)
- **Readiness**: gRPC Health-Check (alle 5s)
- **Startup**: 30 Versuche (alle 5s)

## 🔐 TLS/mTLS

### Mit Cert-Manager

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: ava-grpc-tls
spec:
  secretName: ava-grpc-tls
  issuerRef:
    name: letsencrypt-prod
    kind: ClusterIssuer
  dnsNames:
  - grpc.ava-system.svc.cluster.local
```

### Mit Istio (mTLS)

```bash
kubectl apply -f istio-config.yaml
```

Istio übernimmt automatisch:
- TLS-Termination
- mTLS zwischen Services
- Traffic-Management
- Observability

## 🌐 Ingress / LoadBalancer

### Intern (ClusterIP)

Standard: Service ist nur cluster-intern erreichbar.

### Extern (LoadBalancer)

```yaml
apiVersion: v1
kind: Service
metadata:
  name: ava-grpc-external
  namespace: ava-system
spec:
  type: LoadBalancer
  loadBalancerSourceRanges:
  - 10.0.0.0/8      # Nur interne IPs
  - 203.0.113.0/24  # Spezifische externe IPs
  selector:
    app: ava-grpc
  ports:
  - name: grpc
    port: 50051
    targetPort: grpc
```

### Mit Istio Gateway

```yaml
apiVersion: networking.istio.io/v1beta1
kind: Gateway
metadata:
  name: ava-grpc-gateway
spec:
  selector:
    istio: ingressgateway
  servers:
  - port:
      number: 50051
      name: grpc
      protocol: GRPC
    hosts:
    - grpc.ava-system.com
    tls:
      mode: SIMPLE
      credentialName: ava-grpc-tls
```

## 🔄 Rolling Updates

### Zero-Downtime-Deployment

```bash
# Image aktualisieren
kubectl set image deployment/ava-grpc \
  ava-grpc=ghcr.io/ava-system/ava-grpc:2.1.0 \
  -n ava-system

# Rollout-Status
kubectl rollout status deployment/ava-grpc -n ava-system

# Rollback (falls nötig)
kubectl rollout undo deployment/ava-grpc -n ava-system
```

### Strategy

```yaml
strategy:
  type: RollingUpdate
  rollingUpdate:
    maxSurge: 1
    maxUnavailable: 0  # Keine Downtime!
```

## 📦 CI/CD Integration

### GitHub Actions

```yaml
- name: Deploy to Kubernetes
  run: |
    kubectl apply -f deployment/kubernetes/deployment.yaml
    kubectl rollout status deployment/ava-grpc -n ava-system
```

### ArgoCD

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: ava-grpc
spec:
  source:
    repoURL: https://github.com/ava-system/ava
    targetRevision: main
    path: deployment/kubernetes
  destination:
    server: https://kubernetes.default.svc
    namespace: ava-system
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
```

## 🛠️ Troubleshooting

### Pods starten nicht

```bash
# Events prüfen
kubectl describe pod -n ava-system -l app=ava-grpc

# Logs
kubectl logs -n ava-system -l app=ava-grpc --previous
```

### Network-Probleme

```bash
# Von anderem Pod testen
kubectl run -it --rm debug --image=nicolaka/netshoot --restart=Never -- \
  grpcurl -plaintext ava-grpc.ava-system:50051 list
```

### TLS-Fehler

```bash
# Zertifikat prüfen
kubectl get secret ava-grpc-tls -n ava-system -o yaml

# Cert-Manager-Events
kubectl describe certificate ava-grpc-tls -n ava-system
```

### Resource-Limits

```bash
# Resource-Nutzung
kubectl top pods -n ava-system

# HPA-Status
kubectl get hpa -n ava-system
```

## 🧹 Cleanup

```bash
# Deployment löschen
kubectl delete -f deployment.yaml

# Namespace löschen (inkl. aller Ressourcen)
kubectl delete namespace ava-system
```

## 📚 Weitere Ressourcen

- [Kubernetes Best Practices](https://kubernetes.io/docs/concepts/configuration/overview/)
- [gRPC Health-Checking](https://github.com/grpc/grpc/blob/master/doc/health-checking.md)
- [Cert-Manager Docs](https://cert-manager.io/docs/)
- [Istio Docs](https://istio.io/latest/docs/)



# ===============================

# 1. ADMIN & SICHERHEITSCHECK

# ===============================

If (-not ([Security.Principal.WindowsPrincipal]

    [Security.Principal.WindowsIdentity]::GetCurrent()

).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))

{

    Write-Host "❌ PowerShell MUSS als Administrator gestartet werden!" -ForegroundColor Red

    Pause

    Exit

}



Clear-Host

Write-Host "===================================================" -ForegroundColor Cyan

Write-Host " PROFESSIONAL ETHICAL / BLUE TEAM LAB" -ForegroundColor Green

Write-Host " Detection • Analyse • Defense • Monitoring" -ForegroundColor Yellow

Write-Host "===================================================" -ForegroundColor Cyan



# ===============================

# 2. SYSTEM PROFILING (ENUMERATION)

# ===============================

function System-Profiling {

    Write-Host "`n[ SYSTEM PROFILING ]" -ForegroundColor Cyan



    Write-Host "`nOS & Hardware:" -ForegroundColor Yellow

    Get-ComputerInfo | 

        Select OsName, OsVersion, WindowsBuildLabEx, CsProcessors, CsTotalPhysicalMemory



    Write-Host "`nInstallierte Updates:" -ForegroundColor Yellow

    Get-HotFix | Select HotFixID, InstalledOn

}



# ===============================

# 3. BENUTZER, RECHTE, ANGRIFFSFLÄCHEN

# ===============================

function Identity-Analysis {

    Write-Host "`n[ IDENTITY & PRIVILEGES ]" -ForegroundColor Cyan



    Write-Host "`nLokale Benutzer:" -ForegroundColor Yellow

    Get-LocalUser | Select Name, Enabled, LastLogon



    Write-Host "`nAdministratoren:" -ForegroundColor Yellow

    Get-LocalGroupMember Administrators



    Write-Host "`nAktive Sessions:" -ForegroundColor Yellow

    quser

}



# ===============================

# 4. NETZWERK & BEHAVIOR ANALYSIS

# ===============================

function Network-Behavior {

    Write-Host "`n[ NETWORK & BEHAVIOR ANALYSIS ]" -ForegroundColor Cyan



    Write-Host "`nIP & Adapter:" -ForegroundColor Yellow

    Get-NetIPAddress | Where-Object {$_.AddressFamily -eq "IPv4"}



    Write-Host "`nOffene Verbindungen:" -ForegroundColor Yellow

    Get-NetTCPConnection |

        Select State, LocalAddress, LocalPort, RemoteAddress, RemotePort



    Write-Host "`nListening Services:" -ForegroundColor Yellow

    netstat -ano | Select-String "LISTEN"

}



# ===============================

# 5. PROZESS & THREAT ANALYSE

# ===============================

function Process-Threat-Analysis {

    Write-Host "`n[ PROCESS & THREAT ANALYSIS ]" -ForegroundColor Cyan



    Write-Host "`nTop Prozesse nach CPU:" -ForegroundColor Yellow

    Get-Process | Sort CPU -Descending | Select -First 10 Name, Id, CPU



    Write-Host "`nUnsignierte Prozesse:" -ForegroundColor Yellow

    Get-Process | Where-Object {$_.Path -and !(Get-AuthenticodeSignature $_.Path).Status -eq "Valid"} |

        Select Name, Path

}



# ===============================

# 6. DEFENDER, FIREWALL, HARDENING

# ===============================

function Security-Controls {

    Write-Host "`n[ SECURITY CONTROLS & HARDENING ]" -ForegroundColor Cyan



    Write-Host "`nWindows Defender Status:" -ForegroundColor Yellow

    Get-MpComputerStatus |

        Select AntivirusEnabled, RealTimeProtectionEnabled, TamperProtection



    Write-Host "`nFirewall Status:" -ForegroundColor Yellow

    Get-NetFirewallProfile |

        Select Name, Enabled, DefaultInboundAction



    Write-Host "`nSMB Hardening Check:" -ForegroundColor Yellow

    Get-SmbServerConfiguration | Select EnableSMB1Protocol

}



# ===============================

# 7. LOGGING & DETECTION (SIEM-BASIS)

# ===============================

function Log-Detection {

    Write-Host "`n[ LOGGING & DETECTION ]" -ForegroundColor Cyan



    Write-Host "`nLetzte Security Events:" -ForegroundColor Yellow

    Get-EventLog Security -Newest 25 |

        Select TimeGenerated, EventID, EntryType, Message



    Write-Host "`nPowerShell Logging Status:" -ForegroundColor Yellow

    Get-ItemProperty `

        HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging `

        -ErrorAction SilentlyContinue

}



# ===============================

# 8. LAB & TOOL STRUKTUR

# ===============================

function Lab-Setup {

    Write-Host "`n[ LAB & TOOL SETUP ]" -ForegroundColor Cyan



    $LabPath = "$env:USERPROFILE\BlueTeamLab"

    New-Item -ItemType Directory -Path $LabPath -Force | Out-Null

    Set-Location $LabPath



    Write-Host "Lab-Verzeichnis erstellt: $LabPath" -ForegroundColor Green



    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {

        Write-Host "Installiere Git..." -ForegroundColor Yellow

        winget install --id Git.Git -e

    }



    if (-not (Get-Command python -ErrorAction SilentlyContinue)) {

        Write-Host "Installiere Python..." -ForegroundColor Yellow

        winget install --id Python.Python.3 -e

    }



    Write-Host "Lab-Umgebung bereit." -ForegroundColor Green

}



# ===============================

# 9. HAUPTMENÜ (SOC-STYLE)

# ===============================

function Menu {

    Write-Host ""

    Write-Host "1  System Profiling"

    Write-Host "2  Identity & Privileges"

    Write-Host "3  Network Behavior"

    Write-Host "4  Process Threat Analysis"

    Write-Host "5  Security Controls & Hardening"

    Write-Host "6  Logs & Detection"

    Write-Host "7  Lab Setup"

    Write-Host "0  Beenden"

}



do {

    Menu

    $choice = Read-Host "Auswahl"



    switch ($choice) {

        1 { System-Profiling }

        2 { Identity-Analysis }

        3 { Network-Behavior }

        4 { Process-Threat-Analysis }

        5 { Security-Controls }

        6 { Log-Detection }

        7 { Lab-Setup }

        0 { Write-Host "Lab beendet." -ForegroundColor Green }

        default { Write-Host "Ungültige Auswahl" -ForegroundColor Red }

    }



    Pause

    Clear-Host



} while ($choice -ne 0)



Write-Host "Bleib ethisch. Denk wie ein Angreifer – handle wie ein Verteidiger." -ForegroundColor Cyan



•••••••••••••••••••••••••••••••••••••••

