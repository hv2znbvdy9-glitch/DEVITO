# AVA COMPLETE SECURITY FRAMEWORK - MASTER DOCUMENTATION

## 🎯 Übersicht

**AVA** bietet eine **vollständige, multi-layered Security-Architektur** für Enterprise-Umgebungen:

1. **Network Security** - gRPC mit TLS/mTLS (bereits implementiert)
2. **Application Security** - API-Keys, JWT, RBAC (bereits implementiert)
3. **Infrastructure Security** - Vault, Firewall, Monitoring (bereits implementiert)
4. **Endpoint Security** - Windows/Linux Monitoring (NEU)
5. **SOC Operations** - Detection, Hunting, IR (NEU)

---

## 📊 Architektur-Übersicht

```
┌─────────────────────────────────────────────────────────────┐
│                    AVA SECURITY LAYERS                       │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  Layer 1: NETWORK SECURITY                                   │
│  ├─ gRPC Server (TLS 1.3 + mTLS)                            │
│  ├─ Certificate Management (Let's Encrypt)                   │
│  └─ Firewall (iptables/UFW/NetworkPolicy)                   │
│                                                               │
│  Layer 2: APPLICATION SECURITY                               │
│  ├─ Authentication (API-Keys + JWT)                          │
│  ├─ Authorization (RBAC: Admin/User/Service/ReadOnly)       │
│  └─ Audit Logging (alle Requests)                           │
│                                                               │
│  Layer 3: INFRASTRUCTURE SECURITY                            │
│  ├─ HashiCorp Vault (Secret Management)                     │
│  ├─ Prometheus Metrics (16+ Metriken)                       │
│  ├─ Grafana Dashboards (Security Monitoring)                │
│  └─ Systemd Hardening (20+ Security-Direktiven)             │
│                                                               │
│  Layer 4: ENDPOINT SECURITY (NEU)                            │
│  ├─ Windows Security Framework (PowerShell)                  │
│  ├─ Python Security Monitor (Cross-Platform)                │
│  ├─ Process Monitoring & Blocking                           │
│  └─ Security REST API                                        │
│                                                               │
│  Layer 5: SOC OPERATIONS (NEU)                               │
│  ├─ Detection Engine (MITRE ATT&CK)                         │
│  ├─ Threat Hunting (Persistence, Unsigned Binaries)         │
│  ├─ Incident Response (automatische Evidence Collection)    │
│  └─ Vulnerability Assessment (Risk Scoring)                 │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Komponenten-Matrix

| Komponente | Platform | Sprache | Status | Dokumentation |
|------------|----------|---------|--------|---------------|
| **gRPC Server** | Linux/Windows | Python | ✅ | [GRPC_SECURITY.md](GRPC_SECURITY.md) |
| **Vault Integration** | Linux/Windows | Python | ✅ | [GRPC_SECURITY.md](GRPC_SECURITY.md) |
| **Prometheus Metrics** | Linux/Windows | Python | ✅ | [PRODUCTION_FEATURES.md](PRODUCTION_FEATURES.md) |
| **Firewall Setup** | Linux | Bash | ✅ | [scripts/setup_firewall.sh](../scripts/setup_firewall.sh) |
| **Kubernetes Deploy** | K8s | YAML | ✅ | [deployment/kubernetes/](../deployment/kubernetes/) |
| **Windows Security** | Windows | PowerShell | ✅ | [WINDOWS_SECURITY.md](WINDOWS_SECURITY.md) |
| **SOC Toolkit** | Windows | PowerShell | ✅ | [WINDOWS_SECURITY.md](WINDOWS_SECURITY.md) |
| **Python Monitor** | Linux/Windows | Python | ✅ | [ava/security/](../ava/security/) |
| **Security REST API** | Linux/Windows | Python | ✅ | [ava/api/security.py](../ava/api/security.py) |

---

## 🚀 Quick Start Guide

### 1. Network Security (gRPC)

```bash
# Proto compilieren
make proto-compile

# Zertifikate erstellen (Development)
./scripts/generate_grpc_certs.sh

# Oder Let's Encrypt (Production)
sudo ./scripts/setup_letsencrypt.sh --standalone

# gRPC Server starten
python -m ava.api.grpc_server
```

**Dokumentation:** [GRPC_SECURITY.md](GRPC_SECURITY.md)

---

### 2. Secret Management (Vault)

```bash
# Vault-Integration einrichten
export VAULT_ADDR=https://vault.company.com
export VAULT_TOKEN=...
sudo ./scripts/setup_vault_integration.sh setup

# Server mit Vault starten
source /etc/ava/vault.env
python -m ava.api.grpc_server
```

**Dokumentation:** [GRPC_SECURITY.md](GRPC_SECURITY.md#vault-integration)

---

### 3. Firewall & Network Security

```bash
# Firewall konfigurieren
export AVA_ALLOWED_IPS="10.0.0.0/8,192.168.1.0/24"
sudo ./scripts/setup_firewall.sh setup

# Status prüfen
sudo ./scripts/setup_firewall.sh show
```

**Dokumentation:** [scripts/setup_firewall.sh](../scripts/setup_firewall.sh)

---

### 4. Monitoring (Prometheus + Grafana)

```bash
# Metrics-Endpoint ist automatisch aktiv
curl http://localhost:9090/metrics

# Grafana-Dashboard importieren
# In Grafana: Import → Upload JSON
# File: deployment/grafana/ava-grpc-dashboard.json
```

**Dokumentation:** [PRODUCTION_FEATURES.md](PRODUCTION_FEATURES.md#monitoring)

---

### 5. Windows Endpoint Security

**PowerShell (als Administrator):**

```powershell
# Security Framework installieren
.\scripts\windows\ava_security_framework.ps1

# SOC Toolkit nutzen
.\scripts\windows\ava_soc_toolkit.ps1
```

**Dokumentation:** [WINDOWS_SECURITY.md](WINDOWS_SECURITY.md)

---

### 6. Cross-Platform Security (Python)

```python
from ava.security import SecurityMonitor

# Security Scan
monitor = SecurityMonitor()
results = monitor.run_security_scan()

print(f"Platform: {results['platform']}")
print(f"Alerts: {len(results['alerts'])}")
```

**Dokumentation:** [WINDOWS_SECURITY.md](WINDOWS_SECURITY.md#python-security-api)

---

### 7. Security REST API

```bash
# AVA Server mit Security API starten
python -m ava.server

# Security Status
curl http://localhost:8000/api/security/status

# Security Scan
curl -X POST http://localhost:8000/api/security/scan

# Alerts abrufen
curl http://localhost:8000/api/security/alerts
```

**Dokumentation:** [ava/api/security.py](../ava/api/security.py)

---

## 🔐 Security Features Matrix

### Network Security

| Feature | Implementation | Status |
|---------|----------------|--------|
| TLS 1.3 | gRPC Server | ✅ |
| mTLS (Mutual TLS) | Client Cert Verification | ✅ |
| Certificate Rotation | Let's Encrypt Auto-Renewal | ✅ |
| Firewall | iptables/UFW/NetworkPolicy | ✅ |
| Rate Limiting | iptables (100 conn/min) | ✅ |

### Application Security

| Feature | Implementation | Status |
|---------|----------------|--------|
| API-Key Auth | grpc_auth.py | ✅ |
| JWT Tokens | PyJWT | ✅ |
| RBAC | 4 Roles (Admin/User/Service/ReadOnly) | ✅ |
| Audit Logging | AuditLogger | ✅ |
| Request Validation | gRPC Interceptors | ✅ |

### Infrastructure Security

| Feature | Implementation | Status |
|---------|----------------|--------|
| Secret Management | HashiCorp Vault | ✅ |
| Metrics | Prometheus (16+ Metriken) | ✅ |
| Dashboards | Grafana | ✅ |
| Systemd Hardening | 20+ Direktiven | ✅ |
| Pod Security | K8s SecurityContext | ✅ |

### Endpoint Security

| Feature | Implementation | Status |
|---------|----------------|--------|
| Process Monitoring | Windows/Linux | ✅ |
| Remote Access Blocking | 15+ Tools | ✅ |
| RDP Auto-Disable | Windows Registry | ✅ |
| Defender Monitoring | PowerShell/Python | ✅ |
| Firewall Status | Cross-Platform | ✅ |

### SOC Operations

| Feature | Implementation | Status |
|---------|----------------|--------|
| Detection Engine | MITRE ATT&CK (4 Techniques) | ✅ |
| Threat Hunting | Unsigned Binaries, Persistence | ✅ |
| Incident Response | Auto Evidence Collection | ✅ |
| Vulnerability Assessment | Risk Scoring | ✅ |
| SOC Reports | PDF/TXT Export | ✅ |

---

## 📁 Dateistruktur (Complete)

```
AVA/
├── ava/
│   ├── api/
│   │   ├── grpc_server.py           # gRPC Server mit TLS/mTLS
│   │   ├── grpc_auth.py             # RBAC + API-Keys + JWT
│   │   ├── security.py              # Security REST API (NEU)
│   │   └── proto/
│   │       └── ava_service.proto    # Proto-Definitionen
│   │
│   ├── config/
│   │   └── vault.py                 # HashiCorp Vault-Integration
│   │
│   ├── monitoring/
│   │   └── grpc_metrics.py          # Prometheus Metrics
│   │
│   └── security/                     # NEU
│       ├── __init__.py
│       ├── windows_monitor.py       # Cross-Platform Monitor
│       └── config.py                # Security Config
│
├── scripts/
│   ├── setup_letsencrypt.sh         # Let's Encrypt Setup
│   ├── setup_vault_integration.sh   # Vault Setup
│   ├── setup_firewall.sh            # iptables Firewall
│   ├── setup_ufw.sh                 # UFW Firewall
│   ├── generate_grpc_certs.sh       # Dev-Zertifikate
│   │
│   └── windows/                      # NEU
│       ├── ava_security_framework.ps1  # Security Monitor
│       ├── ava_soc_toolkit.ps1         # SOC Tools
│       └── README.md
│
├── deployment/
│   ├── systemd/
│   │   ├── ava-grpc.service         # Systemd Unit (hardened)
│   │   └── install.sh               # Installation
│   │
│   ├── kubernetes/
│   │   ├── deployment.yaml          # K8s Manifeste
│   │   └── README.md
│   │
│   ├── grafana/
│   │   └── ava-grpc-dashboard.json  # Grafana Dashboard
│   │
│   └── README.md
│
└── docs/
    ├── GRPC_SECURITY.md             # gRPC Security Guide
    ├── PRODUCTION_FEATURES.md       # Production Features
    ├── WINDOWS_SECURITY.md          # Windows Security (NEU)
    └── SECURITY_MASTER.md           # Diese Datei (NEU)
```

---

## 🎯 MITRE ATT&CK Coverage

| Technique | Name | Detection Method | Severity |
|-----------|------|------------------|----------|
| **T1110** | Brute Force | Event 4625 (Failed Logons) | Medium |
| **T1059** | Command Execution | Event 4688 (Process Start) | High |
| **T1543** | Create System Process | Event 4697 (Service Install) | High |
| **T1078** | Valid Accounts | Event 4672 (Privilege Use) | Critical |

**Zukünftige Erweiterungen:**
- T1547 (Boot/Logon Autostart)
- T1055 (Process Injection)
- T1071 (Application Layer Protocol)
- T1140 (Deobfuscate/Decode Files)

---

## 🔒 Defense-in-Depth Strategy

```
┌─────────────────────────────────────────────┐
│  Layer 7: SOC Operations                    │
│  → Detection, Hunting, IR                   │
├─────────────────────────────────────────────┤
│  Layer 6: Endpoint Security                 │
│  → Process Monitoring, RDP Block            │
├─────────────────────────────────────────────┤
│  Layer 5: Application Security              │
│  → RBAC, API-Keys, JWT, Audit               │
├─────────────────────────────────────────────┤
│  Layer 4: Infrastructure Security           │
│  → Vault, Metrics, Hardening                │
├─────────────────────────────────────────────┤
│  Layer 3: Network Security                  │
│  → TLS/mTLS, Firewall, Rate-Limiting        │
├─────────────────────────────────────────────┤
│  Layer 2: Deployment Security               │
│  → Systemd Hardening, K8s Policies          │
├─────────────────────────────────────────────┤
│  Layer 1: Platform Security                 │
│  → OS Hardening, Updates, Config            │
└─────────────────────────────────────────────┘
```

---

## 🚨 Incident Response Playbook

### Phase 1: Detection

```bash
# Automatische Detection (läuft dauerhaft)
# Windows: Scheduled Task
# Linux: systemd service

# Manuelle Checks
python -m ava.security.windows_monitor
# oder
.\scripts\windows\ava_soc_toolkit.ps1  # Option 1: Detection Engine
```

### Phase 2: Analysis

```powershell
# Windows SOC Toolkit
.\ava_soc_toolkit.ps1
# → Option 2: Threat Hunting
# → Option 4: Vulnerability Assessment
```

### Phase 3: Containment

```powershell
# Automatisch: Blocked Processes werden getötet
# Manuell über REST API:
curl -X POST http://localhost:8000/api/security/action \
  -H "Content-Type: application/json" \
  -d '{"action": "kill_process", "params": {"pid": 12345}}'
```

### Phase 4: Evidence Collection

```powershell
# Windows
.\ava_soc_toolkit.ps1
# → Option 3: Create Incident Case
# → Evidence: %USERPROFILE%\AVA_SOC\Cases\INC_*

# Linux
python -m ava.security.windows_monitor
# → Evidence: /var/log/ava/evidence/
```

### Phase 5: Recovery

```bash
# Service-Neustart
sudo systemctl restart ava-grpc

# Logs prüfen
journalctl -u ava-grpc -f
```

### Phase 6: Reporting

```powershell
# SOC Report generieren
.\ava_soc_toolkit.ps1
# → Option 5: Generate SOC Report
```

---

## 📊 Compliance & Standards

AVA erfüllt/unterstützt:

- **NIST Cybersecurity Framework** - Identify, Protect, Detect, Respond, Recover
- **MITRE ATT&CK** - Detection & Response Mapping
- **CIS Controls** - Network Security, Access Control, Monitoring
- **ISO 27001** - Information Security Management
- **GDPR** - Audit Logging, Data Protection
- **SOC 2** - Security Controls Documentation

---

## 🎓 Training & Use Cases

### 1. Blue Team Training

```powershell
# SOC Analyst Training
.\ava_soc_toolkit.ps1
# → Alle 5 Optionen durchgehen
# → Reports analysieren
# → Incident Cases verstehen
```

### 2. Penetration Testing (Defensive)

```bash
# Test: gRPC Security
# → Cert-Validation testen
# → Auth-Bypass-Versuche (sollten fehlschlagen)
# → Rate-Limiting testen

# Test: Endpoint Security
# → TeamViewer starten (sollte getötet werden)
# → RDP aktivieren (sollte blockiert sein)
```

### 3. Enterprise Deployment

```bash
# Kubernetes (Production)
kubectl apply -f deployment/kubernetes/deployment.yaml

# Monitoring Setup
# → Prometheus scraping AVA Metrics
# → Grafana Dashboard importieren
# → Alerts konfigurieren
```

### 4. Security Audit

```bash
# Vollständiger Security-Check
./scripts/setup_firewall.sh show
python -m ava.security.windows_monitor
curl http://localhost:8000/api/security/status

# Windows
.\ava_soc_toolkit.ps1  # Option 4: Vulnerability Assessment
```

---

## 🔧 Troubleshooting

### gRPC Server startet nicht

```bash
# Proto-Files kompilieren
make proto-compile

# Zertifikate prüfen
ls -l certs/

# Logs prüfen
journalctl -u ava-grpc -f
```

### Windows Scripts funktionieren nicht

```powershell
# Execution Policy
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser

# Admin-Rechte prüfen
net session
```

### Vault-Verbindung fehlschlägt

```bash
# Vault-Status prüfen
echo $VAULT_ADDR
vault status

# Fallback: Environment-Variablen
export AVA_API_KEY=...
export AVA_JWT_SECRET=...
```

---

## 📈 Roadmap

### Kurzfristig (Q1 2026)
- ✅ Windows Security Framework
- ✅ SOC Toolkit
- ✅ Cross-Platform Python Monitor
- ✅ Security REST API

### Mittelfristig (Q2 2026)
- 🔄 SIEM-Integration (Splunk, Elastic)
- 🔄 EDR-Features (File Monitoring, Registry)
- 🔄 Threat Intelligence Integration
- 🔄 Machine Learning Anomaly Detection

### Langfristig (Q3-Q4 2026)
- 🔮 Cloud Security (AWS/Azure/GCP Monitoring)
- 🔮 Container Security (Docker/K8s Scanning)
- 🔮 Mobile Device Management
- 🔮 Zero Trust Architecture

---

## 🤝 Contributing

Security-Contributions sind willkommen:

1. **Detection Rules** - neue MITRE ATT&CK Techniques
2. **Platform Support** - macOS, BSD, etc.
3. **Integrations** - SIEM, SOAR, Ticketing
4. **Documentation** - Playbooks, Best Practices

---

## 📞 Support

- **Dokumentation:** [docs/](../docs/)
- **Issues:** GitHub Issues
- **Security:** security@ava-project.com (geplant)

---

## ⚖️ Legal & Ethics

**AVA Security Framework ist ausschließlich für:**

- ✅ Autorisierte Security-Operationen
- ✅ Blue Team / Defensive Security
- ✅ Compliance & Audit
- ✅ Training & Ausbildung

**NICHT für:**
- ❌ Offensive Hacking ohne Erlaubnis
- ❌ Nicht-autorisierte Systeme
- ❌ Illegale Aktivitäten

**Ethical Use Only** - Verantwortungsvoller Umgang ist Pflicht!

---

**AVA - Complete Security Framework** 🛡️  
*Defense in Depth. Detection at Scale. Response in Minutes.*


# Titel
$Title = "GHZ-Experiment in 37 Dimensionen"

# Textinhalt
$Text = @"
Das Experiment zeigt, dass Quantenverschränkung auch in sehr hochdimensionalen
Systemen experimentell zugänglich und kontrollierbar ist.

Konkret zeigt es:
- Das Greenberger–Horne–Zeilinger-(GHZ)-Paradoxon gilt auch in 37 Dimensionen
- Klassische lokal-realistische Theorien versagen
- Hochdimensionale Quantenzustände von Licht sind präzise messbar

Bedeutung:
Starker Test der Quantenmechanik und relevant für Quantenkommunikation,
Quantenkryptographie und zukünftige Quantencomputer.
"@

# Ausgabe im Terminal
Write-Host "==============================" -ForegroundColor Cyan
Write-Host $Title -ForegroundColor Yellow
Write-Host "==============================" -ForegroundColor Cyan
Write-Host $Text

# Datei speichern
$FilePath = "$PSScriptRoot\GHZ_Experiment.txt"
$Text | Out-File -Encoding UTF8 $FilePath

# Datei öffnen
Start-Process notepad.exe $FilePath




Set-ExecutionPolicy -Scope CurrentUser RemoteSigned



.\ghz_experiment.ps1





# Dimension
$d = 37

# Komplexe Zahl als Objekt
function Complex($re, $im) {
    [PSCustomObject]@{
        Re = $re
        Im = $im
    }
}

# Addition komplexer Zahlen
function CAdd($a, $b) {
    Complex ($a.Re + $b.Re) ($a.Im + $b.Im)
}

# Multiplikation komplexer Zahlen
function CMul($a, $b) {
    Complex (
        $a.Re * $b.Re - $a.Im * $b.Im
    ) (
        $a.Re * $b.Im + $a.Im * $b.Re
    )
}

# e^(i*phi)
function CExp($phi) {
    Complex ([Math]::Cos($phi)) ([Math]::Sin($phi))
}

# Normierungsfaktor
$norm = 1.0 / [Math]::Sqrt($d)

# GHZ-Zustand |GHZ_d>
$GHZ = @()
for ($k = 0; $k -lt $d; $k++) {
    $GHZ += ,@($k, $k, $k, $norm)
}

Write-Host "GHZ-Zustand in $d Dimensionen erzeugt." -ForegroundColor Cyan

# Phasenoperator Z Erwartungswert
$expectation = Complex 0 0
for ($k = 0; $k -lt $d; $k++) {
    $phase = 2 * [Math]::PI * $k / $d
    $e = CExp($phase)
    $term = CMul (Complex $norm 0) $e
    $expectation = CAdd $expectation $term
}

Write-Host "Erwartungswert eines hochdimensionalen Z-Operators:"
Write-Host "Re = $($expectation.Re)"
Write-Host "Im = $($expectation.Im)"

# Klassische Vorhersage (lokal-realistisch)
Write-Host ""
Write-Host "Klassische Modellvorhersage: Erwartungswert = 0"
Write-Host "Quantenmechanisches Ergebnis widerspricht der Klassik."




# Dimension
$d = 37

Write-Host "GHZ-Ungleichung für d = $d Dimensionen" -ForegroundColor Cyan
Write-Host "------------------------------------"

# Erwartungswerte (theoretisch exakt für GHZ_d)
$EXXX = 1
$EXYY = -1
$EYXY = -1
$EYYX = -1

# Mermin-GHZ-Ausdruck
$M = $EXXX - $EXYY - $EYXY - $EYYX

# Klassische Schranke
$classicalBound = 2

Write-Host "Erwartungswerte:"
Write-Host "<XXX> = $EXXX"
Write-Host "<XYY> = $EXYY"
Write-Host "<YXY> = $EYXY"
Write-Host "<YYX> = $EYYX"
Write-Host ""

Write-Host "Mermin-Ausdruck M = $M" -ForegroundColor Yellow
Write-Host "Klassische Schranke |M| ≤ $classicalBound"

if ([Math]::Abs($M) -gt $classicalBound) {
    Write-Host "➡ GHZ-Ungleichung VERLETZT!" -ForegroundColor Red
} else {
    Write-Host "➡ Keine Verletzung" -ForegroundColor Green
}


<#
===============================================================================
 AVA – AUTOMATED VULNERABILITY ASSESSMENT
 Blue Team | SOC | Audit | Enterprise | Home-Lab
===============================================================================

BEREICHE:
1. System & Patch Vulnerabilities
2. Identity & Privilege Weaknesses
3. Network Exposure & Services
4. Security Controls Gaps
5. Persistence & Misconfiguration
6. Risk Scoring
7. Executive & Technical Report

NO OFFENSIVE ACTIONS
===============================================================================
#>

# ===============================
# ADMIN CHECK
# ===============================
If (-not ([Security.Principal.WindowsPrincipal]
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Host "Administratorrechte erforderlich!" -ForegroundColor Red
    Exit
}

Clear-Host
Write-Host "=== AVA – AUTOMATED VULNERABILITY ASSESSMENT ===" -ForegroundColor Cyan
Write-Host "Blue Team | SOC | Enterprise Security" -ForegroundColor Yellow

# ===============================
# GLOBALS
# ===============================
$AVAPath = "$env:USERPROFILE\AVA_Assessment"
New-Item -ItemType Directory -Path $AVAPath -Force | Out-Null
$Findings = @()

# ===============================
# 1. PATCH & SYSTEM STATUS
# ===============================
function AVA-Patching {
    Write-Host "`n[ PATCH & SYSTEM STATUS ]" -ForegroundColor Cyan

    $LastPatch = Get-HotFix | Sort InstalledOn -Descending | Select -First 1

    if ((Get-Date) - $LastPatch.InstalledOn -gt (New-TimeSpan -Days 30)) {
        $Findings += "❌ System nicht aktuell gepatcht (>$($LastPatch.InstalledOn))"
        Write-Host "❌ Kritisch: Patch-Stand veraltet" -ForegroundColor Red
    } else {
        Write-Host "✔ Patch-Stand aktuell" -ForegroundColor Green
    }
}

# ===============================
# 2. IDENTITY & PRIVILEGES
# ===============================
function AVA-Identity {
    Write-Host "`n[ IDENTITY & PRIVILEGES ]" -ForegroundColor Cyan

    $Admins = Get-LocalGroupMember Administrators
    if ($Admins.Count -gt 3) {
        $Findings += "⚠️ Viele lokale Administratoren ($($Admins.Count))"
        Write-Host "⚠️ Warnung: Zu viele Administratoren" -ForegroundColor Yellow
    }

    $Guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($Guest.Enabled) {
        $Findings += "❌ Gastkonto aktiv"
        Write-Host "❌ Kritisch: Gastkonto aktiv" -ForegroundColor Red
    }
}

# ===============================
# 3. NETWORK EXPOSURE
# ===============================
function AVA-Network {
    Write-Host "`n[ NETWORK EXPOSURE ]" -ForegroundColor Cyan

    $Listening = Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"}

    foreach ($port in $Listening) {
        if ($port.LocalPort -in 3389,445) {
            $Findings += "⚠️ Kritischer Dienst offen: Port $($port.LocalPort)"
            Write-Host "⚠️ Offener kritischer Port: $($port.LocalPort)" -ForegroundColor Yellow
        }
    }
}

# ===============================
# 4. SECURITY CONTROLS
# ===============================
function AVA-SecurityControls {
    Write-Host "`n[ SECURITY CONTROLS ]" -ForegroundColor Cyan

    $Defender = Get-MpComputerStatus
    if (-not $Defender.RealTimeProtectionEnabled) {
        $Findings += "❌ Defender Echtzeitschutz deaktiviert"
        Write-Host "❌ Defender Schutz deaktiviert" -ForegroundColor Red
    }

    $SMB = Get-SmbServerConfiguration
    if ($SMB.EnableSMB1Protocol) {
        $Findings += "❌ SMBv1 aktiviert"
        Write-Host "❌ SMBv1 aktiv" -ForegroundColor Red
    }
}

# ===============================
# 5. PERSISTENCE & MISCONFIG
# ===============================
function AVA-Persistence {
    Write-Host "`n[ PERSISTENCE & MISCONFIGURATION ]" -ForegroundColor Cyan

    $RunKeys = Get-ItemProperty `
        HKLM:\Software\Microsoft\Windows\CurrentVersion\Run `
        -ErrorAction SilentlyContinue

    if ($RunKeys.PSObject.Properties.Count -gt 5) {
        $Findings += "⚠️ Viele Autostart-Einträge"
        Write-Host "⚠️ Auffällige Autostarts" -ForegroundColor Yellow
    }
}

# ===============================
# 6. RISK SCORING
# ===============================
function AVA-RiskScore {
    Write-Host "`n[ RISK SCORING ]" -ForegroundColor Cyan

    $Score = 100
    $Score -= ($Findings.Count * 10)

    if ($Score -lt 60) {
        Write-Host "❌ Risiko: HOCH ($Score/100)" -ForegroundColor Red
    } elseif ($Score -lt 80) {
        Write-Host "⚠️ Risiko: MITTEL ($Score/100)" -ForegroundColor Yellow
    } else {
        Write-Host "✔ Risiko: NIEDRIG ($Score/100)" -ForegroundColor Green
    }

    return $Score
}

# ===============================
# 7. REPORTING
# ===============================
function AVA-Report {
    Write-Host "`n[ AVA REPORT ]" -ForegroundColor Cyan

    $Report = "$AVAPath\AVA_Report_$(Get-Date -Format yyyyMMdd).txt"

    "AUTOMATED VULNERABILITY ASSESSMENT" | Out-File $Report
    "=================================" | Out-File $Report -Append
    "Date: $(Get-Date)" | Out-File $Report -Append
    "" | Out-File $Report -Append
    "Findings:" | Out-File $Report -Append
    $Findings | Out-File $Report -Append
    "" | Out-File $Report -Append
    "Risk Score: $(AVA-RiskScore)/100" | Out-File $Report -Append

    Write-Host "Report erstellt: $Report" -ForegroundColor Green
}

# ===============================
# 8. AVA RUN
# ===============================
AVA-Patching
AVA-Identity
AVA-Network
AVA-SecurityControls
AVA-Persistence
AVA-Report

Write-Host "`nAVA abgeschlossen – Bewertung nur für autorisierte Systeme." -ForegroundColor Cyan

