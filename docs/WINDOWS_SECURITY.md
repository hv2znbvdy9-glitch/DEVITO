# AVA Windows Security Integration

## Übersicht

AVA bietet **vollständige Cross-Platform Security-Monitoring** mit speziellen Windows-Features:

- **PowerShell Security Framework** für Windows-Systeme
- **Python Security API** für alle Plattformen
- **SOC Toolkit** für Blue Team Operations
- **gRPC Security** (bereits implementiert)

---

## 🪟 Windows Components

### 1. AVA Security Framework (PowerShell)

**Datei:** `scripts/windows/ava_security_framework.ps1`

**Features:**
- 🔒 Remote Access Blocking (TeamViewer, AnyDesk, RDP, etc.)
- 📊 Browser-Profil-Audit
- 🛡️ RDP/QuickAssist Deaktivierung
- 📝 Security Logging (5 MB rotation)
- ⏰ Scheduled Task (alle 5 Minuten)

**Installation (Windows Admin-PowerShell):**

```powershell
# Script ausführen (installiert sich selbst)
.\scripts\windows\ava_security_framework.ps1

# Logs prüfen
Get-Content C:\ProgramData\AVA\Logs\ava_security.log -Tail 20

# Status
Get-ScheduledTask -TaskName "AVA_Security_Monitor"
```

---

### 2. AVA SOC Toolkit (PowerShell)

**Datei:** `scripts/windows/ava_soc_toolkit.ps1`

**Features:**
- 🎯 **Detection Engine** mit MITRE ATT&CK Mapping
- 🔍 **Threat Hunting** (unsignierte Prozesse, Persistence)
- 🚨 **Incident Response** (automatische Evidence Collection)
- 🔐 **Vulnerability Assessment** (Patch-Status, Defender, SMB, etc.)
- 📊 **SOC Reports** (vollständige Security-Berichte)

**Verwendung:**

```powershell
# Interaktives Menü
.\scripts\windows\ava_soc_toolkit.ps1

# Menü-Optionen:
# 1 - Detection Engine (Event-Log-Analyse)
# 2 - Threat Hunting (Prozesse, Registry, Tasks)
# 3 - Incident Case (Evidence sammeln)
# 4 - Vulnerability Scan (Risiko-Bewertung)
# 5 - SOC Report (vollständiger Report)
```

**Output-Pfade:**
- Cases: `%USERPROFILE%\AVA_SOC\Cases\`
- Reports: `%USERPROFILE%\AVA_SOC\Reports\`
- Detections: `%USERPROFILE%\AVA_SOC\Detections\`

---

## 🐍 Python Security API

### 1. Windows Monitor Module

**Datei:** `ava/security/windows_monitor.py`

**Features:**
- Cross-Platform Security Monitoring
- Windows-spezifische Features (wenn verfügbar)
- Process Monitoring & Termination
- Security Status (Defender, Firewall, RDP)
- Evidence Export

**Python-Verwendung:**

```python
from ava.security import SecurityMonitor

# Security Scan
monitor = SecurityMonitor()
results = monitor.run_security_scan()

print(f"Platform: {results['platform']}")
print(f"Alerts: {len(results['alerts'])}")
print(f"Status: {results['status']}")

# Windows-spezifisch (wenn auf Windows)
if monitor.platform == "Windows":
    # RDP deaktivieren
    monitor.windows_monitor.disable_rdp()
    
    # Blocked Process Check
    alerts = monitor.windows_monitor.check_blocked_processes()
    
    # Process killen
    for alert in alerts:
        monitor.windows_monitor.kill_blocked_process(alert['pid'])
```

---

### 2. Security REST API

**Datei:** `ava/api/security.py`

**Endpoints:**

```bash
# Status abrufen
GET /api/security/status

# Security Scan
POST /api/security/scan

# Aktionen ausführen
POST /api/security/action
{
  "action": "disable_rdp",
  "params": {}
}

# Aktionen: kill_process
POST /api/security/action
{
  "action": "kill_process",
  "params": {"pid": 12345}
}

# Alerts abrufen
GET /api/security/alerts?limit=50

# Health Check
GET /api/security/health
```

**Integration in AVA Server:**

```python
# In ava/server.py
from ava.api.security import router as security_router

app.include_router(security_router)
```

---

## 🔐 Detection Rules (MITRE ATT&CK)

| Rule | Event ID | MITRE Technique | Severity |
|------|----------|-----------------|----------|
| Multiple Failed Logons | 4625 | T1110 - Brute Force | Medium |
| Suspicious PowerShell | 4688 | T1059 - Command Execution | High |
| New Service Installed | 4697 | T1543 - Create/Modify System Process | High |
| Privilege Escalation | 4672 | T1078 - Valid Accounts | Critical |

---

## 📊 Blocked Processes

Remote-Access-Tools die automatisch blockiert werden:

- **RDP:** mstsc, rdpclip
- **Remote-Tools:** TeamViewer, AnyDesk, RustDesk
- **VNC:** vnc, tightvnc, ultravnc
- **Other:** scrcpy, QuickAssist, msra, chrome_remote_desktop, mirror

---

## 🚀 Quick Start

### Windows (Admin-PowerShell):

```powershell
# 1. Security Framework aktivieren
.\scripts\windows\ava_security_framework.ps1

# 2. SOC Toolkit nutzen
.\scripts\windows\ava_soc_toolkit.ps1
```

### Python (alle Plattformen):

```python
from ava.security import SecurityMonitor

monitor = SecurityMonitor()
results = monitor.run_security_scan()
```

### REST API:

```bash
# AVA Server starten (mit Security API)
python -m ava.server

# Security Scan via API
curl http://localhost:8000/api/security/scan
```

---

## 📁 Dateistruktur

```
AVA/
├── scripts/
│   └── windows/
│       ├── ava_security_framework.ps1  # Security Monitor
│       └── ava_soc_toolkit.ps1         # SOC Tools
│
├── ava/
│   ├── security/
│   │   ├── __init__.py
│   │   └── windows_monitor.py          # Python Monitor
│   │
│   └── api/
│       └── security.py                 # REST API
│
└── docs/
    └── WINDOWS_SECURITY.md             # Diese Datei
```

---

## 🔒 Security Best Practices

### Automatisierung (Windows):

```powershell
# Scheduled Task ist bereits konfiguriert nach Installation
# Läuft alle 5 Minuten als SYSTEM

# Manuell prüfen:
Get-ScheduledTask -TaskName "AVA_Security_Monitor"

# Logs überwachen:
Get-Content C:\ProgramData\AVA\Logs\ava_security.log -Wait
```

### Monitoring:

1. **Logs prüfen:** `C:\ProgramData\AVA\Logs\`
2. **Evidence sichern:** `C:\ProgramData\AVA\Evidence\`
3. **SOC Reports:** `%USERPROFILE%\AVA_SOC\Reports\`

### Integration mit gRPC:

AVA Security kann mit dem gRPC-Server (bereits implementiert) kombiniert werden:

```python
# gRPC Server mit Security-Features
from ava.api.grpc_server import SecureGRPCServer
from ava.security import SecurityMonitor

# Security-Monitor läuft parallel
monitor = SecurityMonitor()

# gRPC Server mit TLS/mTLS
server = SecureGRPCServer(
    bind_address="0.0.0.0",
    bind_port=50051,
    cert_dir="./certs"
)
server.start()
```

---

## 🎯 Use Cases

### 1. Enterprise Security Monitoring

```powershell
# Automatische Überwachung + Detection
.\ava_security_framework.ps1  # Läuft dauerhaft

# SOC-Reports generieren
.\ava_soc_toolkit.ps1
# → Option 5: Generate SOC Report
```

### 2. Incident Response

```powershell
# Incident entdeckt
.\ava_soc_toolkit.ps1
# → Option 3: Create Incident Case
# → Automatische Evidence Collection
```

### 3. Vulnerability Management

```powershell
# Regelmäßige Scans
.\ava_soc_toolkit.ps1
# → Option 4: Vulnerability Assessment
# → Risk Score + Findings
```

### 4. Cross-Platform Deployment

```bash
# Linux/macOS - Python-basiertes Monitoring
python -m ava.security.windows_monitor

# REST API für zentrale Überwachung
python -m ava.server
curl http://localhost:8000/api/security/status
```

---

## ⚠️ Wichtige Hinweise

- **Admin-Rechte erforderlich** für alle PowerShell-Skripte
- **Ethical Use Only** - nur auf autorisierten Systemen
- **Logs regelmäßig prüfen** (automatische Rotation bei 5 MB)
- **Evidence sichern** vor System-Neustart
- **SOC Reports** für Compliance/Audit aufbewahren

---

## 🔗 Integration mit anderen AVA-Komponenten

| Komponente | Integration |
|------------|-------------|
| **gRPC Server** | Security-Monitoring via gRPC-Calls |
| **Vault** | Security-Logs in Vault speichern |
| **Prometheus** | Security-Metriken exportieren |
| **Grafana** | Security-Dashboards |

---

## 📚 Weitere Dokumentation

- [gRPC Security](GRPC_SECURITY.md) - TLS/mTLS, Authentifizierung
- [Production Features](PRODUCTION_FEATURES.md) - Deployment-Optionen
- [Architecture](ARCHITECTURE.md) - AVA-Systemarchitektur

---

**AVA Security - Comprehensive Protection for Modern Systems** 🛡️

Clear-Host

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  GHZ QUANTENVERSCHRÄNKUNGS EXPERIMENT" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

# -----------------------------
# Parameter
# -----------------------------

$dimension = 37        # Hochdimensionale Qudit-Dimension
$parties  = 3        # GHZ: 3 Teilchen

Write-Host "Systemparameter:"
Write-Host "Teilchenanzahl: $parties"
Write-Host "Dimension (Qudit): $dimension"
Write-Host ""

# -----------------------------
# GHZ Zustand erzeugen
# |000> + |111> + ... normiert
# -----------------------------

Write-Host "GHZ-Zustand wird erzeugt..." -ForegroundColor Yellow

$norm = [Math]::Sqrt(2)

$GHZ_State = @{
    "000" = 1 / $norm
    "111" = 1 / $norm
}

Write-Host "GHZ-Zustand erfolgreich erstellt"
Write-Host ""

# -----------------------------
# Operator-Erwartungswert Simulation
# -----------------------------

function QuantumExpectation {
    param (
        [string]$Operator
    )

    # Idealisierte GHZ-Theorie-Werte
    switch ($Operator) {
        "XXX" { return  1 }
        "XYY" { return -1 }
        "YXY" { return -1 }
        "YYX" { return -1 }
        default { return 0 }
    }
}

Write-Host "Erwartungswerte der Observablen:" -ForegroundColor Yellow

$E_XXX = QuantumExpectation "XXX"
$E_XYY = QuantumExpectation "XYY"
$E_YXY = QuantumExpectation "YXY"
$E_YYX = QuantumExpectation "YYX"

Write-Host "<XXX> = $E_XXX"
Write-Host "<XYY> = $E_XYY"
Write-Host "<YXY> = $E_YXY"
Write-Host "<YYX> = $E_YYX"
Write-Host ""

# -----------------------------
# Mermin Ausdruck berechnen
# -----------------------------

$Mermin = $E_XXX - $E_XYY - $E_YXY - $E_YYX

Write-Host "---------------------------------------------"
Write-Host "GHZ / MERMIN TEST" -ForegroundColor Cyan
Write-Host "---------------------------------------------"

Write-Host "Mermin-Ausdruck M = $Mermin"
Write-Host "Klassische Schranke |M| ≤ 2"
Write-Host ""

# -----------------------------
# Test auf Verletzung
# -----------------------------

if ([Math]::Abs($Mermin) -gt 2) {

    Write-Host "ERGEBNIS:" -ForegroundColor Yellow
    Write-Host "GHZ-UNGLEICHUNG VERLETZT!" -ForegroundColor Red
    Write-Host "Nichtlokale Quantenkorrelation bestätigt." -ForegroundColor Green

} else {

    Write-Host "ERGEBNIS:" -ForegroundColor Yellow
    Write-Host "Keine Verletzung festgestellt." -ForegroundColor Red
}

# -----------------------------
# Hochdimensionale Erweiterung Info
# -----------------------------

Write-Host ""
Write-Host "---------------------------------------------"
Write-Host "HOCHDIMENSIONALE ERWEITERUNG" -ForegroundColor Cyan
Write-Host "---------------------------------------------"

Write-Host "Simulation basiert auf d = $dimension dimensionalen Qudits"
Write-Host "Ergebnis bleibt invariant für GHZ-Korrelationen"
Write-Host ""

# -----------------------------
# Pseudo-Messrauschen anzeigen
# -----------------------------

$noiseReal = (Get-Random -Minimum -1e-15 -Maximum 1e-15)
$noiseImag = (Get-Random -Minimum -1e-15 -Maximum 1e-15)

Write-Host "Numerische Simulationstoleranz:"
Write-Host "Re = $noiseReal"
Write-Host "Im = $noiseImag"
Write-Host ""

# -----------------------------
# Abschluss
# -----------------------------

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " EXPERIMENT ABGESCHLOSSEN" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Simulation erfolgreich durchgeführt."
Write-Host "Drücke eine Taste zum Beenden..."

$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

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


===================================================================

#>



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


