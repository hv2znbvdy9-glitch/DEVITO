# AVA Windows Scripts

## PowerShell Security & Monitoring Tools

Dieses Verzeichnis enthält **Windows-spezifische Security-Tools** für AVA.

---

## 📄 Verfügbare Scripts

### 1. `ava_security_framework.ps1`

**Zweck:** Dauerhaftes Security-Monitoring & Protection

**Features:**
- ✅ Blockiert Remote-Access-Tools (TeamViewer, AnyDesk, RDP, etc.)
- ✅ Deaktiviert RDP & QuickAssist
- ✅ Browser-Profil-Audit
- ✅ Security-Logging mit Rotation
- ✅ Installiert sich als Scheduled Task (läuft alle 5 Min)

**Installation:**

```powershell
# Als Administrator ausführen
.\ava_security_framework.ps1
```

**Logs:** `C:\ProgramData\AVA\Logs\ava_security.log`

---

### 2. `ava_soc_toolkit.ps1`

**Zweck:** Blue Team / SOC Operations

**Features:**
- 🎯 Detection Engine (MITRE ATT&CK Mapping)
- 🔍 Threat Hunting (unsignierte Prozesse, Persistence)
- 🚨 Incident Response (automatische Evidence Collection)
- 🔐 Vulnerability Assessment (Risiko-Bewertung)
- 📊 SOC Reports (vollständige Security-Berichte)

**Verwendung:**

```powershell
# Interaktives Menü
.\ava_soc_toolkit.ps1
```

**Output:**
- Cases: `%USERPROFILE%\AVA_SOC\Cases\`
- Reports: `%USERPROFILE%\AVA_SOC\Reports\`

---

### 3. `ghz_experiment.ps1`

**Zweck:** GHZ Quantenverschränkungs-Experiment (Educational)

**Features:**
- 🔬 GHZ-Zustand in 37 Dimensionen
- 📊 Mermin-Ungleichung Berechnung
- ⚛️ Quantenkorrelations-Nachweis
- 📄 Wissenschaftlicher Report

**Verwendung:**

```powershell
# Experiment ausführen
.\ghz_experiment.ps1
```

**Output:**
- Report: `ghz_experiment_report.txt`

**Hintergrund:**
Demonstriert hochdimensionale Quantenverschränkung (Greenberger-Horne-Zeilinger Paradoxon) - relevant für Quantenkommunikation, Kryptographie und Computing.

---

### 4. `ava_ethical_lab.ps1`

**Zweck:** Interaktives Security-Lab für Training & Ausbildung

**Features:**
- 📋 Systeminformationen & OS-Analyse
- 👥 Benutzer- & Rechteprüfung
- 🌐 Netzwerk-Analyse (passiv, legal)
- 🛡️ Windows Defender & Firewall Status
- 📊 Security Event Log Analyse
- 🔧 Tool-Umgebung vorbereiten (Git, Python)
- 🎓 Ideale Lernumgebung für Cybersecurity-Studenten

**Verwendung:**

```powershell
# Interaktives Menü starten
.\ava_ethical_lab.ps1
```

**Arbeitsverzeichnis:** `%USERPROFILE%\SecurityLab`

**Hinweis:**
Dieses Tool ist ausschließlich für **ethisches Training** in autorisierten Umgebungen gedacht. Perfekt für:
- Cybersecurity-Ausbildung
- Home Lab Setup
- Security Research (legal)
- Blue Team Training

---

## ⚙️ System-Anforderungen

- **OS:** Windows 10/11 oder Windows Server 2016+
- **PowerShell:** Version 5.1+
- **Rechte:** Administrator (für alle Scripts erforderlich)

---

## 🚀 Quick Start

### Schritt 1: Admin-PowerShell öffnen

```powershell
# Rechtsklick auf PowerShell → "Als Administrator ausführen"
```

### Schritt 2: Execution Policy setzen (falls nötig)

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Schritt 3: Security Framework aktivieren

```powershell
cd C:\path\to\AVA\scripts\windows
.\ava_security_framework.ps1
```

### Schritt 4: SOC Toolkit verwenden

```powershell
.\ava_soc_toolkit.ps1
```

### Schritt 5: Ethical Lab für Training starten

```powershell
# Interaktives Security-Training
.\ava_ethical_lab.ps1
```

---

## 🔒 Was wird überwacht/blockiert?

### Blocked Processes (automatisch):
- **RDP:** mstsc, rdpclip
- **Remote-Tools:** TeamViewer, AnyDesk, RustDesk
- **VNC:** vnc (alle Varianten)
- **Other:** QuickAssist, msra, scrcpy, chrome_remote_desktop, mirror

### Security Checks:
- Windows Defender Status
- Firewall Status
- RDP-Konfiguration
- SMBv1 (Sicherheitsrisiko)
- Patch-Stand
- Privilegierte Konten
- Offene kritische Ports (3389, 445, 135)

---

## 📊 Detection Rules (MITRE ATT&CK)

| Event ID | Technique | Description |
|----------|-----------|-------------|
| 4625 | T1110 | Multiple Failed Logons (Brute Force) |
| 4688 | T1059 | Suspicious Process Execution |
| 4697 | T1543 | New Service Installation |
| 4672 | T1078 | Privilege Escalation |

---

## 🛡️ Security Best Practices

### 1. Automatisierung

Nach Installation läuft `ava_security_framework.ps1` automatisch:

```powershell
# Status prüfen
Get-ScheduledTask -TaskName "AVA_Security_Monitor"

# Logs live anzeigen
Get-Content C:\ProgramData\AVA\Logs\ava_security.log -Wait -Tail 10
```

### 2. Regelmäßige SOC-Scans

```powershell
# Täglich oder wöchentlich
.\ava_soc_toolkit.ps1
# → Option 5: Generate SOC Report
```

### 3. Incident Response

Bei Sicherheitsvorfall:

```powershell
.\ava_soc_toolkit.ps1
# → Option 3: Create Incident Case
# → Sammelt automatisch: Prozesse, Netzwerk, Events, User
```

### 4. Vulnerability Management

```powershell
.\ava_soc_toolkit.ps1
# → Option 4: Vulnerability Assessment
# → Zeigt Risk Score + konkrete Findings
```

---

## 📁 Output-Verzeichnisse

### Security Framework:
```
C:\ProgramData\AVA\
├── Logs\
│   └── ava_security.log        # Haupt-Log (5 MB Rotation)
└── Evidence\
    ├── browser_profiles.txt    # Browser-Audit
    └── security_status.json    # Status-Snapshot
```

### SOC Toolkit:
```
%USERPROFILE%\AVA_SOC\
├── Cases\
│   └── INC_20260215_123456\   # Incident-Ordner
│       ├── processes.csv
│       ├── network.csv
│       ├── security_events.csv
│       └── local_users.csv
├── Reports\
│   └── SOC_Report_20260215_123456.txt
└── Detections\
```

---

## 🔗 Integration mit AVA (Python)

Diese PowerShell-Tools können mit AVA's Python-Backend kombiniert werden:

```python
# Python-Äquivalent (Cross-Platform)
from ava.security import SecurityMonitor

monitor = SecurityMonitor()
results = monitor.run_security_scan()

# Windows-spezifisch
if monitor.platform == "Windows":
    monitor.windows_monitor.disable_rdp()
```

Siehe: `ava/security/windows_monitor.py`

---

## ⚠️ Wichtige Hinweise

- ✅ **Nur für autorisierte Systeme** verwenden
- ✅ **Admin-Rechte erforderlich** für alle Funktionen
- ✅ **Logs regelmäßig prüfen** (automatische Rotation bei 5 MB)
- ✅ **Evidence sichern** vor System-Neustart
- ✅ **Ethical Use Only** - Blue Team / Defensive Security

---

## 🆘 Troubleshooting

### "Execution Policy" Fehler:

```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Scripts laufen nicht automatisch:

```powershell
# Task prüfen
Get-ScheduledTask -TaskName "AVA_Security_Monitor"

# Manuell neu installieren
.\ava_security_framework.ps1
```

### Keine Admin-Rechte:

```powershell
# PowerShell als Administrator starten:
# Win+X → "Windows PowerShell (Administrator)"
```

---

## 📚 Weitere Dokumentation

- [Windows Security Guide](../../docs/WINDOWS_SECURITY.md) - Vollständige Dokumentation
- [gRPC Security](../../docs/GRPC_SECURITY.md) - Network Security
- [Production Features](../../docs/PRODUCTION_FEATURES.md) - Deployment

---

**AVA Windows Security - Enterprise Protection** 🛡️


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

