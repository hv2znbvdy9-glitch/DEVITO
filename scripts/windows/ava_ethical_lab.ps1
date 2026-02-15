<#
============================================================
ETHICAL SECURITY LAB – PowerShell Komplettskript
Ausbildung | Studium | Home-Lab | Cybersecurity Basics
============================================================

INHALT:
1. Sicherheits- & Admin-Checks
2. System- & OS-Analyse
3. Benutzer- & Rechteprüfung
4. Netzwerk- & Verbindungsanalyse (passiv)
5. Windows Defender & Firewall
6. Eventlog-Analyse (Security)
7. Tool-Umgebung vorbereiten (Git, Python)
8. Strukturierte Ausgabe
9. Menüsystem (interaktiv)

============================================================
#>

# =========================
# 1. ADMIN CHECK
# =========================
If (-not ([Security.Principal.WindowsPrincipal]
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Host "❌ Bitte PowerShell als ADMINISTRATOR starten!" -ForegroundColor Red
    Pause
    Exit
}

Clear-Host
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " ETHICAL SECURITY LAB – PowerShell" -ForegroundColor Green
Write-Host " Nur für autorisierte Umgebungen" -ForegroundColor Yellow
Write-Host "=============================================" -ForegroundColor Cyan

# =========================
# 2. SYSTEM INFORMATION
# =========================
function Show-SystemInfo {
    Write-Host "`n[ SYSTEM INFORMATION ]" -ForegroundColor Cyan
    systeminfo
}

# =========================
# 3. USER & RECHTE
# =========================
function Show-UserInfo {
    Write-Host "`n[ BENUTZER & RECHTE ]" -ForegroundColor Cyan
    Get-LocalUser | Select Name, Enabled, LastLogon
    Write-Host "`nAdministratorengruppe:" -ForegroundColor Yellow
    Get-LocalGroupMember Administrators
}

# =========================
# 4. NETZWERK (PASSIV)
# =========================
function Show-NetworkInfo {
    Write-Host "`n[ NETZWERK ANALYSE – PASSIV ]" -ForegroundColor Cyan

    Write-Host "`nIP-Konfiguration:" -ForegroundColor Yellow
    ipconfig

    Write-Host "`nAktive Verbindungen:" -ForegroundColor Yellow
    netstat -ano

    Write-Host "`nTCP-Verbindungen (PowerShell):" -ForegroundColor Yellow
    Get-NetTCPConnection | Select State, LocalAddress, LocalPort, RemoteAddress, RemotePort
}

# =========================
# 5. DEFENDER & FIREWALL
# =========================
function Show-SecurityStatus {
    Write-Host "`n[ WINDOWS SECURITY STATUS ]" -ForegroundColor Cyan

    Write-Host "`nWindows Defender:" -ForegroundColor Yellow
    Get-MpComputerStatus |
        Select AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled

    Write-Host "`nFirewall Profile:" -ForegroundColor Yellow
    Get-NetFirewallProfile |
        Select Name, Enabled, DefaultInboundAction, DefaultOutboundAction
}

# =========================
# 6. EVENT LOG ANALYSE
# =========================
function Show-EventLogs {
    Write-Host "`n[ SECURITY EVENT LOGS – LETZTE 20 ]" -ForegroundColor Cyan
    Get-EventLog -LogName Security -Newest 20 |
        Select TimeGenerated, EntryType, Source, EventID, Message
}

# =========================
# 7. TOOL-UMGEBUNG
# =========================
function Prepare-Tools {
    Write-Host "`n[ TOOL-UMGEBUNG VORBEREITEN ]" -ForegroundColor Cyan

    # Arbeitsverzeichnis
    $ToolDir = "$env:USERPROFILE\SecurityLab"
    New-Item -ItemType Directory -Path $ToolDir -Force | Out-Null
    Set-Location $ToolDir

    Write-Host "Arbeitsverzeichnis: $ToolDir" -ForegroundColor Green

    # Git prüfen
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Host "Git nicht gefunden – Installation via winget" -ForegroundColor Yellow
        winget install --id Git.Git -e
    } else {
        Write-Host "Git vorhanden" -ForegroundColor Green
    }

    # Python prüfen
    if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
        Write-Host "Python nicht gefunden – Installation via winget" -ForegroundColor Yellow
        winget install --id Python.Python.3 -e
    } else {
        Write-Host "Python vorhanden" -ForegroundColor Green
    }

    # Beispiel: legales Repo klonen
    Write-Host "Klonen eines Open-Source Security-Repos (Beispiel)" -ForegroundColor Cyan
    git clone https://github.com/ErrOr-ICA/HCKRtool.git
}

# =========================
# 8. MENÜ
# =========================
function Show-Menu {
    Write-Host ""
    Write-Host "1  - Systeminformationen"
    Write-Host "2  - Benutzer & Rechte"
    Write-Host "3  - Netzwerk Analyse (passiv)"
    Write-Host "4  - Defender & Firewall"
    Write-Host "5  - Security Event Logs"
    Write-Host "6  - Tool-Umgebung vorbereiten"
    Write-Host "0  - Beenden"
}

# =========================
# 9. HAUPTSCHLEIFE
# =========================
do {
    Show-Menu
    $choice = Read-Host "Auswahl"

    switch ($choice) {
        1 { Show-SystemInfo }
        2 { Show-UserInfo }
        3 { Show-NetworkInfo }
        4 { Show-SecurityStatus }
        5 { Show-EventLogs }
        6 { Prepare-Tools }
        0 { Write-Host "Beenden..." -ForegroundColor Cyan }
        default { Write-Host "Ungültige Auswahl" -ForegroundColor Red }
    }

    Pause
    Clear-Host

} while ($choice -ne 0)

Write-Host "Lab beendet – arbeite immer ethisch & legal." -ForegroundColor Green
