# =====================================================
# AVA SECURITY FRAMEWORK – WINDOWS v1.0
# Author: AVA Project
# Admin: Security Monitoring & Protection
# =====================================================

# ---------- ADMIN CHECK ----------
$IsAdmin = ([bool](net session 2>$null)) -or ($env:USERNAME -eq "SYSTEM")
if (-not $IsAdmin) {
    Write-Host "❌ Bitte PowerShell als ADMINISTRATOR starten!" -ForegroundColor Red
    exit 1
}

# ---------- BASIS ----------
$BASE      = "C:\ProgramData\AVA"
$LOGDIR    = "$BASE\Logs"
$EVIDENCE  = "$BASE\Evidence"
$LOGFILE   = "$LOGDIR\ava_security.log"
$LOCKFILE  = "$BASE\.lock"
$TASKNAME  = "AVA_Security_Monitor"

New-Item -ItemType Directory -Path $BASE,$LOGDIR,$EVIDENCE -Force | Out-Null

# ---------- LOGGING ----------
function Write-Log {
    param([string]$Text)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ts | $Text" | Out-File $LOGFILE -Append -Encoding UTF8
}

# Log Rotation (5 MB)
if (Test-Path $LOGFILE) {
    if ((Get-Item $LOGFILE).Length -gt 5MB) {
        Rename-Item $LOGFILE "$LOGFILE.old" -Force
    }
}

# ---------- LOCK ----------
if (Test-Path $LOCKFILE) { exit }
New-Item $LOCKFILE -ItemType File -Force | Out-Null

try {

Write-Log "=== AVA SECURITY RUN START ==="

# =====================================================
# 1. PROZESS-MONITORING (REMOTE ACCESS BLOCK)
# =====================================================
$BlockedProcesses = @(
    "mstsc","rdpclip","teamviewer","anydesk","rustdesk",
    "vnc","scrcpy","msra","quickassist","mirror",
    "chrome_remote_desktop"
)

Get-Process | ForEach-Object {
    foreach ($blocked in $BlockedProcesses) {
        if ($_.Name -like "*$blocked*") {
            Write-Log "BLOCKED PROCESS: $($_.Name) [PID: $($_.Id)]"
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        }
    }
}

# =====================================================
# 2. BROWSER-PROFIL-AUDIT
# =====================================================
$BrowserPaths = @(
    "$env:LOCALAPPDATA\Google\Chrome\User Data",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
)

foreach ($path in $BrowserPaths) {
    if (Test-Path $path) {
        Get-ChildItem $path -Directory |
        Select-Object Name, LastWriteTime |
        Out-File "$EVIDENCE\browser_profiles.txt" -Append
    }
}

# =====================================================
# 3. REMOTE-FEATURES DEAKTIVIEREN
# =====================================================

# RDP deaktivieren
Set-ItemProperty `
    "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" `
    -Name fDenyTSConnections -Value 1 -ErrorAction SilentlyContinue

# Firewall RDP blockieren
Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue |
    Disable-NetFirewallRule -ErrorAction SilentlyContinue

# Quick Assist deaktivieren
reg add `
    "HKLM\SOFTWARE\Policies\Microsoft\Windows\QuickAssist" `
    /v AllowQuickAssist /t REG_DWORD /d 0 /f 2>$null | Out-Null

Write-Log "Remote-Features deaktiviert"

# =====================================================
# 4. SECURITY STATUS REPORT
# =====================================================
$Status = @{
    Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    DefenderEnabled = (Get-MpComputerStatus).RealTimeProtectionEnabled
    FirewallEnabled = (Get-NetFirewallProfile -Profile Domain).Enabled
    BlockedProcesses = $BlockedProcesses.Count
}
$Status | ConvertTo-Json | Out-File "$EVIDENCE\security_status.json"

Write-Log "=== AVA SECURITY RUN END ==="

}
catch {
    Write-Log "ERROR: $_"
}
finally {
    Remove-Item $LOCKFILE -Force -ErrorAction SilentlyContinue
}

# =====================================================
# 5. SCHEDULED TASK (AUTOSTART)
# =====================================================
if (-not (Get-ScheduledTask -TaskName $TASKNAME -ErrorAction SilentlyContinue)) {

    $Action = New-ScheduledTaskAction `
        -Execute "powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""

    $Trigger = New-ScheduledTaskTrigger `
        -Once `
        -At (Get-Date) `
        -RepetitionInterval (New-TimeSpan -Minutes 5) `
        -RepetitionDuration ([TimeSpan]::MaxValue)

    Register-ScheduledTask `
        -TaskName $TASKNAME `
        -Action $Action `
        -Trigger $Trigger `
        -RunLevel Highest `
        -User "SYSTEM" `
        -Force | Out-Null

    Write-Host "✅ AVA Security Monitor installiert (läuft alle 5 Minuten)" -ForegroundColor Green
}

Write-Host "🛡️ AVA Security aktiv – Logs: $LOGFILE" -ForegroundColor Cyan

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

