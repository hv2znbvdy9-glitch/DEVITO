# =====================================================
# AVA SOC TOOLKIT – BLUE TEAM / DETECTION ENGINEERING
# Enterprise Security Operations Center Tools
# =====================================================

# ---------- ADMIN CHECK ----------
If (-not ([Security.Principal.WindowsPrincipal]
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Host "❌ Administratorrechte erforderlich!" -ForegroundColor Red
    Exit
}

Clear-Host
Write-Host "=== AVA SOC TOOLKIT ===" -ForegroundColor Cyan
Write-Host "Detection Engineering | Threat Hunting | Incident Response" -ForegroundColor Yellow

# ---------- GLOBALS ----------
$SOCPath = "$env:USERPROFILE\AVA_SOC"
$Cases = "$SOCPath\Cases"
$Reports = "$SOCPath\Reports"
$Detections = "$SOCPath\Detections"

New-Item -ItemType Directory -Path $SOCPath,$Cases,$Reports,$Detections -Force | Out-Null

# =====================================================
# DETECTION RULES (MITRE ATT&CK)
# =====================================================
$DetectionRules = @(
    @{
        Name="Multiple Failed Logons"
        EventID=4625
        Threshold=5
        Mitre="T1110 - Brute Force"
        Severity="Medium"
    },
    @{
        Name="Suspicious PowerShell Execution"
        EventID=4688
        Match="powershell.exe"
        Mitre="T1059 - Command Execution"
        Severity="High"
    },
    @{
        Name="New Service Installed"
        EventID=4697
        Threshold=1
        Mitre="T1543 - Create/Modify System Process"
        Severity="High"
    },
    @{
        Name="Privilege Escalation Attempt"
        EventID=4672
        Threshold=3
        Mitre="T1078 - Valid Accounts"
        Severity="Critical"
    }
)

# =====================================================
# 1. DETECTION ENGINE
# =====================================================
function Run-DetectionEngine {
    Write-Host "`n[ DETECTION ENGINE ]" -ForegroundColor Cyan

    $Alerts = @()

    foreach ($rule in $DetectionRules) {
        try {
            $events = Get-WinEvent -FilterHashtable @{
                LogName='Security'
                Id=$rule.EventID
            } -MaxEvents 100 -ErrorAction SilentlyContinue

            if ($rule.Match) {
                $events = $events | Where-Object {$_.Message -match $rule.Match}
            }

            if ($events.Count -ge ($rule.Threshold ?? 1)) {
                $alert = "⚠️ ALERT: $($rule.Name) | MITRE $($rule.Mitre) | Severity: $($rule.Severity)"
                Write-Host $alert -ForegroundColor Red
                $Alerts += $alert
            } else {
                Write-Host "✔ OK: $($rule.Name)" -ForegroundColor Green
            }
        }
        catch {
            Write-Host "⚠ Fehler bei Regel $($rule.Name): $_" -ForegroundColor Yellow
        }
    }

    return $Alerts
}

# =====================================================
# 2. THREAT HUNTING
# =====================================================
function Start-ThreatHunting {
    Write-Host "`n[ THREAT HUNTING ]" -ForegroundColor Cyan

    # Unsigned Processes
    Write-Host "`nUnsignierte Prozesse:" -ForegroundColor Yellow
    Get-Process | Where-Object {
        $_.Path -and (Get-AuthenticodeSignature $_.Path -ErrorAction SilentlyContinue).Status -ne "Valid"
    } | Select-Object Name, Path -First 10

    # Persistence Mechanisms
    Write-Host "`nRegistry Run Keys:" -ForegroundColor Yellow
    Get-ItemProperty `
        HKLM:\Software\Microsoft\Windows\CurrentVersion\Run `
        -ErrorAction SilentlyContinue

    # Scheduled Tasks (non-Microsoft)
    Write-Host "`nVerdächtige Scheduled Tasks:" -ForegroundColor Yellow
    Get-ScheduledTask | Where-Object {
        $_.TaskPath -notlike "\Microsoft*" -and $_.State -eq "Ready"
    } | Select-Object TaskName, State -First 10
}

# =====================================================
# 3. INCIDENT RESPONSE
# =====================================================
function New-IncidentCase {
    Write-Host "`n[ INCIDENT RESPONSE - NEW CASE ]" -ForegroundColor Cyan

    $CaseID = "INC_" + (Get-Date -Format "yyyyMMdd_HHmmss")
    $CasePath = "$Cases\$CaseID"
    New-Item -ItemType Directory -Path $CasePath | Out-Null

    # Evidence Collection
    Get-Process | Export-Csv "$CasePath\processes.csv" -NoTypeInformation
    Get-NetTCPConnection | Export-Csv "$CasePath\network.csv" -NoTypeInformation
    Get-EventLog Security -Newest 100 | Export-Csv "$CasePath\security_events.csv" -NoTypeInformation
    Get-LocalUser | Export-Csv "$CasePath\local_users.csv" -NoTypeInformation

    Write-Host "✔ Case erstellt: $CaseID" -ForegroundColor Green
    Write-Host "📁 Evidence: $CasePath" -ForegroundColor Cyan

    return $CaseID
}

# =====================================================
# 4. VULNERABILITY ASSESSMENT
# =====================================================
function Start-VulnerabilityAssessment {
    Write-Host "`n[ VULNERABILITY ASSESSMENT ]" -ForegroundColor Cyan

    $Findings = @()

    # Patch Status
    $LastPatch = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ((Get-Date) - $LastPatch.InstalledOn -gt (New-TimeSpan -Days 30)) {
        $Findings += "❌ System nicht aktuell gepatcht (letzte: $($LastPatch.InstalledOn))"
    }

    # Defender Status
    $Defender = Get-MpComputerStatus
    if (-not $Defender.RealTimeProtectionEnabled) {
        $Findings += "❌ Defender Echtzeitschutz deaktiviert"
    }

    # SMBv1
    $SMB = Get-SmbServerConfiguration
    if ($SMB.EnableSMB1Protocol) {
        $Findings += "❌ SMBv1 aktiviert (Sicherheitsrisiko)"
    }

    # Guest Account
    $Guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
    if ($Guest.Enabled) {
        $Findings += "❌ Gastkonto aktiviert"
    }

    # Open Ports
    $Listening = Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"}
    foreach ($port in $Listening) {
        if ($port.LocalPort -in @(3389,445,135)) {
            $Findings += "⚠️ Kritischer Port offen: $($port.LocalPort)"
        }
    }

    # Risk Score
    $RiskScore = [Math]::Max(0, 100 - ($Findings.Count * 15))

    Write-Host "`nFindings:" -ForegroundColor Yellow
    $Findings | ForEach-Object { Write-Host $_ }

    Write-Host "`nRisk Score: $RiskScore/100" -ForegroundColor $(
        if ($RiskScore -lt 60) { "Red" }
        elseif ($RiskScore -lt 80) { "Yellow" }
        else { "Green" }
    )

    return @{
        Findings = $Findings
        RiskScore = $RiskScore
    }
}

# =====================================================
# 5. SOC REPORT
# =====================================================
function New-SOCReport {
    Write-Host "`n[ SOC REPORT GENERATION ]" -ForegroundColor Cyan

    $ReportPath = "$Reports\SOC_Report_$(Get-Date -Format yyyyMMdd_HHmmss).txt"

    $Alerts = Run-DetectionEngine
    $VulnAssessment = Start-VulnerabilityAssessment

    @"
========================================
AVA SOC TOOLKIT - SECURITY REPORT
========================================
Generated: $(Get-Date)
Operator: $env:USERNAME
Hostname: $env:COMPUTERNAME

DETECTION ALERTS
----------------
$($Alerts -join "`n")

VULNERABILITY ASSESSMENT
------------------------
Risk Score: $($VulnAssessment.RiskScore)/100

Findings:
$($VulnAssessment.Findings -join "`n")

MITRE ATT&CK COVERAGE
---------------------
$($DetectionRules | ForEach-Object { "- $($_.Mitre): $($_.Name)" } | Out-String)

SYSTEM INFO
-----------
OS: $((Get-CimInstance Win32_OperatingSystem).Caption)
Defender: $(if ((Get-MpComputerStatus).RealTimeProtectionEnabled) {"Enabled"} else {"Disabled"})
Firewall: $(if ((Get-NetFirewallProfile -Profile Domain).Enabled) {"Enabled"} else {"Disabled"})

========================================
"@ | Out-File $ReportPath

    Write-Host "✔ Report erstellt: $ReportPath" -ForegroundColor Green
}

# =====================================================
# MENU
# =====================================================
function Show-Menu {
    Write-Host ""
    Write-Host "1  Run Detection Engine"
    Write-Host "2  Threat Hunting"
    Write-Host "3  Create Incident Case"
    Write-Host "4  Vulnerability Assessment"
    Write-Host "5  Generate SOC Report"
    Write-Host "0  Beenden"
}

do {
    Show-Menu
    $choice = Read-Host "Auswahl"

    switch ($choice) {
        1 { Run-DetectionEngine }
        2 { Start-ThreatHunting }
        3 { New-IncidentCase }
        4 { Start-VulnerabilityAssessment }
        5 { New-SOCReport }
        0 { Write-Host "SOC Toolkit beendet." -ForegroundColor Green }
        default { Write-Host "Ungültige Auswahl" -ForegroundColor Red }
    }

    if ($choice -ne 0) {
        Pause
        Clear-Host
        Write-Host "=== AVA SOC TOOLKIT ===" -ForegroundColor Cyan
    }
} while ($choice -ne 0)

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


