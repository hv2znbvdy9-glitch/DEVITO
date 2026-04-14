#requires -RunAsAdministrator

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ------------------------------------------------------------
# AVA - Sicherungs- und Protokollsystem
# Rein lokale, defensive Demo-/Überwachungslogik
# ------------------------------------------------------------

$script:AvaRoot = 'C:\AVA'
$script:LogFile = Join-Path $script:AvaRoot 'ActivityLog.txt'
$script:ProtectedResources = @('Energie', 'Daten', 'Material')
$script:ReturnQueue = New-Object System.Collections.Generic.List[string]
$script:SecureMode = $true

# ------------------------------------------------------------
# Initialisierung
# ------------------------------------------------------------
function Initialize-AVAEnvironment {
    if (-not (Test-Path -Path $script:AvaRoot)) {
        New-Item -ItemType Directory -Path $script:AvaRoot -Force | Out-Null
        Write-Host "AVA-Verzeichnis erstellt: $($script:AvaRoot)" -ForegroundColor Cyan
    }

    if (-not (Test-Path -Path $script:LogFile)) {
        New-Item -ItemType File -Path $script:LogFile -Force | Out-Null
    }
}

# ------------------------------------------------------------
# Logging
# ------------------------------------------------------------
function Log-Activity {
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('INFO','WARN','ALERT','ERROR')]
        [string]$Level = 'INFO'
    )

    Initialize-AVAEnvironment

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = '{0} [{1}] {2}' -f $timestamp, $Level, $Message

    Add-Content -Path $script:LogFile -Value $logEntry
    Write-Host $logEntry
}

# ------------------------------------------------------------
# Rückführungsliste verwalten
# ------------------------------------------------------------
function Add-ReturnQueue {
    param(
        [Parameter(Mandatory)]
        [string]$ResourceName
    )

    if (-not $script:ReturnQueue.Contains($ResourceName)) {
        $script:ReturnQueue.Add($ResourceName)
        Write-Host "Ressource '$ResourceName' zur Rückführungsliste hinzugefügt." -ForegroundColor Yellow
        Log-Activity -Level 'WARN' -Message "Rückführung angestoßen: $ResourceName"
    }
    else {
        Log-Activity -Level 'INFO' -Message "Ressource bereits in Rückführungsliste: $ResourceName"
    }
}

# ------------------------------------------------------------
# Sicheren Modus aktivieren
# ------------------------------------------------------------
function Enable-SecureMode {
    if ($script:SecureMode) {
        Write-Host "Sicherer Modus ist aktiv. Unbefugte Aktivitäten werden lokal protokolliert." -ForegroundColor Magenta
        Log-Activity -Level 'INFO' -Message 'Sicherer Modus aktiviert.'
    }
    else {
        Write-Host "Sicherer Modus ist deaktiviert." -ForegroundColor Red
        Log-Activity -Level 'WARN' -Message 'Sicherer Modus ist deaktiviert.'
    }
}

# ------------------------------------------------------------
# Ressourcen überwachen
# Demo-Modus = simuliert Vorfall
# ForceBreach = löst absichtlich einen Testfall aus
# ------------------------------------------------------------
function Monitor-Resource {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ResourceName,

        [switch]$DemoMode,
        [switch]$ForceBreach
    )

    Write-Host "Überwache Ressource: $ResourceName" -ForegroundColor Cyan
    Log-Activity -Level 'INFO' -Message "Überwachung begonnen: $ResourceName"

    Start-Sleep -Seconds 1

    $breachDetected = $false

    if ($ForceBreach) {
        $breachDetected = $true
    }
    elseif ($DemoMode) {
        $breachDetected = ([bool](Get-Random -Minimum 0 -Maximum 2))
    }

    if ($breachDetected) {
        Log-Activity -Level 'ALERT' -Message "Verdächtige Aktivität erkannt bei Ressource: $ResourceName"
        Add-ReturnQueue -ResourceName $ResourceName
    }
    else {
        Log-Activity -Level 'INFO' -Message "Keine Auffälligkeit bei Ressource: $ResourceName"
    }
}

# ------------------------------------------------------------
# Rückführung durchführen
# ------------------------------------------------------------
function Execute-Return {
    if ($script:ReturnQueue.Count -eq 0) {
        Log-Activity -Level 'INFO' -Message 'Keine Ressourcen zur Rückführung vorhanden.'
        return
    }

    Write-Host "Starte Rückführung aller registrierten Ressourcen..." -ForegroundColor Green
    Log-Activity -Level 'WARN' -Message "Rückführung gestartet für $($script:ReturnQueue.Count) Ressource(n)."

    foreach ($resource in $script:ReturnQueue) {
        Write-Host "Rückführung: $resource wird an den Eigentümer zurückgeführt." -ForegroundColor Green
        Log-Activity -Level 'INFO' -Message "Ressource erfolgreich zurückgeführt: $resource"
    }

    $script:ReturnQueue.Clear()
    Log-Activity -Level 'INFO' -Message 'Rückführungsliste geleert.'
}

# ------------------------------------------------------------
# Status anzeigen
# ------------------------------------------------------------
function Get-AVAStatus {
    [pscustomobject]@{
        AvaRoot            = $script:AvaRoot
        LogFile            = $script:LogFile
        SecureMode         = $script:SecureMode
        ProtectedResources = ($script:ProtectedResources -join ', ')
        ReturnQueueCount   = $script:ReturnQueue.Count
    }
}

# ------------------------------------------------------------
# Hauptlogik
# ------------------------------------------------------------
function Start-AVA-System {
    [CmdletBinding()]
    param(
        [switch]$DemoMode,
        [string[]]$ForceBreachFor = @()
    )

    Initialize-AVAEnvironment

    Write-Host "Starte AVA-System..." -ForegroundColor Green
    Log-Activity -Level 'INFO' -Message 'AVA-System gestartet.'

    Enable-SecureMode

    foreach ($resource in $script:ProtectedResources) {
        $forceThis = $ForceBreachFor -contains $resource
        Monitor-Resource -ResourceName $resource -DemoMode:$DemoMode -ForceBreach:$forceThis
    }

    Execute-Return

    Log-Activity -Level 'INFO' -Message 'AVA-Systemüberprüfung abgeschlossen.'
    Write-Host "AVA-System abgeschlossen. Protokoll gespeichert: $($script:LogFile)" -ForegroundColor Cyan
}

# ------------------------------------------------------------
# Start
# ------------------------------------------------------------
Start-AVA-System -DemoMode
Get-AVAStatus | Format-List
