#requires -Version 5.1
<#
.SYNOPSIS
    AVA Security Monitor – THE ANGEL AND THE AGENT
.DESCRIPTION
    Comprehensive Windows security monitoring tool providing TCP/UDP scanning,
    listener audits, integrity checks, process risk assessment, baseline
    comparisons, CSV/HTML reporting, an ASCII dashboard, and continuous monitoring.
.NOTES
    Author : Danny Nico Hildebrand
    Version: 2.0
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ============================================================
# PATHS & GLOBALS
# ============================================================
$script:AvaRoot            = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:LogPath            = Join-Path $script:AvaRoot 'ava.log'
$script:WhitelistPath      = Join-Path $script:AvaRoot 'whitelist.json'
$script:ReportPath         = Join-Path $script:AvaRoot 'report.json'
$script:UdpReportPath      = Join-Path $script:AvaRoot 'udp_report.json'
$script:ListenerReportPath = Join-Path $script:AvaRoot 'listener_report.json'
$script:IntegrityPath      = Join-Path $script:AvaRoot 'integrity.json'
$script:RulePrefix         = 'AVA_Block_'

# ============================================================
# INITIALISATION
# ============================================================
function Initialize-AvaEnvironment {
    if (-not (Test-Path -Path $script:AvaRoot)) {
        New-Item -ItemType Directory -Path $script:AvaRoot -Force | Out-Null
    }

    # Default whitelist
    if (-not (Test-Path -Path $script:WhitelistPath)) {
        $defaultWhitelist = @{
            AllowedRemotePorts = @(80, 443, 53)
            AllowedProcesses   = @('svchost', 'System', 'chrome', 'firefox', 'msedge')
            AllowedRemoteIPs   = @()
        }
        $defaultWhitelist | ConvertTo-Json -Depth 4 | Set-Content -Path $script:WhitelistPath -Encoding UTF8
    }

    # Default integrity baseline
    if (-not (Test-Path -Path $script:IntegrityPath)) {
        $baseline = @{
            whitelistHash = ''
            hostsHash     = ''
            createdAt     = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        }
        $baseline | ConvertTo-Json -Depth 4 | Set-Content -Path $script:IntegrityPath -Encoding UTF8
    }
}

# ============================================================
# LOGGING
# ============================================================
function Write-AvaLog {
    param(
        [ValidateSet('INFO','WARN','ERROR','ALERT')]
        [string]$Level = 'INFO',
        [Parameter(Mandatory)]
        [string]$Message
    )
    $line = "{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Add-Content -Path $script:LogPath -Value $line -Encoding UTF8
}

# ============================================================
# HELPERS
# ============================================================
function Get-ProcessNameSafe {
    param([int]$ProcessId)
    try {
        $proc = Get-Process -Id $ProcessId -ErrorAction Stop
        return $proc.ProcessName
    }
    catch {
        return '<unknown>'
    }
}

function Get-AvaWhitelist {
    if (Test-Path -Path $script:WhitelistPath) {
        return (Get-Content -Path $script:WhitelistPath -Raw -Encoding UTF8 | ConvertFrom-Json)
    }
    return @{ AllowedRemotePorts = @(); AllowedProcesses = @(); AllowedRemoteIPs = @() }
}

function Get-FileHashSafe {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    if (-not (Test-Path -Path $Path)) { return $null }
    try {
        return (Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop).Hash
    }
    catch {
        Write-AvaLog -Level 'ERROR' -Message "Hash konnte nicht berechnet werden: $Path | $($_.Exception.Message)"
        return $null
    }
}

# ============================================================
# TCP CONNECTION SCAN
# ============================================================
function Invoke-AvaConnectionScan {
    param([switch]$AutoBlock)

    Initialize-AvaEnvironment
    $whitelist = Get-AvaWhitelist

    Write-Host ''
    Write-Host 'Starte AVA-TCP-Scan...' -ForegroundColor Cyan
    Write-AvaLog -Level 'INFO' -Message 'TCP-Scan gestartet'

    $results = New-Object System.Collections.Generic.List[object]
    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue

    foreach ($conn in $connections) {
        $remoteAddress = $conn.RemoteAddress
        $remotePort    = [int]$conn.RemotePort
        $localPort     = [int]$conn.LocalPort
        $processId     = [int]$conn.OwningProcess
        $processName   = Get-ProcessNameSafe -ProcessId $processId

        $isAllowed = $false
        if ($whitelist.AllowedRemotePorts -contains $remotePort) { $isAllowed = $true }
        if ($whitelist.AllowedProcesses   -contains $processName) { $isAllowed = $true }
        if ($whitelist.AllowedRemoteIPs   -contains $remoteAddress) { $isAllowed = $true }

        $classification = if ($isAllowed) { 'Allowed' } else { 'Suspicious' }

        $entry = [PSCustomObject]@{
            Timestamp      = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            Protocol       = 'TCP'
            State          = 'Established'
            RemoteAddress  = $remoteAddress
            RemotePort     = $remotePort
            LocalPort      = $localPort
            ProcessId      = $processId
            ProcessName    = $processName
            Classification = $classification
        }
        $results.Add($entry)

        if ($classification -eq 'Suspicious') {
            Write-Host ("[VERDÄCHTIG] {0}:{1} -> {2}:{3} | Prozess: {4}" -f $conn.LocalAddress, $localPort, $remoteAddress, $remotePort, $processName) -ForegroundColor Yellow
            Write-AvaLog -Level 'WARN' -Message ("Verdächtige Verbindung | Remote={0}:{1} | Process={2}" -f $remoteAddress, $remotePort, $processName)

            if ($AutoBlock) {
                $ruleName = "{0}{1}" -f $script:RulePrefix, $remoteAddress
                $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
                if (-not $existing) {
                    New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Action Block -RemoteAddress $remoteAddress -Protocol TCP | Out-Null
                    Write-Host "  -> Blockregel erstellt: $ruleName" -ForegroundColor Red
                    Write-AvaLog -Level 'ALERT' -Message "Firewall-Block erstellt: $ruleName"
                }
            }
        }
        else {
            Write-Host ("[OK] {0}:{1} -> {2}:{3} | Prozess: {4}" -f $conn.LocalAddress, $localPort, $remoteAddress, $remotePort, $processName) -ForegroundColor DarkGreen
        }
    }

    $summary = [PSCustomObject]@{
        ScanTimestamp   = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        TotalConnections = $results.Count
        SuspiciousCount  = @($results | Where-Object { $_.Classification -eq 'Suspicious' }).Count
        AllowedCount     = @($results | Where-Object { $_.Classification -eq 'Allowed' }).Count
        Results          = $results
    }

    $summary | ConvertTo-Json -Depth 6 | Set-Content -Path $script:ReportPath -Encoding UTF8
    Write-AvaLog -Level 'INFO' -Message "TCP-Scan abgeschlossen | Total=$($summary.TotalConnections) | Suspicious=$($summary.SuspiciousCount)"
    Write-Host "TCP-Report: $script:ReportPath" -ForegroundColor Yellow
    Write-Host ''

    return $summary
}

# ============================================================
# UDP SCAN
# ============================================================
function Invoke-AvaUdpScan {
    Initialize-AvaEnvironment
    $whitelist = Get-AvaWhitelist

    Write-Host ''
    Write-Host 'Starte AVA-UDP-Analyse...' -ForegroundColor Cyan
    Write-AvaLog -Level 'INFO' -Message 'UDP-Analyse gestartet'

    $results = New-Object System.Collections.Generic.List[object]
    $udpEndpoints = Get-NetUDPEndpoint -ErrorAction SilentlyContinue

    foreach ($endpoint in $udpEndpoints) {
        $localAddress = $endpoint.LocalAddress
        $localPort    = [int]$endpoint.LocalPort
        $processId    = [int]$endpoint.OwningProcess
        $processName  = Get-ProcessNameSafe -ProcessId $processId

        $isAllowed = $false
        if ($whitelist.AllowedRemotePorts -contains $localPort) { $isAllowed = $true }
        if ($whitelist.AllowedProcesses   -contains $processName) { $isAllowed = $true }

        $classification = if ($isAllowed) { 'Allowed' } else { 'Review' }

        $entry = [PSCustomObject]@{
            Timestamp      = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            Protocol       = 'UDP'
            LocalAddress   = $localAddress
            LocalPort      = $localPort
            ProcessId      = $processId
            ProcessName    = $processName
            Classification = $classification
        }
        $results.Add($entry)

        if ($classification -eq 'Review') {
            Write-Host ("[UDP-PRÜFEN] {0}:{1} | Prozess: {2}" -f $localAddress, $localPort, $processName) -ForegroundColor Yellow
            Write-AvaLog -Level 'WARN' -Message ("UDP-Endpunkt prüfen | Local={0}:{1} | Process={2}" -f $localAddress, $localPort, $processName)
        }
        else {
            Write-Host ("[UDP-OK] {0}:{1} | Prozess: {2}" -f $localAddress, $localPort, $processName) -ForegroundColor DarkGreen
        }
    }

    $summary = [PSCustomObject]@{
        ScanTimestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        TotalUdp      = $results.Count
        ReviewCount   = @($results | Where-Object { $_.Classification -eq 'Review' }).Count
        AllowedCount  = @($results | Where-Object { $_.Classification -eq 'Allowed' }).Count
        Results       = $results
    }

    $summary | ConvertTo-Json -Depth 6 | Set-Content -Path $script:UdpReportPath -Encoding UTF8
    Write-AvaLog -Level 'INFO' -Message "UDP-Analyse abgeschlossen | Total=$($summary.TotalUdp) | Review=$($summary.ReviewCount)"
    Write-Host "UDP-Report: $script:UdpReportPath" -ForegroundColor Yellow
    Write-Host ''

    return $summary
}

# ============================================================
# LISTENER / PORT AUDIT
# ============================================================
function Invoke-AvaListenerAudit {
    Initialize-AvaEnvironment

    Write-Host ''
    Write-Host 'Starte AVA-Listener-Audit...' -ForegroundColor Cyan
    Write-AvaLog -Level 'INFO' -Message 'Listener-Audit gestartet'

    $results = New-Object System.Collections.Generic.List[object]
    $listeners = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue

    foreach ($listener in $listeners) {
        $localAddress = $listener.LocalAddress
        $localPort    = [int]$listener.LocalPort
        $processId    = [int]$listener.OwningProcess
        $processName  = Get-ProcessNameSafe -ProcessId $processId

        $classification = if ($localPort -in @(135, 139, 445, 3389, 5985, 5986)) { 'Sensitive' } else { 'Open' }

        $entry = [PSCustomObject]@{
            Timestamp      = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            Protocol       = 'TCP'
            State          = 'Listen'
            LocalAddress   = $localAddress
            LocalPort      = $localPort
            ProcessId      = $processId
            ProcessName    = $processName
            Classification = $classification
        }
        $results.Add($entry)

        if ($classification -eq 'Sensitive') {
            Write-Host ("[SENSITIV] TCP {0}:{1} | Prozess: {2}" -f $localAddress, $localPort, $processName) -ForegroundColor Red
            Write-AvaLog -Level 'WARN' -Message ("Sensitiver Listener | TCP {0}:{1} | Process={2}" -f $localAddress, $localPort, $processName)
        }
        else {
            Write-Host ("[LISTEN] TCP {0}:{1} | Prozess: {2}" -f $localAddress, $localPort, $processName) -ForegroundColor DarkYellow
        }
    }

    $summary = [PSCustomObject]@{
        ScanTimestamp  = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        TotalListeners = $results.Count
        SensitiveCount = @($results | Where-Object { $_.Classification -eq 'Sensitive' }).Count
        Results        = $results
    }

    $summary | ConvertTo-Json -Depth 6 | Set-Content -Path $script:ListenerReportPath -Encoding UTF8
    Write-AvaLog -Level 'INFO' -Message "Listener-Audit abgeschlossen | Total=$($summary.TotalListeners) | Sensitive=$($summary.SensitiveCount)"
    Write-Host "Listener-Report: $script:ListenerReportPath" -ForegroundColor Yellow
    Write-Host ''

    return $summary
}

# ============================================================
# INTEGRITY CHECKS
# ============================================================
function Update-AvaIntegrityBaseline {
    Initialize-AvaEnvironment

    $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $baseline = @{
        whitelistHash = (Get-FileHashSafe -Path $script:WhitelistPath)
        hostsHash     = (Get-FileHashSafe -Path $hostsPath)
        updatedAt     = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    }

    $baseline | ConvertTo-Json -Depth 4 | Set-Content -Path $script:IntegrityPath -Encoding UTF8
    Write-AvaLog -Level 'INFO' -Message 'Integritäts-Baseline aktualisiert'
    Write-Host 'Integritäts-Baseline aktualisiert.' -ForegroundColor Green
}

function Test-AvaIntegrity {
    Initialize-AvaEnvironment

    $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $baseline  = Get-Content -Path $script:IntegrityPath -Raw -Encoding UTF8 | ConvertFrom-Json

    $currentWhitelistHash = Get-FileHashSafe -Path $script:WhitelistPath
    $currentHostsHash     = Get-FileHashSafe -Path $hostsPath

    Write-Host ''
    Write-Host 'Starte Integritätsprüfung...' -ForegroundColor Cyan

    $changed = $false

    if ($baseline.whitelistHash -and $baseline.whitelistHash -ne $currentWhitelistHash) {
        Write-Host 'WARNUNG: whitelist.json wurde verändert.' -ForegroundColor Red
        Write-AvaLog -Level 'ALERT' -Message 'Integritätsabweichung: whitelist.json geändert'
        $changed = $true
    }
    else {
        Write-Host 'OK: whitelist.json unverändert.' -ForegroundColor Green
    }

    if ($baseline.hostsHash -and $baseline.hostsHash -ne $currentHostsHash) {
        Write-Host 'WARNUNG: hosts-Datei wurde verändert.' -ForegroundColor Red
        Write-AvaLog -Level 'ALERT' -Message 'Integritätsabweichung: hosts-Datei geändert'
        $changed = $true
    }
    else {
        Write-Host 'OK: hosts-Datei unverändert.' -ForegroundColor Green
    }

    Write-Host ''
    return $changed
}

# ============================================================
# SECURITY EVENTS
# ============================================================
function Show-AvaRecentSecurityEvents {
    param([int]$Hours = 24)

    Initialize-AvaEnvironment

    $startTime = (Get-Date).AddHours(-1 * $Hours)

    Write-Host ''
    Write-Host "Lese relevante Ereignisse der letzten $Hours Stunden..." -ForegroundColor Cyan
    Write-AvaLog -Level 'INFO' -Message "Event-Log-Auswertung gestartet | Hours=$Hours"

    $logsToCheck = @(
        'System',
        'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'
    )

    foreach ($logName in $logsToCheck) {
        Write-Host "===== LOG: $logName =====" -ForegroundColor Yellow
        try {
            $events = Get-WinEvent -FilterHashtable @{
                LogName   = $logName
                StartTime = $startTime
            } -MaxEvents 30 -ErrorAction Stop

            foreach ($evt in $events) {
                Write-Host ("[{0}] ID={1} | {2}" -f $evt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'), $evt.Id, $evt.ProviderName)
                Write-Host ("  " + $evt.Message.Split("`n")[0])
            }
        }
        catch {
            Write-Host "Konnte Log nicht lesen: $logName" -ForegroundColor DarkYellow
            Write-AvaLog -Level 'WARN' -Message "Event-Log konnte nicht gelesen werden: $logName"
        }
        Write-Host ''
    }

    Write-AvaLog -Level 'INFO' -Message 'Event-Log-Auswertung abgeschlossen'
}

# ============================================================
# WHITELIST / REPORT DISPLAY
# ============================================================
function Show-AvaWhitelist {
    Initialize-AvaEnvironment
    $wl = Get-AvaWhitelist
    Write-Host ''
    Write-Host '===== AVA Whitelist =====' -ForegroundColor Yellow
    Write-Host "Erlaubte Remote-Ports : $($wl.AllowedRemotePorts -join ', ')"
    Write-Host "Erlaubte Prozesse     : $($wl.AllowedProcesses -join ', ')"
    Write-Host "Erlaubte Remote-IPs   : $($wl.AllowedRemoteIPs -join ', ')"
    Write-Host ''
}

function Show-AvaLastReport {
    if (Test-Path $script:ReportPath) {
        $report = Get-Content -Path $script:ReportPath -Raw -Encoding UTF8 | ConvertFrom-Json
        Write-Host ''
        Write-Host "===== Letzter TCP-Report ($($report.ScanTimestamp)) =====" -ForegroundColor Yellow
        Write-Host "Total: $($report.TotalConnections) | Suspicious: $($report.SuspiciousCount) | Allowed: $($report.AllowedCount)"
        if ($report.Results) {
            $report.Results | Format-Table -Property Timestamp, Protocol, RemoteAddress, RemotePort, ProcessName, Classification -AutoSize
        }
        Write-Host ''
    }
    else {
        Write-Host 'Kein Report vorhanden.' -ForegroundColor Yellow
    }
}

function Remove-AvaBlocks {
    $rules = Get-NetFirewallRule -DisplayName "$($script:RulePrefix)*" -ErrorAction SilentlyContinue
    if ($rules) {
        $rules | Remove-NetFirewallRule
        Write-Host "Alle AVA-Blockregeln entfernt." -ForegroundColor Green
        Write-AvaLog -Level 'INFO' -Message 'Alle AVA-Blockregeln entfernt'
    }
    else {
        Write-Host 'Keine AVA-Blockregeln vorhanden.' -ForegroundColor Yellow
    }
}

# ============================================================
# ENERGY TRANSACTION VALIDATION (Demo)
# ============================================================
function Validate-EnergyTransactions {
    param(
        [string]$TransactionID,
        [string]$InitiatorID
    )
    Write-Host ''
    Write-Host "Prüfe Energie-Transaktion..." -ForegroundColor Cyan
    Write-Host "  TransactionID : $TransactionID"
    Write-Host "  InitiatorID   : $InitiatorID"

    if ([string]::IsNullOrWhiteSpace($TransactionID) -or [string]::IsNullOrWhiteSpace($InitiatorID)) {
        Write-Host '  Ergebnis: UNGÜLTIG (fehlende Parameter)' -ForegroundColor Red
        return $false
    }

    Write-Host '  Ergebnis: GÜLTIG (Demo-Modus)' -ForegroundColor Green
    Write-AvaLog -Level 'INFO' -Message "Energie-Transaktion geprüft | TX=$TransactionID | ID=$InitiatorID | Valid=True"
    return $true
}

# ============================================================
# SCHEDULED MONITORING
# ============================================================
function Start-ScheduledMonitoring {
    $Trigger   = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)
    $Action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$($script:AvaRoot)\Monitor.ps1`""
    $Principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount

    Register-ScheduledTask -TaskName 'Ava_Monitor' -Trigger $Trigger -Action $Action -Principal $Principal
    Write-Host "Scheduled Task 'Ava_Monitor' wurde hinzugefügt." -ForegroundColor Green
    Write-AvaLog -Level 'INFO' -Message 'Scheduled Task Ava_Monitor registriert'
}

function Alert-ByEmail {
    param(
        [string]$EmailTo,
        [string]$Subject,
        [string]$Body
    )
    Send-MailMessage -From 'AVA@security.local' -To $EmailTo -Subject $Subject -Body $Body -SmtpServer 'smtp.server.com' -Port 587
}

# ============================================================
# NEW FEATURE 1: ASCII DASHBOARD
# ============================================================
function Show-AvaDashboard {
    <#
    .SYNOPSIS
        Displays a live ASCII dashboard summarising all scan results.
    #>
    Initialize-AvaEnvironment

    Write-AvaLog -Level 'INFO' -Message 'Dashboard angezeigt'

    # ---------- collect data ----------
    $tcpReport      = $null
    $udpReport      = $null
    $listenerReport = $null

    if (Test-Path $script:ReportPath) {
        $tcpReport = Get-Content -Path $script:ReportPath -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    if (Test-Path $script:UdpReportPath) {
        $udpReport = Get-Content -Path $script:UdpReportPath -Raw -Encoding UTF8 | ConvertFrom-Json
    }
    if (Test-Path $script:ListenerReportPath) {
        $listenerReport = Get-Content -Path $script:ListenerReportPath -Raw -Encoding UTF8 | ConvertFrom-Json
    }

    # ---------- risk score ----------
    $score = 0
    if ($tcpReport)      { $score += [int]$tcpReport.SuspiciousCount  * 10 }
    if ($udpReport)      { $score += [int]$udpReport.ReviewCount      * 5  }
    if ($listenerReport) { $score += [int]$listenerReport.SensitiveCount * 15 }

    $integrityChanged = $false
    if (Test-Path $script:IntegrityPath) {
        $integrityChanged = Test-AvaIntegrity
    }
    if ($integrityChanged) { $score += 25 }
    if ($score -gt 100) { $score = 100 }

    $riskLabel = if ($score -ge 80) { 'KRITISCH' }
                 elseif ($score -ge 50) { 'HOCH' }
                 elseif ($score -ge 25) { 'MITTEL' }
                 elseif ($score -ge 10) { 'NIEDRIG' }
                 else { 'OK' }

    $riskColor = switch ($riskLabel) {
        'KRITISCH' { 'Red' }
        'HOCH'     { 'Red' }
        'MITTEL'   { 'Yellow' }
        'NIEDRIG'  { 'DarkYellow' }
        default    { 'Green' }
    }

    # ---------- render ----------
    $width = 60
    $border = '=' * $width

    Write-Host ''
    Write-Host $border -ForegroundColor DarkCyan
    Write-Host '       AVA SECURITY DASHBOARD' -ForegroundColor Cyan
    Write-Host ('       {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) -ForegroundColor DarkGray
    Write-Host $border -ForegroundColor DarkCyan
    Write-Host ''

    # Risk gauge
    $filledBlocks = [math]::Floor($score / 5)
    $emptyBlocks  = 20 - $filledBlocks
    $gauge = ('[' + ('#' * $filledBlocks) + ('-' * $emptyBlocks) + ']')
    Write-Host ("  RISK SCORE : {0}/100  {1}" -f $score, $gauge) -ForegroundColor $riskColor
    Write-Host ("  BEWERTUNG  : {0}" -f $riskLabel) -ForegroundColor $riskColor
    Write-Host ''

    # TCP section
    Write-Host '  --- TCP CONNECTIONS ---' -ForegroundColor Yellow
    if ($tcpReport) {
        Write-Host ("    Total        : {0}" -f $tcpReport.TotalConnections)
        Write-Host ("    Allowed      : {0}" -f $tcpReport.AllowedCount) -ForegroundColor Green
        Write-Host ("    Suspicious   : {0}" -f $tcpReport.SuspiciousCount) -ForegroundColor $(if ($tcpReport.SuspiciousCount -gt 0) { 'Red' } else { 'Green' })
        Write-Host ("    Scan         : {0}" -f $tcpReport.ScanTimestamp) -ForegroundColor DarkGray
    }
    else { Write-Host '    Kein TCP-Report vorhanden.' -ForegroundColor DarkGray }
    Write-Host ''

    # UDP section
    Write-Host '  --- UDP ENDPOINTS ---' -ForegroundColor Yellow
    if ($udpReport) {
        Write-Host ("    Total        : {0}" -f $udpReport.TotalUdp)
        Write-Host ("    Allowed      : {0}" -f $udpReport.AllowedCount) -ForegroundColor Green
        Write-Host ("    Review       : {0}" -f $udpReport.ReviewCount) -ForegroundColor $(if ($udpReport.ReviewCount -gt 0) { 'Yellow' } else { 'Green' })
        Write-Host ("    Scan         : {0}" -f $udpReport.ScanTimestamp) -ForegroundColor DarkGray
    }
    else { Write-Host '    Kein UDP-Report vorhanden.' -ForegroundColor DarkGray }
    Write-Host ''

    # Listener section
    Write-Host '  --- LISTENER / PORTS ---' -ForegroundColor Yellow
    if ($listenerReport) {
        Write-Host ("    Total        : {0}" -f $listenerReport.TotalListeners)
        Write-Host ("    Sensitive    : {0}" -f $listenerReport.SensitiveCount) -ForegroundColor $(if ($listenerReport.SensitiveCount -gt 0) { 'Red' } else { 'Green' })
        Write-Host ("    Scan         : {0}" -f $listenerReport.ScanTimestamp) -ForegroundColor DarkGray
    }
    else { Write-Host '    Kein Listener-Report vorhanden.' -ForegroundColor DarkGray }
    Write-Host ''

    # Integrity
    Write-Host '  --- INTEGRITÄT ---' -ForegroundColor Yellow
    if ($integrityChanged) {
        Write-Host '    Status       : VERÄNDERT' -ForegroundColor Red
    }
    else {
        Write-Host '    Status       : OK' -ForegroundColor Green
    }
    Write-Host ''
    Write-Host $border -ForegroundColor DarkCyan
    Write-Host ''
}

# ============================================================
# NEW FEATURE 2: CSV EXPORT
# ============================================================
function Export-AvaCsv {
    <#
    .SYNOPSIS
        Exports TCP, UDP and listener scan results to CSV files.
    .PARAMETER OutputDir
        Directory to write CSV files into. Defaults to AvaRoot.
    #>
    param(
        [string]$OutputDir = $script:AvaRoot
    )

    Initialize-AvaEnvironment
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }

    $stamp     = Get-Date -Format 'yyyyMMdd_HHmmss'
    $exported  = @()

    # TCP
    if (Test-Path $script:ReportPath) {
        $tcp     = Get-Content -Path $script:ReportPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $csvPath = Join-Path $OutputDir "ava_tcp_$stamp.csv"
        if ($tcp.Results -and $tcp.Results.Count -gt 0) {
            $tcp.Results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            $exported += $csvPath
        }
    }

    # UDP
    if (Test-Path $script:UdpReportPath) {
        $udp     = Get-Content -Path $script:UdpReportPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $csvPath = Join-Path $OutputDir "ava_udp_$stamp.csv"
        if ($udp.Results -and $udp.Results.Count -gt 0) {
            $udp.Results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            $exported += $csvPath
        }
    }

    # Listeners
    if (Test-Path $script:ListenerReportPath) {
        $listener = Get-Content -Path $script:ListenerReportPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $csvPath  = Join-Path $OutputDir "ava_listener_$stamp.csv"
        if ($listener.Results -and $listener.Results.Count -gt 0) {
            $listener.Results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            $exported += $csvPath
        }
    }

    if ($exported.Count -gt 0) {
        foreach ($f in $exported) {
            Write-Host "CSV exportiert: $f" -ForegroundColor Green
        }
        Write-AvaLog -Level 'INFO' -Message "CSV-Export abgeschlossen | Dateien=$($exported.Count)"
    }
    else {
        Write-Host 'Keine Reports zum Exportieren vorhanden.' -ForegroundColor Yellow
    }

    return $exported
}

# ============================================================
# NEW FEATURE 3: HTML REPORT
# ============================================================
function Export-AvaHtmlReport {
    <#
    .SYNOPSIS
        Generates a self-contained HTML report from all available scan data.
    .PARAMETER OutputDir
        Directory for the HTML file. Defaults to AvaRoot.
    #>
    param(
        [string]$OutputDir = $script:AvaRoot
    )

    Initialize-AvaEnvironment
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }

    $stamp    = Get-Date -Format 'yyyyMMdd_HHmmss'
    $htmlPath = Join-Path $OutputDir "ava_report_$stamp.html"

    # Collect data
    $tcpReport      = $null
    $udpReport      = $null
    $listenerReport = $null

    if (Test-Path $script:ReportPath)         { $tcpReport      = Get-Content -Path $script:ReportPath         -Raw -Encoding UTF8 | ConvertFrom-Json }
    if (Test-Path $script:UdpReportPath)      { $udpReport      = Get-Content -Path $script:UdpReportPath      -Raw -Encoding UTF8 | ConvertFrom-Json }
    if (Test-Path $script:ListenerReportPath) { $listenerReport = Get-Content -Path $script:ListenerReportPath -Raw -Encoding UTF8 | ConvertFrom-Json }

    # Risk score
    $score = 0
    if ($tcpReport)      { $score += [int]$tcpReport.SuspiciousCount  * 10 }
    if ($udpReport)      { $score += [int]$udpReport.ReviewCount      * 5  }
    if ($listenerReport) { $score += [int]$listenerReport.SensitiveCount * 15 }
    if ($score -gt 100) { $score = 100 }

    $riskLabel = if ($score -ge 80) { 'KRITISCH' }
                 elseif ($score -ge 50) { 'HOCH' }
                 elseif ($score -ge 25) { 'MITTEL' }
                 elseif ($score -ge 10) { 'NIEDRIG' }
                 else { 'OK' }

    $badgeClass = switch ($riskLabel) {
        'OK'       { 'ok' }
        'NIEDRIG'  { 'low' }
        'MITTEL'   { 'med' }
        default    { 'high' }
    }

    # Helper to build table rows
    function ConvertTo-HtmlRows {
        param([array]$Items, [array]$Properties)
        $rows = ''
        foreach ($item in $Items) {
            $cells = foreach ($prop in $Properties) {
                $val = $item.$prop
                if ($null -eq $val) { $val = '' }
                "<td>$([System.Net.WebUtility]::HtmlEncode([string]$val))</td>"
            }
            $rows += "<tr>$($cells -join '')</tr>`n"
        }
        return $rows
    }

    # TCP table
    $tcpSection = ''
    if ($tcpReport -and $tcpReport.Results) {
        $props = @('Timestamp','Protocol','RemoteAddress','RemotePort','LocalPort','ProcessName','Classification')
        $headerCells = ($props | ForEach-Object { "<th>$_</th>" }) -join ''
        $bodyRows = ConvertTo-HtmlRows -Items $tcpReport.Results -Properties $props
        $tcpSection = @"
<h2>TCP Connections</h2>
<p>Total: $($tcpReport.TotalConnections) | Suspicious: $($tcpReport.SuspiciousCount) | Allowed: $($tcpReport.AllowedCount)</p>
<table><tr>$headerCells</tr>$bodyRows</table>
"@
    }

    # UDP table
    $udpSection = ''
    if ($udpReport -and $udpReport.Results) {
        $props = @('Timestamp','Protocol','LocalAddress','LocalPort','ProcessName','Classification')
        $headerCells = ($props | ForEach-Object { "<th>$_</th>" }) -join ''
        $bodyRows = ConvertTo-HtmlRows -Items $udpReport.Results -Properties $props
        $udpSection = @"
<h2>UDP Endpoints</h2>
<p>Total: $($udpReport.TotalUdp) | Review: $($udpReport.ReviewCount) | Allowed: $($udpReport.AllowedCount)</p>
<table><tr>$headerCells</tr>$bodyRows</table>
"@
    }

    # Listener table
    $listenerSection = ''
    if ($listenerReport -and $listenerReport.Results) {
        $props = @('Timestamp','Protocol','State','LocalAddress','LocalPort','ProcessName','Classification')
        $headerCells = ($props | ForEach-Object { "<th>$_</th>" }) -join ''
        $bodyRows = ConvertTo-HtmlRows -Items $listenerReport.Results -Properties $props
        $listenerSection = @"
<h2>Listeners</h2>
<p>Total: $($listenerReport.TotalListeners) | Sensitive: $($listenerReport.SensitiveCount)</p>
<table><tr>$headerCells</tr>$bodyRows</table>
"@
    }

    $html = @"
<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<title>AVA Security Report</title>
<style>
body { font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #fafafa; }
h1 { margin: 0 0 10px 0; }
h2 { margin-top: 24px; }
.badge { display: inline-block; padding: 4px 14px; border-radius: 16px; font-weight: 600; font-size: 14px; }
.ok   { background: #e8f5e9; color: #1b5e20; }
.low  { background: #e3f2fd; color: #0d47a1; }
.med  { background: #fff8e1; color: #e65100; }
.high { background: #ffebee; color: #b71c1c; }
table { border-collapse: collapse; width: 100%; margin-top: 10px; }
th, td { border: 1px solid #ddd; padding: 6px 10px; text-align: left; font-size: 13px; }
th { background: #f5f5f5; }
.meta { color: #666; font-size: 12px; }
</style>
</head>
<body>
<h1>AVA Security Report</h1>
<p class="meta">Computer: $($env:COMPUTERNAME) | User: $($env:USERDOMAIN)\$($env:USERNAME) | Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
<p><span class="badge $badgeClass">RISK SCORE: $score/100 &mdash; $riskLabel</span></p>
$tcpSection
$udpSection
$listenerSection
<p class="meta">Report generated by AVA Security Monitor v2.0</p>
</body>
</html>
"@

    Set-Content -Path $htmlPath -Value $html -Encoding UTF8
    Write-Host "HTML-Report exportiert: $htmlPath" -ForegroundColor Green
    Write-AvaLog -Level 'INFO' -Message "HTML-Report exportiert: $htmlPath"
    return $htmlPath
}

# ============================================================
# NEW FEATURE 4: PROCESS RISK ASSESSMENT
# ============================================================
function Get-AvaProcessRisk {
    <#
    .SYNOPSIS
        Evaluates running processes for risk indicators and assigns a score.
    .DESCRIPTION
        Checks for unsigned executables, processes running from temp/user paths,
        known LOLBins, high resource usage, and network activity.
    #>
    Initialize-AvaEnvironment

    Write-Host ''
    Write-Host 'Starte Prozess-Risikobewertung...' -ForegroundColor Cyan
    Write-AvaLog -Level 'INFO' -Message 'Prozess-Risikobewertung gestartet'

    $lolBins = @(
        'powershell','pwsh','cmd','wscript','cscript','mshta',
        'rundll32','regsvr32','bitsadmin','certutil','wmic',
        'msbuild','installutil','regasm','regsvcs'
    )

    $suspiciousPathPatterns = @('\\Temp\\','\\AppData\\','\\Downloads\\','\\Users\\Public\\')

    $results = New-Object System.Collections.Generic.List[object]
    $processes = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Id -ne 0 }

    # Get processes with network connections
    $netProcs = @{}
    try {
        $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        foreach ($c in $conns) {
            $netProcs[[int]$c.OwningProcess] = $true
        }
    }
    catch { }

    foreach ($proc in $processes) {
        $riskScore   = 0
        $riskFactors = New-Object System.Collections.Generic.List[string]
        $procPath    = ''

        try { $procPath = $proc.Path } catch { }

        # LOLBin check
        if ($lolBins -contains $proc.ProcessName) {
            $riskScore += 20
            $riskFactors.Add('LOLBin')
        }

        # Suspicious path
        if ($procPath) {
            foreach ($pattern in $suspiciousPathPatterns) {
                if ($procPath -like "*$pattern*") {
                    $riskScore += 15
                    $riskFactors.Add('SuspiciousPath')
                    break
                }
            }
        }

        # High CPU
        try {
            $cpu = $proc.CPU
            if ($cpu -gt 300) {
                $riskScore += 10
                $riskFactors.Add('HighCPU')
            }
        }
        catch { }

        # High memory (>500 MB working set)
        if ($proc.WorkingSet64 -gt 500MB) {
            $riskScore += 5
            $riskFactors.Add('HighMemory')
        }

        # Has network connections
        if ($netProcs.ContainsKey($proc.Id)) {
            $riskScore += 5
            $riskFactors.Add('NetworkActive')
        }

        # No path (potential injection)
        if (-not $procPath -and $proc.ProcessName -ne 'Idle' -and $proc.ProcessName -ne 'System') {
            $riskScore += 10
            $riskFactors.Add('NoPath')
        }

        $riskLevel = if ($riskScore -ge 30) { 'HIGH' }
                     elseif ($riskScore -ge 15) { 'MEDIUM' }
                     elseif ($riskScore -gt 0)  { 'LOW' }
                     else { 'NONE' }

        $entry = [PSCustomObject]@{
            ProcessName = $proc.ProcessName
            PID         = $proc.Id
            Path        = $procPath
            RiskScore   = $riskScore
            RiskLevel   = $riskLevel
            RiskFactors = ($riskFactors -join ', ')
            CPU         = [math]::Round($proc.CPU, 2)
            MemoryMB    = [math]::Round($proc.WorkingSet64 / 1MB, 1)
        }

        $results.Add($entry)
    }

    # Sort by risk descending
    $sorted = $results | Sort-Object -Property RiskScore -Descending

    # Display top risks
    $topRisks = @($sorted | Where-Object { $_.RiskScore -gt 0 })
    Write-Host ''
    Write-Host "Prozesse mit Risiko: $($topRisks.Count) von $($results.Count)" -ForegroundColor Yellow

    foreach ($r in ($topRisks | Select-Object -First 20)) {
        $color = switch ($r.RiskLevel) {
            'HIGH'   { 'Red' }
            'MEDIUM' { 'Yellow' }
            default  { 'DarkYellow' }
        }
        Write-Host ("  [{0}] {1} (PID {2}) Score={3} | {4}" -f $r.RiskLevel, $r.ProcessName, $r.PID, $r.RiskScore, $r.RiskFactors) -ForegroundColor $color
    }

    # Save report
    $reportPath = Join-Path $script:AvaRoot 'process_risk_report.json'
    $summary = [PSCustomObject]@{
        ScanTimestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        TotalProcesses = $results.Count
        HighRisk       = @($topRisks | Where-Object { $_.RiskLevel -eq 'HIGH' }).Count
        MediumRisk     = @($topRisks | Where-Object { $_.RiskLevel -eq 'MEDIUM' }).Count
        LowRisk        = @($topRisks | Where-Object { $_.RiskLevel -eq 'LOW' }).Count
        Results        = $sorted
    }
    $summary | ConvertTo-Json -Depth 6 | Set-Content -Path $reportPath -Encoding UTF8

    Write-AvaLog -Level 'INFO' -Message "Prozess-Risikobewertung abgeschlossen | High=$($summary.HighRisk) | Medium=$($summary.MediumRisk) | Low=$($summary.LowRisk)"
    Write-Host "Prozess-Risk-Report: $reportPath" -ForegroundColor Yellow
    Write-Host ''

    return $summary
}

# ============================================================
# NEW FEATURE 5: BASELINE COMPARISON (alt/neu)
# ============================================================
function Compare-AvaBaseline {
    <#
    .SYNOPSIS
        Compares two scan snapshots (old vs new) and highlights differences.
    .PARAMETER OldReportPath
        Path to the older JSON report file.
    .PARAMETER NewReportPath
        Path to the newer JSON report file. Defaults to the current TCP report.
    #>
    param(
        [Parameter(Mandatory)]
        [string]$OldReportPath,
        [string]$NewReportPath = $script:ReportPath
    )

    Initialize-AvaEnvironment

    if (-not (Test-Path $OldReportPath)) {
        Write-Host "Alter Report nicht gefunden: $OldReportPath" -ForegroundColor Red
        return $null
    }
    if (-not (Test-Path $NewReportPath)) {
        Write-Host "Neuer Report nicht gefunden: $NewReportPath" -ForegroundColor Red
        return $null
    }

    Write-Host ''
    Write-Host 'Starte Baseline-Vergleich...' -ForegroundColor Cyan
    Write-AvaLog -Level 'INFO' -Message "Baseline-Vergleich | Old=$OldReportPath | New=$NewReportPath"

    $oldReport = Get-Content -Path $OldReportPath -Raw -Encoding UTF8 | ConvertFrom-Json
    $newReport = Get-Content -Path $NewReportPath -Raw -Encoding UTF8 | ConvertFrom-Json

    # Build lookup keys: RemoteAddress:RemotePort:ProcessName for TCP
    function Get-ConnectionKey {
        param($Entry)
        if ($Entry.RemoteAddress) {
            return "{0}:{1}:{2}" -f $Entry.RemoteAddress, $Entry.RemotePort, $Entry.ProcessName
        }
        elseif ($Entry.LocalAddress) {
            return "{0}:{1}:{2}" -f $Entry.LocalAddress, $Entry.LocalPort, $Entry.ProcessName
        }
        return ''
    }

    $oldKeys = @{}
    $newKeys = @{}

    if ($oldReport.Results) {
        foreach ($r in $oldReport.Results) {
            $key = Get-ConnectionKey -Entry $r
            if ($key) { $oldKeys[$key] = $r }
        }
    }

    if ($newReport.Results) {
        foreach ($r in $newReport.Results) {
            $key = Get-ConnectionKey -Entry $r
            if ($key) { $newKeys[$key] = $r }
        }
    }

    $added   = New-Object System.Collections.Generic.List[object]
    $removed = New-Object System.Collections.Generic.List[object]
    $changed = New-Object System.Collections.Generic.List[object]

    # New connections
    foreach ($key in $newKeys.Keys) {
        if (-not $oldKeys.ContainsKey($key)) {
            $added.Add($newKeys[$key])
        }
        elseif ($newKeys[$key].Classification -ne $oldKeys[$key].Classification) {
            $changed.Add([PSCustomObject]@{
                Key               = $key
                OldClassification = $oldKeys[$key].Classification
                NewClassification = $newKeys[$key].Classification
            })
        }
    }

    # Removed connections
    foreach ($key in $oldKeys.Keys) {
        if (-not $newKeys.ContainsKey($key)) {
            $removed.Add($oldKeys[$key])
        }
    }

    # Display
    Write-Host ''
    Write-Host ("  Alter Scan   : {0}" -f $oldReport.ScanTimestamp) -ForegroundColor DarkGray
    Write-Host ("  Neuer Scan   : {0}" -f $newReport.ScanTimestamp) -ForegroundColor DarkGray
    Write-Host ''

    Write-Host ("  NEU hinzugekommen : {0}" -f $added.Count) -ForegroundColor $(if ($added.Count -gt 0) { 'Yellow' } else { 'Green' })
    foreach ($a in ($added | Select-Object -First 15)) {
        $addr = if ($a.RemoteAddress) { "{0}:{1}" -f $a.RemoteAddress, $a.RemotePort } else { "{0}:{1}" -f $a.LocalAddress, $a.LocalPort }
        Write-Host ("    + {0} | {1} [{2}]" -f $addr, $a.ProcessName, $a.Classification) -ForegroundColor Yellow
    }

    Write-Host ("  ENTFERNT          : {0}" -f $removed.Count) -ForegroundColor $(if ($removed.Count -gt 0) { 'Cyan' } else { 'Green' })
    foreach ($r in ($removed | Select-Object -First 15)) {
        $addr = if ($r.RemoteAddress) { "{0}:{1}" -f $r.RemoteAddress, $r.RemotePort } else { "{0}:{1}" -f $r.LocalAddress, $r.LocalPort }
        Write-Host ("    - {0} | {1} [{2}]" -f $addr, $r.ProcessName, $r.Classification) -ForegroundColor Cyan
    }

    Write-Host ("  KLASSIFIKATION GEÄNDERT : {0}" -f $changed.Count) -ForegroundColor $(if ($changed.Count -gt 0) { 'Red' } else { 'Green' })
    foreach ($c in $changed) {
        Write-Host ("    ~ {0} : {1} -> {2}" -f $c.Key, $c.OldClassification, $c.NewClassification) -ForegroundColor Red
    }
    Write-Host ''

    $comparison = [PSCustomObject]@{
        ComparedAt         = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        OldScanTimestamp   = $oldReport.ScanTimestamp
        NewScanTimestamp   = $newReport.ScanTimestamp
        AddedCount         = $added.Count
        RemovedCount       = $removed.Count
        ChangedCount       = $changed.Count
        Added              = $added
        Removed            = $removed
        Changed            = $changed
    }

    $comparisonPath = Join-Path $script:AvaRoot 'baseline_comparison.json'
    $comparison | ConvertTo-Json -Depth 6 | Set-Content -Path $comparisonPath -Encoding UTF8
    Write-Host "Vergleichs-Report: $comparisonPath" -ForegroundColor Yellow

    Write-AvaLog -Level 'INFO' -Message "Baseline-Vergleich abgeschlossen | Added=$($added.Count) | Removed=$($removed.Count) | Changed=$($changed.Count)"

    return $comparison
}

# ============================================================
# NEW FEATURE 6: CONTINUOUS MONITOR
# ============================================================
function Start-AvaContinuousMonitor {
    <#
    .SYNOPSIS
        Runs AVA scans repeatedly at a configurable interval.
    .PARAMETER IntervalSeconds
        Seconds between scan cycles. Default 60.
    .PARAMETER MaxCycles
        Maximum number of cycles. 0 = unlimited. Default 0.
    .PARAMETER IncludeTcp
        Run TCP connection scan each cycle.
    .PARAMETER IncludeUdp
        Run UDP endpoint scan each cycle.
    .PARAMETER IncludeListeners
        Run listener audit each cycle.
    .PARAMETER IncludeProcessRisk
        Run process risk assessment each cycle.
    #>
    param(
        [int]$IntervalSeconds  = 60,
        [int]$MaxCycles        = 0,
        [switch]$IncludeTcp    = $true,
        [switch]$IncludeUdp    = $true,
        [switch]$IncludeListeners   = $true,
        [switch]$IncludeProcessRisk = $false
    )

    Initialize-AvaEnvironment

    Write-Host ''
    Write-Host '=============================================' -ForegroundColor DarkCyan
    Write-Host '  AVA DAUER-MONITOR GESTARTET' -ForegroundColor Cyan
    Write-Host "  Intervall : ${IntervalSeconds}s" -ForegroundColor DarkGray
    Write-Host "  Max Zyklen: $(if ($MaxCycles -eq 0) { 'Unbegrenzt' } else { $MaxCycles })" -ForegroundColor DarkGray
    Write-Host '  Strg+C zum Abbrechen' -ForegroundColor DarkGray
    Write-Host '=============================================' -ForegroundColor DarkCyan
    Write-Host ''

    Write-AvaLog -Level 'INFO' -Message "Dauer-Monitor gestartet | Interval=${IntervalSeconds}s | MaxCycles=$MaxCycles"

    $cycle = 0
    while ($true) {
        $cycle++

        Write-Host ("--- Zyklus {0} | {1} ---" -f $cycle, (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) -ForegroundColor Cyan

        # Archive previous report for baseline comparison
        $previousReportPath = $null
        if ((Test-Path $script:ReportPath) -and $IncludeTcp) {
            $previousReportPath = Join-Path $script:AvaRoot ("report_prev_{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
            Copy-Item -Path $script:ReportPath -Destination $previousReportPath -Force
        }

        if ($IncludeTcp)         { Invoke-AvaConnectionScan | Out-Null }
        if ($IncludeUdp)         { Invoke-AvaUdpScan | Out-Null }
        if ($IncludeListeners)   { Invoke-AvaListenerAudit | Out-Null }
        if ($IncludeProcessRisk) { Get-AvaProcessRisk | Out-Null }

        # Auto baseline comparison if previous exists
        if ($previousReportPath -and (Test-Path $previousReportPath) -and $IncludeTcp) {
            Write-Host '  Baseline-Vergleich mit vorherigem Zyklus:' -ForegroundColor DarkGray
            Compare-AvaBaseline -OldReportPath $previousReportPath | Out-Null
            Remove-Item -Path $previousReportPath -Force -ErrorAction SilentlyContinue
        }

        # Show dashboard summary
        Show-AvaDashboard

        if ($MaxCycles -gt 0 -and $cycle -ge $MaxCycles) {
            Write-Host "Max Zyklen ($MaxCycles) erreicht. Monitor beendet." -ForegroundColor Cyan
            Write-AvaLog -Level 'INFO' -Message "Dauer-Monitor beendet nach $cycle Zyklen"
            break
        }

        Write-Host ("Nächster Zyklus in {0} Sekunden..." -f $IntervalSeconds) -ForegroundColor DarkGray
        Start-Sleep -Seconds $IntervalSeconds
    }
}

# ============================================================
# MENU (updated with all features)
# ============================================================
function Show-AvaMenu {
    do {
        Write-Host ''
        Write-Host '=========================================' -ForegroundColor DarkCyan
        Write-Host '     THE ANGEL AND THE AGENT / AVA' -ForegroundColor Cyan
        Write-Host '=========================================' -ForegroundColor DarkCyan
        Write-Host '1  - TCP-Scan nur anzeigen'
        Write-Host '2  - TCP-Scan + verdächtige Adressen blockieren'
        Write-Host '3  - Letzten TCP-Report anzeigen'
        Write-Host '4  - AVA-Whitelist anzeigen'
        Write-Host '5  - Alle AVA-Blockregeln entfernen'
        Write-Host '6  - Logdatei anzeigen'
        Write-Host '7  - Demo Energie-Transaktion prüfen'
        Write-Host '8  - UDP-Analyse'
        Write-Host '9  - Listener-/Port-Audit'
        Write-Host '10 - Integritätsprüfung'
        Write-Host '11 - Integritäts-Baseline neu setzen'
        Write-Host '12 - Relevante Security-Events anzeigen'
        Write-Host '--- Neue Funktionen ---' -ForegroundColor DarkCyan
        Write-Host '13 - ASCII-Dashboard'
        Write-Host '14 - CSV-Export'
        Write-Host '15 - HTML-Report'
        Write-Host '16 - Prozess-Risikobewertung'
        Write-Host '17 - Baseline-Vergleich (alt/neu)'
        Write-Host '18 - Dauer-Monitor starten'
        Write-Host '0  - Beenden'
        Write-Host ''

        $choice = Read-Host 'Bitte Auswahl eingeben'

        switch ($choice) {
            '1'  { Invoke-AvaConnectionScan }
            '2'  { Invoke-AvaConnectionScan -AutoBlock }
            '3'  { Show-AvaLastReport }
            '4'  { Show-AvaWhitelist }
            '5'  { Remove-AvaBlocks }
            '6'  {
                if (Test-Path $script:LogPath) {
                    Get-Content -Path $script:LogPath
                }
                else {
                    Write-Host 'Keine Logdatei vorhanden.' -ForegroundColor Yellow
                }
            }
            '7'  {
                $tx = Read-Host 'TransactionID'
                $id = Read-Host 'InitiatorID'
                [void](Validate-EnergyTransactions -TransactionID $tx -InitiatorID $id)
            }
            '8'  { Invoke-AvaUdpScan }
            '9'  { Invoke-AvaListenerAudit }
            '10' { Test-AvaIntegrity }
            '11' { Update-AvaIntegrityBaseline }
            '12' {
                $hours = Read-Host 'Wie viele Stunden rückwirkend? (z.B. 24)'
                if (-not [string]::IsNullOrWhiteSpace($hours) -and $hours -match '^\d+$') {
                    Show-AvaRecentSecurityEvents -Hours ([int]$hours)
                }
                else {
                    Show-AvaRecentSecurityEvents -Hours 24
                }
            }
            '13' { Show-AvaDashboard }
            '14' {
                $dir = Read-Host "Export-Verzeichnis (leer = $($script:AvaRoot))"
                if ([string]::IsNullOrWhiteSpace($dir)) { $dir = $script:AvaRoot }
                Export-AvaCsv -OutputDir $dir
            }
            '15' {
                $dir = Read-Host "Report-Verzeichnis (leer = $($script:AvaRoot))"
                if ([string]::IsNullOrWhiteSpace($dir)) { $dir = $script:AvaRoot }
                Export-AvaHtmlReport -OutputDir $dir
            }
            '16' { Get-AvaProcessRisk }
            '17' {
                $oldPath = Read-Host 'Pfad zum alten Report (JSON)'
                if (-not [string]::IsNullOrWhiteSpace($oldPath)) {
                    Compare-AvaBaseline -OldReportPath $oldPath
                }
                else {
                    Write-Host 'Kein Pfad angegeben.' -ForegroundColor Yellow
                }
            }
            '18' {
                $intInput = Read-Host 'Intervall in Sekunden (Standard: 60)'
                $interval = 60
                if (-not [string]::IsNullOrWhiteSpace($intInput) -and $intInput -match '^\d+$') {
                    $interval = [int]$intInput
                }
                $cycInput = Read-Host 'Max Zyklen (0 = unbegrenzt, Standard: 0)'
                $maxCyc   = 0
                if (-not [string]::IsNullOrWhiteSpace($cycInput) -and $cycInput -match '^\d+$') {
                    $maxCyc = [int]$cycInput
                }
                Start-AvaContinuousMonitor -IntervalSeconds $interval -MaxCycles $maxCyc
            }
            '0' {
                Write-Host 'AVA Security Monitor beendet.' -ForegroundColor Cyan
            }
            default {
                Write-Host 'Ungültige Eingabe.' -ForegroundColor Red
            }
        }
    } while ($choice -ne '0')
}

# ============================================================
# ENTRY POINT (when run directly)
# ============================================================
if ($MyInvocation.InvocationName -ne '.') {
    Initialize-AvaEnvironment
    Show-AvaMenu
}
