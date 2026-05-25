#requires -Version 5.1
#requires -RunAsAdministrator
<#
AVA SOC PORTAL V5 - ALL IN ONE ELITE
Defensiv / Lokal / Read-Only

- Kein Angriff
- Kein Exploit
- Kein Scan fremder Systeme
- Kein Deauth / Cracken / Payload
- Nur lokale Sichtbarkeit, Baseline, Delta, Risk Score, HTML Portal
#>

[CmdletBinding()]
param(
    [switch]$RunOnce,
    [switch]$Loop,
    [switch]$InstallTask,
    [switch]$RemoveTask,
    [ValidateRange(5, 86400)]
    [int]$IntervalSeconds = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Root = 'C:\Windows\SecurityGuardian'
$LogDir = Join-Path $Root 'Logs'
$StateDir = Join-Path $Root 'State'
$ReportDir = Join-Path $Root 'Reports'

$TaskName = 'AVA_SOC_PORTAL_V5'
$ScriptPath = $PSCommandPath

$EventLog = Join-Path $LogDir 'ava_soc_v5_events.jsonl'
$AlertLog = Join-Path $LogDir 'ava_soc_v5_alerts.jsonl'
$TangleLog = Join-Path $LogDir 'ava_soc_v5_tangle.jsonl'
$TangleState = Join-Path $StateDir 'ava_soc_v5_tangle_state.json'
$BaselinePath = Join-Path $StateDir 'ava_soc_v5_baseline.json'
$PortalHtml = Join-Path $ReportDir 'ava_soc_portal_v5.html'
$SnapshotJson = Join-Path $ReportDir 'ava_soc_v5_snapshot.json'
$AnalysisJson = Join-Path $ReportDir 'ava_soc_v5_analysis.json'

$RiskPorts = @(21, 23, 135, 139, 445, 3389, 5985, 5986)
$SuspiciousPowerShell = @(
    '-enc',
    'encodedcommand',
    'downloadstring',
    'invoke-expression',
    'iex',
    '-nop',
    'noprofile',
    '-w hidden',
    'windowstyle hidden',
    'executionpolicy bypass',
    '-ep bypass'
)
$SuspiciousProcessNames = @(
    'powershell.exe',
    'pwsh.exe',
    'cmd.exe',
    'wscript.exe',
    'cscript.exe',
    'mshta.exe',
    'rundll32.exe',
    'regsvr32.exe'
)
$PortalRefreshSeconds = 60
$MaxPortalAlerts = 30
$MaxTableRows = 80
$MaxRiskScore = 999
$CoreSentence = 'Fakten vor Angst. Baseline vor Chaos. Sichtbarkeit vor Kontrolle.'
$TaskStartDelayMinutes = 1
$TaskRepetitionDurationDays = 3650

function Initialize-DirectoryPath {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Initialize-PortalLayout {
    foreach ($directory in @($Root, $LogDir, $StateDir, $ReportDir)) {
        Initialize-DirectoryPath -Path $directory
    }
}

function HtmlEncode {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return ''
    }

    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Sha256Text {
    param([Parameter(Mandatory)][string]$Text)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally {
        $sha.Dispose()
    }
}

function Write-JsonLine {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][object]$Object
    )

    $Object |
        ConvertTo-Json -Depth 30 -Compress |
        Add-Content -LiteralPath $Path -Encoding UTF8
}

function Write-Tangle {
    param(
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][string]$Summary,
        [AllowNull()][object]$Data
    )

    $previousHash = $null
    if (Test-Path -LiteralPath $TangleState) {
        try {
            $previousHash = (Get-Content -LiteralPath $TangleState -Raw | ConvertFrom-Json).last_hash
        }
        catch {
            $previousHash = $null
        }
    }

    $chainEvent = [ordered]@{
        time          = (Get-Date).ToString('o')
        host          = $env:COMPUTERNAME
        user          = $env:USERNAME
        type          = $Type
        summary       = $Summary
        previous_hash = $previousHash
        data          = $Data
    }

    $raw = $chainEvent | ConvertTo-Json -Depth 30 -Compress
    $hash = Sha256Text -Text $raw
    $chainEvent.hash = $hash

    Write-JsonLine -Path $TangleLog -Object $chainEvent

    [ordered]@{
        updated   = (Get-Date).ToString('o')
        last_hash = $hash
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $TangleState -Encoding UTF8
}

function Add-Alert {
    param(
        [Parameter(Mandatory)][ValidateSet('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')][string]$Severity,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][int]$Score,
        [AllowNull()][object]$Data
    )

    $alert = [ordered]@{
        time     = (Get-Date).ToString('o')
        severity = $Severity
        title    = $Title
        message  = $Message
        score    = $Score
        data     = $Data
    }

    Write-JsonLine -Path $AlertLog -Object $alert
    return $alert
}

function ConvertTo-TableRow {
    param(
        [AllowNull()][object[]]$Items,
        [Parameter(Mandatory)][string[]]$Props,
        [string]$EmptyText = 'Keine Daten gefunden.'
    )

    $rows = New-Object System.Collections.Generic.List[string]

    foreach ($item in @($Items)) {
        $cells = foreach ($property in $Props) {
            "<td>$(HtmlEncode $item.$property)</td>"
        }
        $null = $rows.Add("<tr>$($cells -join '')</tr>")
    }

    if ($rows.Count -eq 0) {
        $null = $rows.Add("<tr><td colspan='$($Props.Count)'>$(HtmlEncode $EmptyText)</td></tr>")
    }

    return $rows.ToArray()
}

function Get-WlanNetworksSafe {
    try {
        $raw = netsh wlan show networks mode=bssid 2>&1 | Out-String
    }
    catch {
        return @([pscustomobject]@{ Error = $_.Exception.Message })
    }

    if ($LASTEXITCODE -ne 0) {
        $rawPreview = $raw.Trim()
        if ($rawPreview.Length -gt 500) {
            $rawPreview = $rawPreview.Substring(0, 500)
        }

        return @([pscustomobject]@{
                Error = "netsh wlan show networks mode=bssid failed with exit code $LASTEXITCODE."
                Raw   = $rawPreview
            })
    }

    $items = New-Object System.Collections.Generic.List[object]
    $ssid = $null
    $auth = $null
    $enc = $null

    foreach ($line in ($raw -split "`r?`n")) {
        $trimmedLine = $line.Trim()

        if ($trimmedLine -match '^SSID\s+\d+\s+:\s+(.*)$') {
            $ssid = $Matches[1]
            $auth = $null
            $enc = $null
        }
        elseif ($trimmedLine -match '^Authentication\s+:\s+(.*)$') {
            $auth = $Matches[1]
        }
        elseif ($trimmedLine -match '^Encryption\s+:\s+(.*)$') {
            $enc = $Matches[1]
        }
        elseif ($trimmedLine -match '^BSSID\s+\d+\s+:\s+(.*)$') {
            $null = $items.Add([pscustomobject]@{
                    SSID           = $ssid
                    BSSID          = $Matches[1]
                    Authentication = $auth
                    Encryption     = $enc
                    Signal         = $null
                    RadioType      = $null
                    Channel        = $null
                })
        }
        elseif ($trimmedLine -match '^Signal\s+:\s+(.*)$') {
            if ($items.Count -gt 0) {
                $items[$items.Count - 1].Signal = $Matches[1]
            }
        }
        elseif ($trimmedLine -match '^Radio type\s+:\s+(.*)$') {
            if ($items.Count -gt 0) {
                $items[$items.Count - 1].RadioType = $Matches[1]
            }
        }
        elseif ($trimmedLine -match '^Channel\s+:\s+(.*)$') {
            if ($items.Count -gt 0) {
                $items[$items.Count - 1].Channel = $Matches[1]
            }
        }
    }

    return $items.ToArray()
}

function Get-DefenderSafe {
    try {
        Get-MpComputerStatus | Select-Object AMServiceEnabled,
            AntivirusEnabled,
            AntispywareEnabled,
            BehaviorMonitorEnabled,
            RealTimeProtectionEnabled,
            IoavProtectionEnabled,
            NISEnabled,
            OnAccessProtectionEnabled,
            AntivirusSignatureLastUpdated,
            FullScanEndTime,
            QuickScanEndTime
    }
    catch {
        [pscustomobject]@{ Error = $_.Exception.Message }
    }
}

function Get-AdminsSafe {
    try {
        Get-LocalGroupMember -Group 'Administrators' |
            Select-Object Name, ObjectClass, PrincipalSource
    }
    catch {
        @([pscustomobject]@{ Error = $_.Exception.Message })
    }
}

function Get-TasksSafe {
    try {
        Get-ScheduledTask |
            Where-Object { $_.TaskPath -notlike '\Microsoft*' } |
            Select-Object TaskName, TaskPath, State
    }
    catch {
        @([pscustomobject]@{ Error = $_.Exception.Message })
    }
}

function Get-ServicesSafe {
    try {
        Get-CimInstance Win32_Service |
            Where-Object { $_.State -eq 'Running' } |
            Select-Object Name, DisplayName, State, StartMode, StartName, PathName
    }
    catch {
        @([pscustomobject]@{ Error = $_.Exception.Message })
    }
}

function Get-ProcessesSafe {
    try {
        Get-CimInstance Win32_Process |
            Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine
    }
    catch {
        @([pscustomobject]@{ Error = $_.Exception.Message })
    }
}

function Get-ConnectionsSafe {
    try {
        $connections = @(Get-NetTCPConnection -State Established)
        if ($connections.Count -eq 0) {
            return @()
        }

        $owningProcesses = @($connections | Select-Object -ExpandProperty OwningProcess -Unique)
        $processMap = @{}
        Get-Process -Id $owningProcesses -ErrorAction SilentlyContinue | ForEach-Object {
            $processMap[$_.Id] = $_.ProcessName
        }

        $connections |
            ForEach-Object {
                [pscustomobject]@{
                    LocalAddress  = $_.LocalAddress
                    LocalPort     = $_.LocalPort
                    RemoteAddress = $_.RemoteAddress
                    RemotePort    = $_.RemotePort
                    State         = $_.State
                    PID           = $_.OwningProcess
                    Process       = $processMap[$_.OwningProcess]
                }
            }
    }
    catch {
        @([pscustomobject]@{ Error = $_.Exception.Message })
    }
}

function Get-NetworkLocalSafe {
    $adapters = try {
        Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed
    }
    catch {
        @([pscustomobject]@{ Error = $_.Exception.Message })
    }

    $ipconfig = try {
        Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, IPv6Address, IPv4DefaultGateway, DNSServer
    }
    catch {
        @([pscustomobject]@{ Error = $_.Exception.Message })
    }

    $neighbors = try {
        Get-NetNeighbor -AddressFamily IPv4 |
            Where-Object { $_.State -ne 'Unreachable' } |
            Select-Object InterfaceAlias, IPAddress, LinkLayerAddress, State
    }
    catch {
        @([pscustomobject]@{ Error = $_.Exception.Message })
    }

    [ordered]@{
        adapters  = $adapters
        ipconfig  = $ipconfig
        neighbors = $neighbors
    }
}

function Get-FirewallSafe {
    try {
        Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
    }
    catch {
        @([pscustomobject]@{ Error = $_.Exception.Message })
    }
}

function Get-Snapshot {
    [ordered]@{
        time        = (Get-Date).ToString('o')
        computer    = $env:COMPUTERNAME
        user        = $env:USERNAME
        mode        = 'LOCAL_DEFENSIVE_READ_ONLY'
        defender    = Get-DefenderSafe
        firewall    = Get-FirewallSafe
        admins      = Get-AdminsSafe
        tasks       = Get-TasksSafe
        services    = Get-ServicesSafe
        processes   = Get-ProcessesSafe
        connections = Get-ConnectionsSafe
        network     = Get-NetworkLocalSafe
        wlan        = Get-WlanNetworksSafe
    }
}

function Get-Baseline {
    if (Test-Path -LiteralPath $BaselinePath) {
        try {
            return Get-Content -LiteralPath $BaselinePath -Raw | ConvertFrom-Json
        }
        catch {
            return $null
        }
    }

    return $null
}

function Save-Baseline {
    param([Parameter(Mandatory)][object]$Snapshot)

    $Snapshot |
        ConvertTo-Json -Depth 30 |
        Set-Content -LiteralPath $BaselinePath -Encoding UTF8
}

function Measure-SnapshotRisk {
    param([Parameter(Mandatory)][object]$Snapshot)

    $alerts = New-Object System.Collections.Generic.List[object]
    $score = 0

    if ($Snapshot.defender.PSObject.Properties.Name -contains 'RealTimeProtectionEnabled') {
        if ($Snapshot.defender.RealTimeProtectionEnabled -eq $false) {
            $score += 100
            $null = $alerts.Add((Add-Alert -Severity 'CRITICAL' -Title 'Defender Realtime Off' -Message 'Windows Defender Echtzeitschutz ist deaktiviert.' -Score 100 -Data $Snapshot.defender))
        }
    }

    foreach ($firewallProfile in @($Snapshot.firewall)) {
        if ($firewallProfile.Enabled -eq $false) {
            $score += 80
            $null = $alerts.Add((Add-Alert -Severity 'HIGH' -Title 'Firewall Profile Disabled' -Message "Firewall-Profil deaktiviert: $($firewallProfile.Name)" -Score 80 -Data $firewallProfile))
        }
    }

    foreach ($connection in @($Snapshot.connections)) {
        if ($null -eq $connection.RemotePort) {
            continue
        }

        $remotePort = 0
        if (-not [int]::TryParse([string]$connection.RemotePort, [ref]$remotePort)) {
            continue
        }

        if ($RiskPorts -contains $remotePort) {
            $severity = 'MEDIUM'
            $riskScore = 45

            if ($remotePort -in @(445, 3389, 5985, 5986)) {
                $severity = 'HIGH'
                $riskScore = 75
            }

            $score += $riskScore
            $null = $alerts.Add((Add-Alert -Severity $severity -Title 'Risk Port Connection' -Message "Verbindung zu Risiko-Port $remotePort durch $($connection.Process)." -Score $riskScore -Data $connection))
        }
    }

    foreach ($process in @($Snapshot.processes)) {
        $processName = ''
        if ($process.Name) {
            $processName = ([string]$process.Name).ToLowerInvariant()
        }

        if ($processName -in $SuspiciousProcessNames) {
            $commandLine = ''
            if ($process.CommandLine) {
                $commandLine = ([string]$process.CommandLine).ToLowerInvariant()
            }

            $hits = New-Object System.Collections.Generic.List[string]

            foreach ($signature in $SuspiciousPowerShell) {
                if ($commandLine.Contains($signature)) {
                    $null = $hits.Add($signature)
                }
            }

            if ($hits.Count -gt 0) {
                $score += 85
                $null = $alerts.Add((Add-Alert -Severity 'HIGH' -Title 'Suspicious Command Line' -Message "Verdächtige Kommandozeile erkannt: $($process.Name)" -Score 85 -Data ([ordered]@{
                            process = $process
                            hits    = $hits.ToArray()
                        })))
            }
        }
    }

    $baseline = Get-Baseline
    $delta = [ordered]@{
        baseline_exists = $null -ne $baseline
        new_admins      = @()
        new_neighbors   = @()
        new_wlan_bssid  = @()
    }

    if ($null -eq $baseline) {
        Save-Baseline -Snapshot $Snapshot
    }
    else {
        $oldAdmins = @($baseline.admins | ForEach-Object { $_.Name })
        foreach ($admin in @($Snapshot.admins)) {
            if ($admin.Name -and ($oldAdmins -notcontains $admin.Name)) {
                $delta.new_admins += $admin
                $score += 90
                $null = $alerts.Add((Add-Alert -Severity 'HIGH' -Title 'New Local Admin' -Message "Neuer lokaler Administrator: $($admin.Name)" -Score 90 -Data $admin))
            }
        }

        $oldNeighbors = @($baseline.network.neighbors | ForEach-Object { "$($_.IPAddress)|$($_.LinkLayerAddress)" })
        foreach ($neighbor in @($Snapshot.network.neighbors)) {
            $key = "$($neighbor.IPAddress)|$($neighbor.LinkLayerAddress)"
            if ($neighbor.IPAddress -and ($oldNeighbors -notcontains $key)) {
                $delta.new_neighbors += $neighbor
                $score += 25
            }
        }

        $oldBssid = @($baseline.wlan | ForEach-Object { $_.BSSID })
        foreach ($wlanEntry in @($Snapshot.wlan)) {
            if ($wlanEntry.BSSID -and ($oldBssid -notcontains $wlanEntry.BSSID)) {
                $delta.new_wlan_bssid += $wlanEntry
                $score += 10
            }
        }
    }

    return [ordered]@{
        time        = (Get-Date).ToString('o')
        score       = [Math]::Min($score, $MaxRiskScore)
        alert_count = @($alerts).Count
        alerts      = $alerts
        delta       = $delta
    }
}

function Write-Portal {
    param(
        [Parameter(Mandatory)][object]$Snapshot,
        [Parameter(Mandatory)][object]$Analysis
    )

    $score = [int]$Analysis.score
    $health = 'OK'
    if ($score -ge 150) { $health = 'WARN' }
    if ($score -ge 300) { $health = 'HIGH' }
    if ($score -ge 500) { $health = 'CRITICAL' }

    $lastHash = 'N/A'
    if (Test-Path -LiteralPath $TangleState) {
        try {
            $lastHash = (Get-Content -LiteralPath $TangleState -Raw | ConvertFrom-Json).last_hash
        }
        catch {
            $lastHash = 'N/A'
        }
    }

    $alertRows = foreach ($alert in @($Analysis.alerts | Sort-Object score -Descending | Select-Object -First $MaxPortalAlerts)) {
        "<tr><td>$(HtmlEncode $alert.severity)</td><td>$(HtmlEncode $alert.title)</td><td>$(HtmlEncode $alert.message)</td><td>$(HtmlEncode $alert.score)</td><td>$(HtmlEncode $alert.time)</td></tr>"
    }
    if (-not $alertRows) {
        $alertRows = "<tr><td colspan='5'>Keine Alerts gefunden.</td></tr>"
    }

    $firewallRows = ConvertTo-TableRow -Items @($Snapshot.firewall) -Props @('Name', 'Enabled', 'DefaultInboundAction', 'DefaultOutboundAction')
    $connectionRows = ConvertTo-TableRow -Items (@($Snapshot.connections) | Select-Object -First $MaxTableRows) -Props @('Process', 'PID', 'LocalAddress', 'LocalPort', 'RemoteAddress', 'RemotePort', 'State')
    $processRows = ConvertTo-TableRow -Items (@($Snapshot.processes) | Select-Object -First $MaxTableRows) -Props @('Name', 'ProcessId', 'ParentProcessId', 'ExecutablePath', 'CommandLine')
    $wlanRows = ConvertTo-TableRow -Items (@($Snapshot.wlan) | Select-Object -First $MaxTableRows) -Props @('SSID', 'BSSID', 'Authentication', 'Encryption', 'Signal', 'RadioType', 'Channel')
    $neighborRows = ConvertTo-TableRow -Items (@($Snapshot.network.neighbors) | Select-Object -First $MaxTableRows) -Props @('InterfaceAlias', 'IPAddress', 'LinkLayerAddress', 'State')
    $adminRows = ConvertTo-TableRow -Items @($Snapshot.admins) -Props @('Name', 'ObjectClass', 'PrincipalSource')
    $taskRows = ConvertTo-TableRow -Items (@($Snapshot.tasks) | Select-Object -First $MaxTableRows) -Props @('TaskName', 'TaskPath', 'State')

    @"
<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="$PortalRefreshSeconds">
<title>AVA SOC PORTAL V5</title>
<style>
:root{
--bg:#05080c;--panel:#0c1520dd;--line:#16384d;--green:#19ff8f;--blue:#22a7ff;
--text:#eaf6ff;--muted:#8fa3ad;--warn:#ffcc66;--danger:#ff5d6c;
}
*{box-sizing:border-box}
body{
margin:0;padding:34px;background:
linear-gradient(rgba(255,255,255,.025) 1px,transparent 1px),
linear-gradient(90deg,rgba(255,255,255,.025) 1px,transparent 1px),
radial-gradient(circle at top,#0d1720 0%,#05080c 60%);
background-size:60px 60px,60px 60px,cover;color:var(--text);
font-family:Consolas,"Segoe UI",monospace;
}
.frame{border:1px solid rgba(25,255,143,.35);padding:26px;min-height:92vh;box-shadow:0 0 35px rgba(25,255,143,.08)}
.topbar{display:flex;justify-content:space-between;border-bottom:1px solid var(--line);padding-bottom:18px;margin-bottom:30px;gap:12px;flex-wrap:wrap}
.badge{border:1px solid rgba(25,255,143,.45);color:var(--green);padding:8px 14px;letter-spacing:3px;font-size:12px}
h1{font-size:56px;margin:10px 0 4px 0;letter-spacing:3px;line-height:1}
h1 span{color:var(--blue)}
.subtitle{color:var(--muted);letter-spacing:4px;font-size:12px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin:26px 0}
.card{background:var(--panel);border:1px solid var(--line);padding:16px;box-shadow:inset 0 0 22px rgba(34,167,255,.04);overflow:auto}
.card h2{color:var(--green);font-size:13px;letter-spacing:3px;margin:0 0 12px 0;text-transform:uppercase}
.big{font-size:30px;color:var(--blue);font-weight:bold}
.small{color:var(--muted);font-size:12px}
.section{margin-top:24px}
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;margin-top:10px}
th,td{padding:8px;border-bottom:1px solid rgba(255,255,255,.07);text-align:left;vertical-align:top;font-size:12px}
th{color:var(--blue);text-transform:uppercase;letter-spacing:1px}
.notice{border-left:4px solid var(--warn);background:rgba(255,204,102,.08);padding:16px;color:#ffe3a3}
.legal{border-left:4px solid var(--green);background:rgba(25,255,143,.06);padding:16px;color:#bfffdc}
.hash{word-break:break-all;color:var(--muted);font-size:12px}
.footer{margin-top:30px;padding-top:18px;border-top:1px solid var(--line);color:var(--muted);display:flex;justify-content:space-between;gap:14px;flex-wrap:wrap;font-size:12px;letter-spacing:2px}
.status-OK{color:var(--green)}.status-WARN{color:var(--warn)}.status-HIGH,.status-CRITICAL{color:var(--danger)}
</style>
</head>
<body>
<div class="frame">

<div class="topbar">
<div class="badge">AVA SOC PORTAL V5</div>
<div class="badge">LOCAL / READ ONLY / DEFENSIVE</div>
</div>

<div>
<div class="subtitle">// SECURITY OPERATIONS VISIBILITY</div>
<h1>AVA SOC <span>PORTAL V5</span></h1>
<div class="subtitle">BASELINE · DELTA · TANGLE · DEFENDER · WLAN · NETWORK · PROCESS</div>
</div>

<div class="grid">
<div class="card"><h2>Health</h2><div class="big status-$health">$health</div><div class="small">Score: $score</div></div>
<div class="card"><h2>Alerts</h2><div class="big">$($Analysis.alert_count)</div><div class="small">Risk Events</div></div>
<div class="card"><h2>Connections</h2><div class="big">$(@($Snapshot.connections).Count)</div><div class="small">Established TCP</div></div>
<div class="card"><h2>Processes</h2><div class="big">$(@($Snapshot.processes).Count)</div><div class="small">Local Processes</div></div>
<div class="card"><h2>WLAN</h2><div class="big">$(@($Snapshot.wlan).Count)</div><div class="small">Visible BSSID</div></div>
<div class="card"><h2>Neighbors</h2><div class="big">$(@($Snapshot.network.neighbors).Count)</div><div class="small">LAN / ARP</div></div>
</div>

<div class="section legal">
<b>Kernsatz:</b> $(HtmlEncode $CoreSentence)<br>
Dieses System ist lokal, defensiv und read-only. Keine Angriffe, keine Exploits, keine fremden Ziele.
</div>

<div class="section card">
<h2>Tangle Hash Chain</h2>
<div class="small">Letzter Hash:</div>
<div class="hash">$(HtmlEncode $lastHash)</div>
</div>

<div class="section card">
<h2>Alerts</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Severity</th><th>Title</th><th>Message</th><th>Score</th><th>Time</th></tr></thead>
<tbody>
$($alertRows -join "`n")
</tbody>
</table>
</div>
</div>

<div class="section card">
<h2>Firewall Profiles</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Name</th><th>Enabled</th><th>Inbound</th><th>Outbound</th></tr></thead>
<tbody>
$($firewallRows -join "`n")
</tbody>
</table>
</div>
</div>

<div class="section card">
<h2>Established Connections</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Process</th><th>PID</th><th>Local</th><th>LPort</th><th>Remote</th><th>RPort</th><th>State</th></tr></thead>
<tbody>
$($connectionRows -join "`n")
</tbody>
</table>
</div>
</div>

<div class="section card">
<h2>Suspicious Process View</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Name</th><th>PID</th><th>PPID</th><th>Path</th><th>CommandLine</th></tr></thead>
<tbody>
$($processRows -join "`n")
</tbody>
</table>
</div>
</div>

<div class="section card">
<h2>WLAN View</h2>
<div class="table-wrap">
<table>
<thead><tr><th>SSID</th><th>BSSID</th><th>Auth</th><th>Encryption</th><th>Signal</th><th>Radio</th><th>Channel</th></tr></thead>
<tbody>
$($wlanRows -join "`n")
</tbody>
</table>
</div>
</div>

<div class="section card">
<h2>LAN Neighbors</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Interface</th><th>IP</th><th>MAC</th><th>State</th></tr></thead>
<tbody>
$($neighborRows -join "`n")
</tbody>
</table>
</div>
</div>

<div class="section card">
<h2>Local Admins</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Name</th><th>Class</th><th>Source</th></tr></thead>
<tbody>
$($adminRows -join "`n")
</tbody>
</table>
</div>
</div>

<div class="section card">
<h2>Non-Microsoft Scheduled Tasks</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Name</th><th>Path</th><th>State</th></tr></thead>
<tbody>
$($taskRows -join "`n")
</tbody>
</table>
</div>
</div>

<div class="section notice">
<b>AVA Hinweis:</b> Wichtig sind Veränderungen: neue Admins, neue LAN-Nachbarn, neue BSSID, Risiko-Ports,
verdächtige PowerShell-Parameter oder deaktivierter Defender.
</div>

<div class="footer">
<div>AVA SOC PORTAL V5 · THE CYBER BITE HUD STYLE</div>
<div>$(HtmlEncode $Snapshot.time)</div>
</div>

</div>
</body>
</html>
"@ | Set-Content -LiteralPath $PortalHtml -Encoding UTF8
}

function Invoke-AvaSoc {
    Initialize-PortalLayout

    $snapshot = Get-Snapshot
    $analysis = Measure-SnapshotRisk -Snapshot $snapshot

    Write-JsonLine -Path $EventLog -Object $snapshot

    $snapshot |
        ConvertTo-Json -Depth 30 |
        Set-Content -LiteralPath $SnapshotJson -Encoding UTF8

    $analysis |
        ConvertTo-Json -Depth 30 |
        Set-Content -LiteralPath $AnalysisJson -Encoding UTF8

    Write-Tangle -Type 'SOC_SNAPSHOT' -Summary 'AVA SOC Portal V5 Snapshot erstellt' -Data ([ordered]@{
            score    = $analysis.score
            alerts   = @($analysis.alerts).Count
            computer = $snapshot.computer
            time     = $snapshot.time
        })

    Write-Portal -Snapshot $snapshot -Analysis $analysis

    Write-Host 'AVA SOC PORTAL V5 erstellt.' -ForegroundColor Green
    Write-Host "Score: $($analysis.score)" -ForegroundColor Yellow
    Write-Host "Alerts: $(@($analysis.alerts).Count)" -ForegroundColor Yellow
    Write-Host "Portal: $PortalHtml" -ForegroundColor Cyan
}

function Install-AvaTask {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    if (-not $ScriptPath) {
        throw 'Bitte zuerst als .ps1 speichern.'
    }

    Initialize-PortalLayout

    $action = New-ScheduledTaskAction `
        -Execute 'powershell.exe' `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -RunOnce"

    $TaskIntervalSeconds = [Math]::Max($IntervalSeconds, 60)
    $RepetitionInterval = "PT$($TaskIntervalSeconds)S"
    $RepetitionDuration = "P$($TaskRepetitionDurationDays)D"

    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes($TaskStartDelayMinutes)
    $trigger.Repetition.Interval = $RepetitionInterval
    $trigger.Repetition.Duration = $RepetitionDuration

    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest

    if ($PSCmdlet.ShouldProcess($TaskName, 'Register scheduled task')) {
        Register-ScheduledTask `
            -TaskName $TaskName `
            -Action $action `
            -Trigger $trigger `
            -Principal $principal `
            -Force | Out-Null
    }

    Write-Host "Task installiert: $TaskName" -ForegroundColor Green
}

function Uninstall-AvaTask {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) {
        if ($PSCmdlet.ShouldProcess($TaskName, 'Unregister scheduled task')) {
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        }
        Write-Host "Task entfernt: $TaskName" -ForegroundColor Yellow
    }
    else {
        Write-Host "Task nicht gefunden: $TaskName" -ForegroundColor DarkYellow
    }
}

if ($InstallTask) {
    Install-AvaTask
    exit
}

if ($RemoveTask) {
    Uninstall-AvaTask
    exit
}

if ($Loop) {
    while ($true) {
        Invoke-AvaSoc
        Start-Sleep -Seconds $IntervalSeconds
    }
}
else {
    Invoke-AvaSoc
}

if ($RunOnce) {
    try {
        Start-Process $PortalHtml -ErrorAction Stop
    }
    catch {
        Write-Host "Portal konnte nicht automatisch geöffnet werden: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}
