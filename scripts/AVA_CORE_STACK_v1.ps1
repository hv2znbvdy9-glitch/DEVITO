#requires -RunAsAdministrator
<#
AVA CORE STACK v1
Defensiv / Lokal / Read-Only
Windows Defender Telemetrie
PowerShell Prozessanalyse
Netzwerk TCP/UDP
Baseline + Delta Engine
Event-/Alert-Tangle
HTML Portal
Optional: Nmap Inventarisierung nur wenn installiert
#>

[CmdletBinding()]
param(
    [switch]$RunOnce,
    [switch]$CreateBaseline,
    [switch]$OpenPortal
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$Root      = 'C:\Windows\SecurityGuardian'
$LogDir    = Join-Path $Root 'Logs'
$StateDir  = Join-Path $Root 'State'
$ReportDir = Join-Path $Root 'Reports'

$EventLog     = Join-Path $LogDir 'events_tangle.jsonl'
$AlertLog     = Join-Path $LogDir 'alerts.jsonl'
$BaselineFile = Join-Path $StateDir 'baseline_core.json'
$TangleState  = Join-Path $StateDir 'tangle_state.json'
$PortalFile   = Join-Path $ReportDir 'ava_core_portal.html'
$MaxTcpDisplayRows = 50

foreach ($d in @($Root, $LogDir, $StateDir, $ReportDir)) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
}

function HtmlEncode {
    param($v)
    if ($null -eq $v) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$v)
}

function Sha256Text {
    param([string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
        $hash = $sha.ComputeHash($bytes)
        return (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally {
        $sha.Dispose()
    }
}

function Get-LastTangleHash {
    if (Test-Path -LiteralPath $TangleState) {
        try {
            return (Get-Content -Path $TangleState -Raw | ConvertFrom-Json).last_hash
        }
        catch {}
    }
    return 'GENESIS'
}

function Write-TangleEvent {
    param(
        [Parameter(Mandatory)][string]$Type,
        [string]$Severity = 'INFO',
        [Parameter(Mandatory)][string]$Message,
        [hashtable]$Data = @{}
    )

    $prev = Get-LastTangleHash
    $obj = [ordered]@{
        time          = (Get-Date).ToString('s')
        computer      = $env:COMPUTERNAME
        user          = $env:USERNAME
        type          = $Type
        severity      = $Severity
        message       = $Message
        data          = $Data
        previous_hash = $prev
    }

    $raw = $obj | ConvertTo-Json -Depth 8 -Compress
    $hash = Sha256Text -Text $raw
    $obj.hash = $hash

    ($obj | ConvertTo-Json -Depth 8 -Compress) | Add-Content -Path $EventLog -Encoding UTF8
    (@{ last_hash = $hash; updated = (Get-Date).ToString('s') } | ConvertTo-Json) |
        Set-Content -Path $TangleState -Encoding UTF8

    if ($Severity -in @('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')) {
        ($obj | ConvertTo-Json -Depth 8 -Compress) | Add-Content -Path $AlertLog -Encoding UTF8
    }
}

function Get-DefenderInfo {
    try {
        $mp = Get-MpComputerStatus
        return [ordered]@{
            available           = $true
            realtime_protection = $mp.RealTimeProtectionEnabled
            antivirus_enabled   = $mp.AntivirusEnabled
            antispyware_enabled = $mp.AntispywareEnabled
            signature_age       = $mp.AntivirusSignatureAge
            last_quick_scan     = $mp.QuickScanEndTime
            last_full_scan      = $mp.FullScanEndTime
            tamper_protection   = $mp.IsTamperProtected
        }
    }
    catch {
        return [ordered]@{
            available = $false
            error     = $_.Exception.Message
        }
    }
}

function Get-PowerShellProcessInfo {
    $bad = @(
        '-enc', 'encodedcommand', '-nop', 'noprofile',
        '-w hidden', 'windowstyle hidden',
        'downloadstring', 'invoke-expression', 'iex',
        'bypass', '-ep bypass', 'frombase64string'
    )

    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -in @('powershell.exe', 'pwsh.exe') } |
        ForEach-Object {
            $cmd = [string]$_.CommandLine
            $lower = $cmd.ToLowerInvariant()
            $hits = @($bad | Where-Object { $lower.Contains($_) })

            [ordered]@{
                pid          = $_.ProcessId
                ppid         = $_.ParentProcessId
                name         = $_.Name
                path         = $_.ExecutablePath
                command_line = $cmd
                suspicious   = ($hits.Count -gt 0)
                hits         = $hits
            }
        }
}

function Get-NetworkInfo {
    $tcp = @()
    $udp = @()

    try {
        $tcp = Get-NetTCPConnection |
            Where-Object { $_.State -eq 'Established' } |
            Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
    }
    catch {}

    try {
        $udp = Get-NetUDPEndpoint |
            Select-Object LocalAddress, LocalPort, OwningProcess
    }
    catch {}

    $procMap = @{}
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procMap[[int]$_.Id] = $_.ProcessName }

    $tcpOut = foreach ($c in $tcp) {
        [ordered]@{
            protocol       = 'TCP'
            local_address  = $c.LocalAddress
            local_port     = $c.LocalPort
            remote_address = $c.RemoteAddress
            remote_port    = $c.RemotePort
            state          = $c.State
            pid            = $c.OwningProcess
            process        = $procMap[[int]$c.OwningProcess]
        }
    }

    $udpOut = foreach ($u in $udp) {
        [ordered]@{
            protocol      = 'UDP'
            local_address = $u.LocalAddress
            local_port    = $u.LocalPort
            pid           = $u.OwningProcess
            process       = $procMap[[int]$u.OwningProcess]
        }
    }

    return [ordered]@{
        tcp = @($tcpOut)
        udp = @($udpOut)
    }
}

function Get-Admins {
    try {
        $adminGroup = Get-LocalGroup | Where-Object { $_.SID.Value -eq 'S-1-5-32-544' } | Select-Object -First 1
        if ($adminGroup) {
            return Get-LocalGroupMember -Group $adminGroup.Name |
                Select-Object Name, ObjectClass, PrincipalSource
        }
    }
    catch {}

    try {
        return Get-LocalGroupMember -Group 'Administratoren' |
            Select-Object Name, ObjectClass, PrincipalSource
    }
    catch {
        try {
            return Get-LocalGroupMember -Group 'Administrators' |
                Select-Object Name, ObjectClass, PrincipalSource
        }
        catch {
            return @()
        }
    }
}

function Get-TasksLite {
    try {
        return Get-ScheduledTask |
            Where-Object {
                $_.TaskPath -notlike '\Microsoft\*' -and
                $_.TaskName -notlike 'AVA*'
            } |
            Select-Object TaskName, TaskPath, State
    }
    catch {
        return @()
    }
}

function Get-ServiceLite {
    try {
        return Get-CimInstance Win32_Service |
            Where-Object { $_.State -eq 'Running' } |
            Select-Object Name, DisplayName, State, StartMode, StartName, PathName
    }
    catch {
        return @()
    }
}

function Get-NmapInfo {
    $nmap = Get-Command nmap.exe -ErrorAction SilentlyContinue
    if (-not $nmap) {
        return [ordered]@{
            installed = $false
            note      = 'Nmap nicht gefunden. Optional installieren, falls gewünscht.'
        }
    }

    return [ordered]@{
        installed = $true
        path      = $nmap.Source
        note      = 'Nur Erkennung. Kein Scan ausgeführt.'
    }
}

function New-Snapshot {
    return [ordered]@{
        time       = (Get-Date).ToString('s')
        computer   = $env:COMPUTERNAME
        user       = $env:USERNAME
        run_once   = [bool]$RunOnce
        defender   = Get-DefenderInfo
        powershell = @(Get-PowerShellProcessInfo)
        network    = Get-NetworkInfo
        admins     = @(Get-Admins)
        tasks      = @(Get-TasksLite)
        services   = @(Get-ServiceLite)
        nmap       = Get-NmapInfo
    }
}

function Compare-WithBaseline {
    param($Snapshot)

    $alerts = New-Object System.Collections.Generic.List[object]
    if (-not (Test-Path -LiteralPath $BaselineFile)) {
        $alerts.Add([ordered]@{
            severity = 'LOW'
            type     = 'BASELINE'
            message  = 'Keine Baseline vorhanden. Starte mit -CreateBaseline.'
        })
        return $alerts
    }

    $base = Get-Content -Path $BaselineFile -Raw | ConvertFrom-Json

    foreach ($p in $Snapshot.powershell) {
        if ($p.suspicious) {
            $alerts.Add([ordered]@{
                severity = 'HIGH'
                type     = 'POWERSHELL'
                message  = "Verdächtiger PowerShell-Prozess erkannt: PID $($p.pid)"
                data     = $p
            })
        }
    }

    if ($Snapshot.defender.available -and -not $Snapshot.defender.realtime_protection) {
        $alerts.Add([ordered]@{
            severity = 'CRITICAL'
            type     = 'DEFENDER'
            message  = 'Defender Echtzeitschutz ist AUS.'
        })
    }

    $baseAdmins = @($base.admins | ForEach-Object { $_.Name })
    foreach ($a in $Snapshot.admins) {
        if ($baseAdmins -notcontains $a.Name) {
            $alerts.Add([ordered]@{
                severity = 'HIGH'
                type     = 'ADMIN_DELTA'
                message  = "Neuer lokaler Admin seit Baseline: $($a.Name)"
                data     = @{ admin = $a.Name }
            })
        }
    }

    $baseTasks = @($base.tasks | ForEach-Object { "$($_.TaskPath)$($_.TaskName)" })
    foreach ($t in $Snapshot.tasks) {
        $id = "$($t.TaskPath)$($t.TaskName)"
        if ($baseTasks -notcontains $id) {
            $alerts.Add([ordered]@{
                severity = 'MEDIUM'
                type     = 'TASK_DELTA'
                message  = "Neue geplante Aufgabe seit Baseline: $id"
            })
        }
    }

    # FTP, Telnet, RPC, NetBIOS, SMB, RDP, WinRM (5985 HTTP / 5986 HTTPS)
    $riskPorts = @(21, 23, 135, 139, 445, 3389, 5985, 5986)
    foreach ($c in $Snapshot.network.tcp) {
        if ($riskPorts -contains [int]$c.local_port -or $riskPorts -contains [int]$c.remote_port) {
            $alerts.Add([ordered]@{
                severity = 'MEDIUM'
                type     = 'NETWORK_RISK_PORT'
                message  = "Risikorelevante TCP-Verbindung/Port erkannt: $($c.process) PID $($c.pid)"
                data     = $c
            })
        }
    }

    return $alerts
}

function Build-Portal {
    param($Snapshot, $Alerts)

    $criticalCount = (@($Alerts | Where-Object { $_.severity -eq 'CRITICAL' })).Count
    $highCount = (@($Alerts | Where-Object { $_.severity -eq 'HIGH' })).Count

    $alertRows = foreach ($a in $Alerts) {
        "<tr><td>$(HtmlEncode $a.severity)</td><td>$(HtmlEncode $a.type)</td><td>$(HtmlEncode $a.message)</td></tr>"
    }
    if (-not $alertRows) {
        $alertRows = @("<tr><td colspan='3'>Keine Alerts</td></tr>")
    }

    $psRows = foreach ($p in $Snapshot.powershell) {
        "<tr><td>$(HtmlEncode $p.pid)</td><td>$(HtmlEncode $p.name)</td><td>$(HtmlEncode $p.suspicious)</td><td>$(HtmlEncode ($p.hits -join ', '))</td></tr>"
    }
    if (-not $psRows) {
        $psRows = @("<tr><td colspan='4'>Keine laufenden PowerShell-Prozesse erkannt.</td></tr>")
    }

    $tcpRows = foreach ($c in ($Snapshot.network.tcp | Select-Object -First $MaxTcpDisplayRows)) {
        "<tr><td>$(HtmlEncode $c.process)</td><td>$(HtmlEncode $c.pid)</td><td>$(HtmlEncode $c.local_port)</td><td>$(HtmlEncode $c.remote_address)</td><td>$(HtmlEncode $c.remote_port)</td></tr>"
    }
    if (-not $tcpRows) {
        $tcpRows = @("<tr><td colspan='5'>Keine etablierten TCP-Verbindungen.</td></tr>")
    }

@"
<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>AVA CORE STACK Portal</title>
  <style>
    body { font-family: Segoe UI, Tahoma, Arial, sans-serif; background: #0b1220; color: #e2e8f0; margin: 0; padding: 20px; }
    h1 { margin: 0 0 8px; color: #22d3ee; }
    .meta { color: #94a3b8; margin-bottom: 16px; }
    .cards { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 16px; }
    .card { background: #172033; border: 1px solid #22314f; border-radius: 8px; padding: 12px 16px; min-width: 120px; }
    .card .n { font-size: 1.4rem; font-weight: 700; }
    .section { margin-top: 18px; }
    table { width: 100%; border-collapse: collapse; font-size: 0.86rem; }
    th, td { border-bottom: 1px solid #243247; padding: 8px; text-align: left; vertical-align: top; }
    th { color: #7dd3fc; }
  </style>
</head>
<body>
<h1>AVA CORE STACK 🌀🗿🔑</h1>
<p class="meta">Zeit: $(HtmlEncode $Snapshot.time) | Host: $(HtmlEncode $Snapshot.computer) | User: $(HtmlEncode $Snapshot.user)</p>

<div class="cards">
  <div class="card"><div>Alerts gesamt</div><div class="n">$(HtmlEncode $Alerts.Count)</div></div>
  <div class="card"><div>Critical</div><div class="n">$(HtmlEncode $criticalCount)</div></div>
  <div class="card"><div>High</div><div class="n">$(HtmlEncode $highCount)</div></div>
  <div class="card"><div>TCP/UDP</div><div class="n">$(HtmlEncode $Snapshot.network.tcp.Count)/$(HtmlEncode $Snapshot.network.udp.Count)</div></div>
</div>

<div class="section">
  <h2>Alerts</h2>
  <table>
    <thead><tr><th>Severity</th><th>Type</th><th>Message</th></tr></thead>
    <tbody>$($alertRows -join '')</tbody>
  </table>
</div>

<div class="section">
  <h2>PowerShell Prozesse</h2>
  <table>
    <thead><tr><th>PID</th><th>Name</th><th>Suspicious</th><th>Hits</th></tr></thead>
    <tbody>$($psRows -join '')</tbody>
  </table>
</div>

<div class="section">
  <h2>TCP (Top $(HtmlEncode $MaxTcpDisplayRows))</h2>
  <table>
    <thead><tr><th>Prozess</th><th>PID</th><th>LocalPort</th><th>RemoteAddress</th><th>RemotePort</th></tr></thead>
    <tbody>$($tcpRows -join '')</tbody>
  </table>
</div>
</body>
</html>
"@ | Set-Content -Path $PortalFile -Encoding UTF8
}

$snapshot = New-Snapshot

if ($CreateBaseline) {
    $snapshot | ConvertTo-Json -Depth 12 | Set-Content -Path $BaselineFile -Encoding UTF8
    Write-TangleEvent -Type 'BASELINE' -Severity 'INFO' -Message 'Baseline erstellt.' -Data @{ path = $BaselineFile }
    Write-Host "AVA Baseline erstellt: $BaselineFile" -ForegroundColor Green
}

$alerts = Compare-WithBaseline -Snapshot $snapshot

Write-TangleEvent -Type 'SNAPSHOT' -Severity 'INFO' -Message 'Snapshot erstellt.' -Data @{
    powershell_count = @($snapshot.powershell).Count
    tcp_count        = @($snapshot.network.tcp).Count
    udp_count        = @($snapshot.network.udp).Count
    admin_count      = @($snapshot.admins).Count
    task_count       = @($snapshot.tasks).Count
    service_count    = @($snapshot.services).Count
    run_once         = [bool]$RunOnce
}

foreach ($a in $alerts) {
    $sev = if ($a.severity) { $a.severity } else { 'LOW' }
    $typ = if ($a.type) { $a.type } else { 'ALERT' }
    $msg = if ($a.message) { $a.message } else { 'Alert ohne Meldung' }
    Write-TangleEvent -Type $typ -Severity $sev -Message $msg -Data @{ alert = $a }
}

Build-Portal -Snapshot $snapshot -Alerts $alerts

Write-Host ''
Write-Host 'AVA CORE STACK abgeschlossen.' -ForegroundColor Cyan
Write-Host "Portal: $PortalFile" -ForegroundColor Green
Write-Host "Eventlog: $EventLog" -ForegroundColor Green
Write-Host "Alerts: $AlertLog" -ForegroundColor Green

if ($OpenPortal) {
    Start-Process $PortalFile
}
