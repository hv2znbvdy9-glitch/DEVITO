#requires -RunAsAdministrator
<#
AVA 3.14 NEXT LAYER — ALL
UNIFIED LOCAL DEFENSIVE VISIBILITY SYSTEM

Defensiv / Lokal / Read-Only
- Kein Angriff
- Kein Exploit
- Kein Fremdscan
- Kein Deauth
- Kein Cracken
- Kein Payload
- Keine offensive Automatisierung

Funktionen:
- SOC Snapshot
- Defender / Firewall / Prozesse / Dienste / Admins / Tasks
- Netzwerk TCP / WLAN / LAN Nachbarn
- Baseline + Delta
- Risk Score
- Alert JSONL
- Tangle Hash Chain
- HTML HUD Portal
- Optional Scheduled Task
#>

[CmdletBinding()]
param(
    [switch]$RunOnce,
    [switch]$Loop,
    [switch]$InstallTask,
    [switch]$RemoveTask,
    [switch]$ResetBaseline,
    [int]$IntervalSeconds = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# =========================
# CONFIG
# =========================

$Root       = 'C:\Windows\SecurityGuardian'
$LogDir     = Join-Path $Root 'Logs'
$StateDir   = Join-Path $Root 'State'
$ReportDir  = Join-Path $Root 'Reports'
$PortalDir  = Join-Path $Root 'Portal'

$TaskName   = 'AVA_3_14_NEXT_LAYER_ALL'
$ScriptPath = $PSCommandPath

$MinPortalRefreshSeconds = 5
$DefaultPortalRefreshSeconds = 300
$DefaultLogRotationMaxMB = 25
$TaskPathExcludePattern = '\Microsoft\*'
$WarnScoreThreshold = 150
$HighScoreThreshold = 300
$CriticalScoreThreshold = 500
$MaxRiskScore = 999

$PortalRefreshSeconds = if ($Loop) { [Math]::Max($MinPortalRefreshSeconds, $IntervalSeconds) } else { $DefaultPortalRefreshSeconds }

$EventLog     = Join-Path $LogDir 'ava_3_14_events.jsonl'
$AlertLog     = Join-Path $LogDir 'ava_3_14_alerts.jsonl'
$TangleLog    = Join-Path $LogDir 'ava_3_14_tangle.jsonl'
$TangleState  = Join-Path $StateDir 'ava_3_14_tangle_state.json'
$BaselinePath = Join-Path $StateDir 'ava_3_14_baseline.json'
$PortalHtml   = Join-Path $PortalDir 'index.html'
$SnapshotJson = Join-Path $ReportDir 'ava_3_14_latest_snapshot.json'
$AnalysisJson = Join-Path $ReportDir 'ava_3_14_latest_analysis.json'

$RiskPorts = @(21, 23, 135, 139, 445, 3389, 5985, 5986)

$SuspiciousCmdPatterns = @(
    '-enc',
    'encodedcommand',
    'downloadstring',
    'invoke-expression',
    'iex ',
    '-nop',
    'noprofile',
    '-w hidden',
    'windowstyle hidden',
    'executionpolicy bypass',
    '-ep bypass',
    'frombase64string',
    'bitsadmin',
    'certutil',
    'mshta'
)

# =========================
# HELPERS
# =========================

function Initialize-GuardianDirectory {
    foreach ($d in @($Root, $LogDir, $StateDir, $ReportDir, $PortalDir)) {
        if (-not (Test-Path -LiteralPath $d)) {
            New-Item -ItemType Directory -Path $d -Force | Out-Null
        }
    }
}

function HtmlEncode {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Sha256Text {
    param([Parameter(Mandatory)][string]$Text)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
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

    $Object | ConvertTo-Json -Depth 40 -Compress |
        Add-Content -LiteralPath $Path -Encoding UTF8
}

function Invoke-LogRotation {
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$MaxMB = $DefaultLogRotationMaxMB
    )

    if (Test-Path -LiteralPath $Path) {
        $file = Get-Item -LiteralPath $Path
        if ($file.Length -gt ($MaxMB * 1MB)) {
            $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
            Rename-Item -LiteralPath $Path -NewName "$($file.BaseName)_$stamp$($file.Extension)" -Force
        }
    }
}

function Write-Tangle {
    param(
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][string]$Summary,
        [Parameter(Mandatory)][AllowNull()][object]$Data
    )

    $prev = $null

    if (Test-Path -LiteralPath $TangleState) {
        try {
            $prev = (Get-Content -LiteralPath $TangleState -Raw | ConvertFrom-Json).last_hash
        }
        catch {
            $prev = $null
        }
    }

    $chainEvent = [ordered]@{
        time          = (Get-Date).ToString('o')
        host          = $env:COMPUTERNAME
        user          = $env:USERNAME
        type          = $Type
        summary       = $Summary
        previous_hash = $prev
        data          = $Data
    }

    $raw = $chainEvent | ConvertTo-Json -Depth 40 -Compress
    $hash = Sha256Text -Text $raw
    $chainEvent['hash'] = $hash

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

    [ordered]@{
        time     = (Get-Date).ToString('o')
        severity = $Severity
        title    = $Title
        message  = $Message
        score    = $Score
        data     = $Data
    }
}

function Get-HealthFromScore {
    param([Parameter(Mandatory)][int]$Score)

    if ($Score -ge $CriticalScoreThreshold) { return 'CRITICAL' }
    if ($Score -ge $HighScoreThreshold) { return 'HIGH' }
    if ($Score -ge $WarnScoreThreshold) { return 'WARN' }
    return 'OK'
}

function Get-SeverityFromScore {
    param([Parameter(Mandatory)][int]$Score)

    if ($Score -ge $CriticalScoreThreshold) { return 'CRITICAL' }
    if ($Score -ge $HighScoreThreshold) { return 'HIGH' }
    if ($Score -ge $WarnScoreThreshold) { return 'MEDIUM' }
    return 'LOW'
}

# =========================
# COLLECTORS
# =========================

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
            QuickScanEndTime,
            FullScanEndTime
    }
    catch {
        [pscustomobject]@{ Error = $_.Exception.Message }
    }
}

function Get-FirewallSafe {
    try {
        Get-NetFirewallProfile |
            Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
    }
    catch {
        @([pscustomobject]@{ Error = $_.Exception.Message })
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
            Where-Object { $_.TaskPath -notlike $TaskPathExcludePattern } |
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
        $procMap = @{}
        Get-Process | ForEach-Object {
            $procMap[$_.Id] = $_.ProcessName
        }

        Get-NetTCPConnection -State Established |
            ForEach-Object {
                [pscustomobject]@{
                    LocalAddress  = $_.LocalAddress
                    LocalPort     = $_.LocalPort
                    RemoteAddress = $_.RemoteAddress
                    RemotePort    = $_.RemotePort
                    State         = $_.State
                    PID           = $_.OwningProcess
                    Process       = $procMap[$_.OwningProcess]
                }
            }
    }
    catch {
        @([pscustomobject]@{ Error = $_.Exception.Message })
    }
}

function Get-WlanNetworksSafe {
    try {
        $raw = netsh wlan show networks mode=bssid 2>&1 | Out-String
    }
    catch {
        return @([pscustomobject]@{ Error = $_.Exception.Message })
    }

    $items = New-Object System.Collections.Generic.List[object]

    $ssid = $null
    $auth = $null
    $enc = $null

    foreach ($line in ($raw -split "`r?`n")) {
        $l = $line.Trim()

        if ($l -match '^SSID\s+\d+\s+:\s+(.*)$') {
            $ssid = $Matches[1]
            $auth = $null
            $enc = $null
        }
        elseif ($l -match '^Authentication\s+:\s+(.*)$') {
            $auth = $Matches[1]
        }
        elseif ($l -match '^Encryption\s+:\s+(.*)$') {
            $enc = $Matches[1]
        }
        elseif ($l -match '^BSSID\s+\d+\s+:\s+(.*)$') {
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
        elseif ($l -match '^Signal\s+:\s+(.*)$') {
            if ($items.Count -gt 0) { $items[$items.Count - 1].Signal = $Matches[1] }
        }
        elseif ($l -match '^Radio type\s+:\s+(.*)$') {
            if ($items.Count -gt 0) { $items[$items.Count - 1].RadioType = $Matches[1] }
        }
        elseif ($l -match '^Channel\s+:\s+(.*)$') {
            if ($items.Count -gt 0) { $items[$items.Count - 1].Channel = $Matches[1] }
        }
    }

    return $items
}

function Get-NetworkLocalSafe {
    $adapters = try {
        Get-NetAdapter |
            Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed
    }
    catch {
        @([pscustomobject]@{ Error = $_.Exception.Message })
    }

    $ipconfig = try {
        Get-NetIPConfiguration |
            Select-Object InterfaceAlias, IPv4Address, IPv6Address, IPv4DefaultGateway, DNSServer
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

function Get-LocalSnapshot {
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

# =========================
# BASELINE / ANALYSIS
# =========================

function Get-BaselineSnapshot {
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
        ConvertTo-Json -Depth 40 |
        Set-Content -LiteralPath $BaselinePath -Encoding UTF8
}

function Measure-SnapshotRisk {
    param([Parameter(Mandatory)][object]$Snapshot)

    $alerts = New-Object System.Collections.Generic.List[object]
    $score = 0

    # Defender
    if ($Snapshot.defender.PSObject.Properties.Name -contains 'RealTimeProtectionEnabled') {
        if ($Snapshot.defender.RealTimeProtectionEnabled -eq $false) {
            $score += 100
            $null = $alerts.Add((Add-Alert -Severity 'CRITICAL' -Title 'Defender Echtzeitschutz deaktiviert' -Message 'Windows Defender RealTimeProtectionEnabled ist FALSE.' -Score 100 -Data $Snapshot.defender))
        }
    }

    # Firewall
    foreach ($fw in @($Snapshot.firewall)) {
        if ($fw.Enabled -eq $false) {
            $score += 80
            $null = $alerts.Add((Add-Alert -Severity 'HIGH' -Title 'Firewall Profil deaktiviert' -Message "Firewall-Profil deaktiviert: $($fw.Name)" -Score 80 -Data $fw))
        }
    }

    # Risk Ports
    foreach ($c in @($Snapshot.connections)) {
        if ($null -eq $c.RemotePort) { continue }

        $remotePort = 0
        if (-not [int]::TryParse([string]$c.RemotePort, [ref]$remotePort)) { continue }

        if ($RiskPorts -contains $remotePort) {
            $sev = 'MEDIUM'
            $s = 45

            if ($remotePort -in @(445, 3389, 5985, 5986)) {
                $sev = 'HIGH'
                $s = 75
            }

            $score += $s
            $null = $alerts.Add((Add-Alert -Severity $sev -Title 'Risiko-Port Verbindung' -Message "Established TCP zu Risiko-Port $remotePort durch Prozess $($c.Process)." -Score $s -Data $c))
        }
    }

    # Suspicious command lines
    foreach ($p in @($Snapshot.processes)) {
        $cmd = ''
        if ($p.CommandLine) {
            $cmd = ([string]$p.CommandLine).ToLowerInvariant()
        }

        $procName = ''
        if ($p.Name) {
            $procName = ([string]$p.Name).ToLowerInvariant()
        }

        if ($procName -in @('powershell.exe', 'pwsh.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe')) {
            $hits = @()

            foreach ($pattern in $SuspiciousCmdPatterns) {
                if ($cmd.Contains($pattern)) {
                    $hits += $pattern
                }
            }

            if ($hits.Count -gt 0) {
                $s = 85
                $score += $s
                $null = $alerts.Add((Add-Alert -Severity 'HIGH' -Title 'Verdächtige Kommandozeile' -Message "Verdächtige Parameter erkannt bei $($p.Name)." -Score $s -Data ([ordered]@{
                            process = $p
                            hits    = $hits
                        })))
            }
        }
    }

    # Baseline / Delta
    $baseline = Get-BaselineSnapshot

    $delta = [ordered]@{
        baseline_exists = $null -ne $baseline
        new_admins      = @()
        new_neighbors   = @()
        new_wlan_bssid  = @()
        new_tasks       = @()
        new_services    = @()
    }

    if ($null -eq $baseline) {
        Save-Baseline -Snapshot $Snapshot
    }
    else {
        $oldAdmins = @($baseline.admins | ForEach-Object { $_.Name })
        foreach ($a in @($Snapshot.admins)) {
            if ($a.Name -and ($oldAdmins -notcontains $a.Name)) {
                $delta.new_admins += $a
                $score += 90
                $null = $alerts.Add((Add-Alert -Severity 'HIGH' -Title 'Neuer lokaler Administrator' -Message "Neuer Admin seit Baseline: $($a.Name)" -Score 90 -Data $a))
            }
        }

        $oldNeighbors = @($baseline.network.neighbors | ForEach-Object { "$($_.IPAddress)|$($_.LinkLayerAddress)" })
        foreach ($n in @($Snapshot.network.neighbors)) {
            $key = "$($n.IPAddress)|$($n.LinkLayerAddress)"
            if ($n.IPAddress -and ($oldNeighbors -notcontains $key)) {
                $delta.new_neighbors += $n
                $score += 25
            }
        }

        $oldBssid = @($baseline.wlan | ForEach-Object { $_.BSSID })
        foreach ($w in @($Snapshot.wlan)) {
            if ($w.BSSID -and ($oldBssid -notcontains $w.BSSID)) {
                $delta.new_wlan_bssid += $w
                $score += 10
            }
        }

        $oldTasks = @($baseline.tasks | ForEach-Object { "$($_.TaskPath)$($_.TaskName)" })
        foreach ($t in @($Snapshot.tasks)) {
            $key = "$($t.TaskPath)$($t.TaskName)"
            if ($t.TaskName -and ($oldTasks -notcontains $key)) {
                $delta.new_tasks += $t
                $score += 30
            }
        }

        $oldServices = @($baseline.services | ForEach-Object { $_.Name })
        foreach ($s in @($Snapshot.services)) {
            if ($s.Name -and ($oldServices -notcontains $s.Name)) {
                $delta.new_services += $s
                $score += 20
            }
        }
    }

    foreach ($a in @($alerts)) {
        Write-JsonLine -Path $AlertLog -Object $a
    }

    [ordered]@{
        time          = (Get-Date).ToString('o')
        score         = [Math]::Min($score, $MaxRiskScore)
        alert_count   = @($alerts).Count
        alerts        = $alerts
        delta         = $delta
        principles    = 'LOCAL / DEFENSIVE / READ-ONLY'
        core_sentence = 'Fakten vor Angst. Baseline vor Chaos. Sichtbarkeit vor Kontrolle.'
    }
}

# =========================
# HTML PORTAL
# =========================

function ConvertTo-HtmlTableRow {
    param(
        [AllowNull()][object[]]$Items,
        [Parameter(Mandatory)][string[]]$Props,
        [string]$EmptyText = 'Keine Daten'
    )

    $rows = New-Object System.Collections.Generic.List[string]
    foreach ($item in @($Items)) {
        $cells = foreach ($p in $Props) {
            "<td>$(HtmlEncode $item.$p)</td>"
        }

        $null = $rows.Add("<tr>$($cells -join '')</tr>")
    }

    if ($rows.Count -eq 0) {
        $null = $rows.Add("<tr><td colspan='$($Props.Count)'>$(HtmlEncode $EmptyText)</td></tr>")
    }

    return $rows
}

function Write-HudPortal {
    param(
        [Parameter(Mandatory)][object]$Snapshot,
        [Parameter(Mandatory)][object]$Analysis
    )

    $score = [int]$Analysis.score
    $health = Get-HealthFromScore -Score $score

    $lastHash = 'N/A'
    if (Test-Path -LiteralPath $TangleState) {
        try {
            $lastHash = (Get-Content -LiteralPath $TangleState -Raw | ConvertFrom-Json).last_hash
        }
        catch {
            $lastHash = 'N/A'
        }
    }

    $alertRows = New-Object System.Collections.Generic.List[string]
    foreach ($a in @($Analysis.alerts | Sort-Object score -Descending | Select-Object -First 50)) {
        $null = $alertRows.Add("<tr><td>$(HtmlEncode $a.severity)</td><td>$(HtmlEncode $a.title)</td><td>$(HtmlEncode $a.message)</td><td>$(HtmlEncode $a.score)</td><td>$(HtmlEncode $a.time)</td></tr>")
    }
    if ($alertRows.Count -eq 0) {
        $null = $alertRows.Add("<tr><td colspan='5'>Keine Alerts im aktuellen Lauf.</td></tr>")
    }

    $connRows = ConvertTo-HtmlTableRow -Items (@($Snapshot.connections) | Select-Object -First 100) -Props @('Process', 'PID', 'LocalAddress', 'LocalPort', 'RemoteAddress', 'RemotePort', 'State') -EmptyText 'Keine TCP-Verbindungen erfasst.'
    $procRows = ConvertTo-HtmlTableRow -Items (@($Snapshot.processes) | Select-Object -First 100) -Props @('Name', 'ProcessId', 'ParentProcessId', 'ExecutablePath', 'CommandLine') -EmptyText 'Keine Prozesse erfasst.'
    $wlanRows = ConvertTo-HtmlTableRow -Items (@($Snapshot.wlan) | Select-Object -First 100) -Props @('SSID', 'BSSID', 'Authentication', 'Encryption', 'Signal', 'RadioType', 'Channel') -EmptyText 'Keine WLAN-Daten erfasst.'
    $neighborRows = ConvertTo-HtmlTableRow -Items (@($Snapshot.network.neighbors) | Select-Object -First 100) -Props @('InterfaceAlias', 'IPAddress', 'LinkLayerAddress', 'State') -EmptyText 'Keine LAN-Nachbarn erfasst.'
    $adminRows = ConvertTo-HtmlTableRow -Items @($Snapshot.admins) -Props @('Name', 'ObjectClass', 'PrincipalSource') -EmptyText 'Keine Administrator-Einträge erfasst.'
    $taskRows = ConvertTo-HtmlTableRow -Items (@($Snapshot.tasks) | Select-Object -First 100) -Props @('TaskName', 'TaskPath', 'State') -EmptyText 'Keine Task-Daten erfasst.'
    $serviceRows = ConvertTo-HtmlTableRow -Items (@($Snapshot.services) | Select-Object -First 100) -Props @('Name', 'DisplayName', 'State', 'StartMode', 'StartName') -EmptyText 'Keine Service-Daten erfasst.'
    $fwRows = ConvertTo-HtmlTableRow -Items @($Snapshot.firewall) -Props @('Name', 'Enabled', 'DefaultInboundAction', 'DefaultOutboundAction') -EmptyText 'Keine Firewall-Daten erfasst.'

    $html = @"
<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="refresh" content="$PortalRefreshSeconds">
  <title>AVA 3.14 NEXT LAYER</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; }
    body { font-family: Segoe UI, Tahoma, Arial, sans-serif; background:#0f172a; color:#e2e8f0; margin:0; padding:20px; }
    h1,h2 { color:#22d3ee; margin:0 0 12px 0; }
    .meta { color:#94a3b8; margin:0 0 20px 0; font-size:0.9rem; }
    .cards { display:flex; gap:12px; flex-wrap:wrap; margin-bottom:20px; }
    .card { background:#111827; border:1px solid #1f2937; border-top:3px solid #22d3ee; padding:12px; min-width:150px; border-radius:8px; }
    .num { font-size:1.6rem; font-weight:700; }
    .lbl { color:#94a3b8; font-size:0.8rem; text-transform:uppercase; }
    .health-ok { color:#22c55e; }
    .health-warn { color:#eab308; }
    .health-high { color:#f97316; }
    .health-critical { color:#ef4444; }
    .section { margin-top:24px; }
    table { width:100%; border-collapse:collapse; font-size:0.82rem; }
    th,td { border-bottom:1px solid #1f2937; padding:7px 8px; text-align:left; vertical-align:top; word-break:break-word; }
    th { color:#93c5fd; background:#0b1220; }
    tr:hover td { background:#111827; }
    .footer { margin-top:24px; color:#64748b; font-size:0.75rem; border-top:1px solid #1f2937; padding-top:10px; }
  </style>
</head>
<body>
  <h1>AVA 3.14 NEXT LAYER — ALL</h1>
  <div class="meta">
    Defensiv / Lokal / Read-Only &nbsp;|&nbsp;
    Zeit: $(HtmlEncode $Snapshot.time) &nbsp;|&nbsp;
    Host: $(HtmlEncode $Snapshot.computer) &nbsp;|&nbsp;
    User: $(HtmlEncode $Snapshot.user) &nbsp;|&nbsp;
    Last Hash: $(HtmlEncode $lastHash)
  </div>

  <div class="cards">
    <div class="card"><div class="num">$($Analysis.score)</div><div class="lbl">Risk Score</div></div>
    <div class="card"><div class="num">$($Analysis.alert_count)</div><div class="lbl">Alert Count</div></div>
    <div class="card"><div class="num">$($Snapshot.connections.Count)</div><div class="lbl">TCP Established</div></div>
    <div class="card"><div class="num">$($Snapshot.processes.Count)</div><div class="lbl">Processes</div></div>
    <div class="card"><div class="num">$($Snapshot.wlan.Count)</div><div class="lbl">WLAN BSSID</div></div>
    <div class="card"><div class="num health-$($health.ToLowerInvariant())">$health</div><div class="lbl">Health</div></div>
  </div>

  <div class="section">
    <h2>Alerts (Top 50)</h2>
    <table><thead><tr><th>Severity</th><th>Title</th><th>Message</th><th>Score</th><th>Time</th></tr></thead><tbody>$($alertRows -join '')</tbody></table>
  </div>

  <div class="section">
    <h2>Firewall</h2>
    <table><thead><tr><th>Name</th><th>Enabled</th><th>DefaultInbound</th><th>DefaultOutbound</th></tr></thead><tbody>$($fwRows -join '')</tbody></table>
  </div>

  <div class="section">
    <h2>Administrators</h2>
    <table><thead><tr><th>Name</th><th>Class</th><th>Source</th></tr></thead><tbody>$($adminRows -join '')</tbody></table>
  </div>

  <div class="section">
    <h2>Scheduled Tasks (non-Microsoft)</h2>
    <table><thead><tr><th>TaskName</th><th>TaskPath</th><th>State</th></tr></thead><tbody>$($taskRows -join '')</tbody></table>
  </div>

  <div class="section">
    <h2>Running Services</h2>
    <table><thead><tr><th>Name</th><th>DisplayName</th><th>State</th><th>StartMode</th><th>StartName</th></tr></thead><tbody>$($serviceRows -join '')</tbody></table>
  </div>

  <div class="section">
    <h2>TCP Connections (Top 100)</h2>
    <table><thead><tr><th>Process</th><th>PID</th><th>LocalAddress</th><th>LocalPort</th><th>RemoteAddress</th><th>RemotePort</th><th>State</th></tr></thead><tbody>$($connRows -join '')</tbody></table>
  </div>

  <div class="section">
    <h2>Processes (Top 100)</h2>
    <table><thead><tr><th>Name</th><th>PID</th><th>PPID</th><th>Path</th><th>CommandLine</th></tr></thead><tbody>$($procRows -join '')</tbody></table>
  </div>

  <div class="section">
    <h2>WLAN (Top 100)</h2>
    <table><thead><tr><th>SSID</th><th>BSSID</th><th>Auth</th><th>Enc</th><th>Signal</th><th>Radio</th><th>Channel</th></tr></thead><tbody>$($wlanRows -join '')</tbody></table>
  </div>

  <div class="section">
    <h2>LAN Nachbarn (Top 100)</h2>
    <table><thead><tr><th>Interface</th><th>IP</th><th>MAC</th><th>State</th></tr></thead><tbody>$($neighborRows -join '')</tbody></table>
  </div>

  <div class="footer">
    Prinzipien: $(HtmlEncode $Analysis.principles) &nbsp;|&nbsp;
    Kernsatz: $(HtmlEncode $Analysis.core_sentence) &nbsp;|&nbsp;
    Logs: $(HtmlEncode $EventLog) / $(HtmlEncode $AlertLog) / $(HtmlEncode $TangleLog)
  </div>
</body>
</html>
"@

    Set-Content -LiteralPath $PortalHtml -Value $html -Encoding UTF8
}

# =========================
# TASK MANAGEMENT
# =========================

function Install-GuardianTask {
    if (-not $ScriptPath) {
        throw 'PSCommandPath is empty. Script must be started with -File.'
    }

    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy RemoteSigned -File `"$ScriptPath`" -RunOnce"

    $trigger = New-ScheduledTaskTrigger -Once `
        -At (Get-Date).AddMinutes(1) `
        -RepetitionInterval (New-TimeSpan -Seconds $IntervalSeconds) `
        -RepetitionDuration ([TimeSpan]::MaxValue)

    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest

    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null

    Write-JsonLine -Path $EventLog -Object ([ordered]@{
            time     = (Get-Date).ToString('o')
            category = 'task'
            severity = 'INFO'
            message  = "Scheduled Task installiert: $TaskName (alle ${IntervalSeconds}s)"
        })
}

function Remove-GuardianTask {
    [CmdletBinding(SupportsShouldProcess)]
    param()

    if ((Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) -and $PSCmdlet.ShouldProcess($TaskName, 'Unregister scheduled task')) {
        Unregister-ScheduledTask -TaskName $TaskName

        Write-JsonLine -Path $EventLog -Object ([ordered]@{
            time     = (Get-Date).ToString('o')
            category = 'task'
            severity = 'INFO'
            message  = "Scheduled Task entfernt: $TaskName"
        })
    }
}

# =========================
# ENGINE
# =========================

function Invoke-GuardianCycle {
    Invoke-LogRotation -Path $EventLog
    Invoke-LogRotation -Path $AlertLog
    Invoke-LogRotation -Path $TangleLog

    $snapshot = Get-LocalSnapshot
    $analysis = Measure-SnapshotRisk -Snapshot $snapshot

    $snapshot | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath $SnapshotJson -Encoding UTF8
    $analysis | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath $AnalysisJson -Encoding UTF8

    Write-JsonLine -Path $EventLog -Object ([ordered]@{
            time     = (Get-Date).ToString('o')
            category = 'snapshot'
            severity = Get-SeverityFromScore -Score $analysis.score
            message  = "Snapshot verarbeitet: score=$($analysis.score) alerts=$($analysis.alert_count)"
        })

    Write-Tangle -Type 'snapshot_analysis' -Summary "score=$($analysis.score) alerts=$($analysis.alert_count)" -Data ([ordered]@{
            snapshot_time = $snapshot.time
            analysis_time = $analysis.time
            score         = $analysis.score
            alert_count   = $analysis.alert_count
        })

    Write-HudPortal -Snapshot $snapshot -Analysis $analysis

    Write-Host ("[{0}] Score={1} Alerts={2} Portal={3}" -f (Get-Date).ToString('s'), $analysis.score, $analysis.alert_count, $PortalHtml) -ForegroundColor Cyan
}

# =========================
# MAIN
# =========================

Initialize-GuardianDirectory

if ($ResetBaseline -and (Test-Path -LiteralPath $BaselinePath)) {
    Remove-Item -LiteralPath $BaselinePath -Force
}

if ($RemoveTask) {
    Remove-GuardianTask
    exit 0
}

if ($InstallTask -and -not $RunOnce -and -not $Loop) {
    Install-GuardianTask
    exit 0
}

if ($Loop) {
    Write-Host "AVA 3.14 NEXT LAYER: Loop aktiv (${IntervalSeconds}s). Stop mit Ctrl+C." -ForegroundColor Green
    while ($true) {
        Invoke-GuardianCycle
        Start-Sleep -Seconds $IntervalSeconds
    }
}
else {
    Invoke-GuardianCycle

    if ($InstallTask) {
        Install-GuardianTask
    }
}
