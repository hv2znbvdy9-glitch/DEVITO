#requires -Version 5.1
<#
AVA 3.14 SAFE LOCAL NODE
Lokal / Defensiv / Read-Only

Keine Angriffe
Keine Exploits
Keine Fremdscans
Kein Auto-Spread
Keine Änderungen am System

Erstellt:
- Snapshot JSON
- Alerts JSONL
- Tangle Hash Chain
- HTML Portal
- Netzwerk-/System-/Defender-/Firewall-/Prozess-Sicht
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# =========================
# CONFIG
# =========================

$Root = Join-Path $env:USERPROFILE 'Desktop\AVA_3_14_SAFE_LOCAL_NODE'
$LogDir = Join-Path $Root 'Logs'
$StateDir = Join-Path $Root 'State'
$ReportDir = Join-Path $Root 'Reports'
$PortalDir = Join-Path $Root 'Portal'

$SnapshotJson = Join-Path $ReportDir 'snapshot_latest.json'
$AnalysisJson = Join-Path $ReportDir 'analysis_latest.json'
$AlertLog = Join-Path $LogDir 'alerts.jsonl'
$EventLog = Join-Path $LogDir 'events.jsonl'
$TangleLog = Join-Path $LogDir 'tangle.jsonl'
$TangleState = Join-Path $StateDir 'tangle_state.json'
$BaselinePath = Join-Path $StateDir 'baseline.json'
$PortalHtml = Join-Path $PortalDir 'index.html'
$PortalRefreshSeconds = 60
$MaxPortalAlerts = 50
$MaxRiskScore = 999
$CoreSentence = 'Fakten vor Angst. Baseline vor Chaos. Sichtbarkeit vor Kontrolle.'

$RiskPorts = @(21, 23, 135, 139, 445, 3389, 5985, 5986)

$SuspiciousPatterns = @(
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

# =========================
# HELPERS
# =========================

function Initialize-DirectoryPath {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Force -Path $Path | Out-Null
    }
}

function Initialize-NodeDirectoryLayout {
    foreach ($d in @($Root, $LogDir, $StateDir, $ReportDir, $PortalDir)) {
        Initialize-DirectoryPath -Path $d
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

    $Object |
        ConvertTo-Json -Depth 40 -Compress |
        Add-Content -LiteralPath $Path -Encoding UTF8
}

function Write-Tangle {
    param(
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][string]$Summary,
        [AllowNull()][object]$Data
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
        computer      = $env:COMPUTERNAME
        user          = $env:USERNAME
        type          = $Type
        summary       = $Summary
        previous_hash = $prev
        data          = $Data
    }

    $raw = $chainEvent | ConvertTo-Json -Depth 40 -Compress
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

    [ordered]@{
        time     = (Get-Date).ToString('o')
        severity = $Severity
        title    = $Title
        message  = $Message
        score    = $Score
        data     = $Data
    }
}

function ConvertTo-TableRow {
    param(
        [AllowNull()][object[]]$Items,
        [Parameter(Mandatory)][string[]]$Props,
        [string]$EmptyText = 'Keine Daten gefunden.'
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

    return $rows.ToArray()
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

    if ($LASTEXITCODE -ne 0) {
        return @([pscustomobject]@{
                Error = "netsh wlan show networks mode=bssid failed with exit code $LASTEXITCODE (z.B. WLAN deaktiviert, WLAN-Dienst aus oder kein WLAN-Adapter vorhanden)."
                Raw   = $raw.Trim()
            })
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

    return $items.ToArray()
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

# =========================
# BASELINE + ANALYSIS
# =========================

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
        ConvertTo-Json -Depth 40 |
        Set-Content -LiteralPath $BaselinePath -Encoding UTF8
}

function Measure-SnapshotRisk {
    param([Parameter(Mandatory)][object]$Snapshot)

    $alerts = New-Object System.Collections.Generic.List[object]
    $score = 0

    if ($Snapshot.defender.PSObject.Properties.Name -contains 'RealTimeProtectionEnabled') {
        if ($Snapshot.defender.RealTimeProtectionEnabled -eq $false) {
            $score += 100
            $null = $alerts.Add((Add-Alert -Severity 'CRITICAL' -Title 'Defender Echtzeitschutz deaktiviert' -Message 'Windows Defender Echtzeitschutz ist aus.' -Score 100 -Data $Snapshot.defender))
        }
    }

    foreach ($fw in @($Snapshot.firewall)) {
        if ($fw.Enabled -eq $false) {
            $score += 80
            $null = $alerts.Add((Add-Alert -Severity 'HIGH' -Title 'Firewall Profil deaktiviert' -Message "Firewall-Profil deaktiviert: $($fw.Name)" -Score 80 -Data $fw))
        }
    }

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

    foreach ($p in @($Snapshot.processes)) {
        if ($p.ProcessId -eq $PID) { continue }

        $cmd = ''
        if ($p.CommandLine) {
            $cmd = ([string]$p.CommandLine).ToLowerInvariant()
        }

        $procName = ''
        if ($p.Name) {
            $procName = ([string]$p.Name).ToLowerInvariant()
        }

        if ($procName -in $SuspiciousProcessNames) {
            $hits = New-Object System.Collections.Generic.List[string]
            foreach ($pattern in $SuspiciousPatterns) {
                if ($cmd.Contains($pattern)) {
                    $null = $hits.Add($pattern)
                }
            }

            if ($hits.Count -gt 0) {
                $score += 85
                $null = $alerts.Add((Add-Alert -Severity 'HIGH' -Title 'Verdächtige Kommandozeile' -Message "Verdächtige Parameter erkannt bei $($p.Name)." -Score 85 -Data ([ordered]@{
                            process = $p
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
        foreach ($svc in @($Snapshot.services)) {
            if ($svc.Name -and ($oldServices -notcontains $svc.Name)) {
                $delta.new_services += $svc
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
        principles    = 'LOCAL / DEFENSIVE / READ-ONLY / NO AUTO-SPREAD'
        core_sentence = $CoreSentence
    }
}

# =========================
# PORTAL
# =========================

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

    $alertRows = foreach ($a in @($Analysis.alerts | Sort-Object score -Descending | Select-Object -First $MaxPortalAlerts)) {
        "<tr><td>$(HtmlEncode $a.severity)</td><td>$(HtmlEncode $a.title)</td><td>$(HtmlEncode $a.message)</td><td>$(HtmlEncode $a.score)</td><td>$(HtmlEncode $a.time)</td></tr>"
    }
    if (-not $alertRows) {
        $alertRows = "<tr><td colspan='5' style='color:#8fa3ad;'>Keine Alerts gefunden.</td></tr>"
    }

    $connRows = ConvertTo-TableRow -Items (@($Snapshot.connections) | Select-Object -First 100) -Props @('Process', 'PID', 'LocalAddress', 'LocalPort', 'RemoteAddress', 'RemotePort', 'State')
    $procRows = ConvertTo-TableRow -Items (@($Snapshot.processes) | Select-Object -First 100) -Props @('Name', 'ProcessId', 'ParentProcessId', 'ExecutablePath', 'CommandLine')
    $wlanRows = ConvertTo-TableRow -Items (@($Snapshot.wlan) | Select-Object -First 100) -Props @('SSID', 'BSSID', 'Authentication', 'Encryption', 'Signal', 'RadioType', 'Channel')
    $neighborRows = ConvertTo-TableRow -Items (@($Snapshot.network.neighbors) | Select-Object -First 100) -Props @('InterfaceAlias', 'IPAddress', 'LinkLayerAddress', 'State')
    $adminRows = ConvertTo-TableRow -Items @($Snapshot.admins) -Props @('Name', 'ObjectClass', 'PrincipalSource')
    $taskRows = ConvertTo-TableRow -Items (@($Snapshot.tasks) | Select-Object -First 100) -Props @('TaskName', 'TaskPath', 'State')
    $serviceRows = ConvertTo-TableRow -Items (@($Snapshot.services) | Select-Object -First 100) -Props @('Name', 'DisplayName', 'State', 'StartMode', 'StartName')
    $fwRows = ConvertTo-TableRow -Items @($Snapshot.firewall) -Props @('Name', 'Enabled', 'DefaultInboundAction', 'DefaultOutboundAction')

    $html = @"
<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="$PortalRefreshSeconds">
<title>AVA 3.14 SAFE LOCAL NODE</title>
<style>
:root{--bg:#05080c;--panel:#0c1520dd;--line:#17384f;--green:#19ff8f;--blue:#22a7ff;--text:#eaf6ff;--muted:#8fa3ad;--warn:#ffcc66;--danger:#ff5d6c}
*{box-sizing:border-box}
body{margin:0;padding:34px;background:linear-gradient(rgba(255,255,255,.025) 1px,transparent 1px),linear-gradient(90deg,rgba(255,255,255,.025) 1px,transparent 1px),radial-gradient(circle at top,#102033 0%,#05080c 60%);background-size:60px 60px,60px 60px,cover;color:var(--text);font-family:Consolas,"Segoe UI",monospace}
.frame{border:1px solid rgba(25,255,143,.35);padding:26px;min-height:92vh;box-shadow:0 0 35px rgba(25,255,143,.08)}
.topbar{display:flex;justify-content:space-between;border-bottom:1px solid var(--line);padding-bottom:18px;margin-bottom:30px;gap:12px;flex-wrap:wrap}
.badge{border:1px solid rgba(25,255,143,.45);color:var(--green);padding:8px 14px;letter-spacing:3px;font-size:12px}
h1{font-size:48px;margin:10px 0 4px 0;letter-spacing:3px;line-height:1}
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
pre{white-space:pre-wrap;word-break:break-word;color:#d8f5ff}
.legal{border-left:4px solid var(--green);background:rgba(25,255,143,.06);padding:16px;color:#bfffdc}
.hash{word-break:break-all;color:var(--muted);font-size:12px}
.footer{margin-top:30px;padding-top:18px;border-top:1px solid var(--line);color:var(--muted);display:flex;justify-content:space-between;gap:14px;flex-wrap:wrap;font-size:12px;letter-spacing:2px}
.status-OK{color:var(--green)}
.status-WARN{color:var(--warn)}
.status-HIGH,.status-CRITICAL{color:var(--danger)}
</style>
</head>
<body>
<div class="frame">
<div class="topbar"><div class="badge">AVA 3.14 SAFE LOCAL NODE</div><div class="badge">LOCAL / DEFENSIVE / READ-ONLY</div></div>
<div><div class="subtitle">// UNIFIED LOCAL DEFENSIVE VISIBILITY</div><h1>AVA <span>3.14</span></h1><div class="subtitle">SOC · MEMORY LINK · TANGLE · BASELINE · DELTA · HUD PORTAL</div></div>
<div class="grid">
<div class="card"><h2>Health</h2><div class="big status-$health">$health</div><div class="small">Score: $score</div></div>
<div class="card"><h2>Alerts</h2><div class="big">$($Analysis.alert_count)</div><div class="small">Risk Events</div></div>
<div class="card"><h2>Connections</h2><div class="big">$(@($Snapshot.connections).Count)</div><div class="small">Established TCP</div></div>
<div class="card"><h2>Processes</h2><div class="big">$(@($Snapshot.processes).Count)</div><div class="small">Local Processes</div></div>
<div class="card"><h2>WLAN</h2><div class="big">$(@($Snapshot.wlan).Count)</div><div class="small">Visible BSSID</div></div>
<div class="card"><h2>Neighbors</h2><div class="big">$(@($Snapshot.network.neighbors).Count)</div><div class="small">LAN / ARP</div></div>
</div>
<div class="section legal"><b>Kernsatz:</b> $(HtmlEncode $CoreSentence)<br>Dieses System ist lokal, defensiv und read-only. Keine Angriffe, keine Exploits, keine fremden Ziele, kein Auto-Spread.</div>
<div class="section card"><h2>Tangle Hash Chain</h2><div class="small">Letzter Hash:</div><div class="hash">$(HtmlEncode $lastHash)</div></div>

<div class="section card"><h2>Alerts</h2><div class="table-wrap"><table><tr><th>Severity</th><th>Title</th><th>Message</th><th>Score</th><th>Time</th></tr>$($alertRows -join "`n")</table></div></div>
<div class="section card"><h2>Firewall</h2><div class="table-wrap"><table><tr><th>Name</th><th>Enabled</th><th>DefaultInbound</th><th>DefaultOutbound</th></tr>$($fwRows -join "`n")</table></div></div>
<div class="section card"><h2>Administrators</h2><div class="table-wrap"><table><tr><th>Name</th><th>Class</th><th>Source</th></tr>$($adminRows -join "`n")</table></div></div>
<div class="section card"><h2>Scheduled Tasks</h2><div class="table-wrap"><table><tr><th>TaskName</th><th>TaskPath</th><th>State</th></tr>$($taskRows -join "`n")</table></div></div>
<div class="section card"><h2>Services</h2><div class="table-wrap"><table><tr><th>Name</th><th>DisplayName</th><th>State</th><th>StartMode</th><th>StartName</th></tr>$($serviceRows -join "`n")</table></div></div>
<div class="section card"><h2>TCP Connections</h2><div class="table-wrap"><table><tr><th>Process</th><th>PID</th><th>LocalAddress</th><th>LocalPort</th><th>RemoteAddress</th><th>RemotePort</th><th>State</th></tr>$($connRows -join "`n")</table></div></div>
<div class="section card"><h2>Processes</h2><div class="table-wrap"><table><tr><th>Name</th><th>PID</th><th>PPID</th><th>Path</th><th>CommandLine</th></tr>$($procRows -join "`n")</table></div></div>
<div class="section card"><h2>WLAN</h2><div class="table-wrap"><table><tr><th>SSID</th><th>BSSID</th><th>Auth</th><th>Enc</th><th>Signal</th><th>Radio</th><th>Channel</th></tr>$($wlanRows -join "`n")</table></div></div>
<div class="section card"><h2>LAN Neighbors</h2><div class="table-wrap"><table><tr><th>Interface</th><th>IP</th><th>MAC</th><th>State</th></tr>$($neighborRows -join "`n")</table></div></div>

<div class="footer"><div>Principles: $(HtmlEncode $Analysis.principles)</div><div>Logs: $(HtmlEncode $EventLog) / $(HtmlEncode $AlertLog) / $(HtmlEncode $TangleLog)</div></div>
</div>
</body>
</html>
"@

    $html | Set-Content -LiteralPath $PortalHtml -Encoding UTF8
}

# =========================
# ENGINE
# =========================

function Invoke-Ava {
    Initialize-NodeDirectoryLayout

    $snapshot = Get-Snapshot
    $analysis = Measure-SnapshotRisk -Snapshot $snapshot

    Write-JsonLine -Path $EventLog -Object $snapshot

    $snapshot |
        ConvertTo-Json -Depth 40 |
        Set-Content -LiteralPath $SnapshotJson -Encoding UTF8

    $analysis |
        ConvertTo-Json -Depth 40 |
        Set-Content -LiteralPath $AnalysisJson -Encoding UTF8

    Write-Tangle -Type 'AVA_3_14_SAFE_LOCAL_NODE' -Summary 'Lokaler defensiver Snapshot erstellt' -Data ([ordered]@{
            time        = $snapshot.time
            computer    = $snapshot.computer
            user        = $snapshot.user
            score       = $analysis.score
            alert_count = $analysis.alert_count
            mode        = 'LOCAL_DEFENSIVE_READ_ONLY_NO_AUTOSPREAD'
        })

    Write-Portal -Snapshot $snapshot -Analysis $analysis

    Write-Host ''
    Write-Host 'AVA 3.14 SAFE LOCAL NODE abgeschlossen.' -ForegroundColor Green
    Write-Host "Score:  $($analysis.score)" -ForegroundColor Yellow
    Write-Host "Alerts: $($analysis.alert_count)" -ForegroundColor Yellow
    Write-Host "Root:   $Root" -ForegroundColor Cyan
    Write-Host "Portal: $PortalHtml" -ForegroundColor Cyan
    Write-Host ''
    Write-Host $CoreSentence -ForegroundColor Green

    try {
        Start-Process $PortalHtml -ErrorAction Stop
    }
    catch {
        Write-Host "Portal konnte nicht automatisch geöffnet werden: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

Invoke-Ava
