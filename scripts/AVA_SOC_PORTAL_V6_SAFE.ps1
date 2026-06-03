#requires -Version 5.1
<#
AVA SOC PORTAL V6 SAFE EDITION
Lokal / Defensiv / Read-Only

Keine Angriffe
Keine Exploits
Keine Fremdscans
Keine automatische Ausbreitung
Keine Aenderungen am System

Funktionen:
- Host / MAC / IP Monitoring
- WLAN / LAN Neighbor Sicht
- Baseline + Delta Detection
- Timeline JSONL
- Risk Score
- Tangle Hash Chain
- HTML Security Dashboard
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$Now = Get-Date -Format "yyyyMMdd_HHmmss"

$Root      = Join-Path $env:USERPROFILE "Desktop\AVA_SOC_PORTAL_V6_SAFE"
$LogDir    = Join-Path $Root "Logs"
$StateDir  = Join-Path $Root "State"
$ReportDir = Join-Path $Root "Reports"

$SnapshotJson = Join-Path $ReportDir "snapshot_latest.json"
$AnalysisJson = Join-Path $ReportDir "analysis_latest.json"
$PortalHtml   = Join-Path $ReportDir "ava_soc_portal_v6_safe.html"

$TimelineLog  = Join-Path $LogDir "ava_v6_timeline.jsonl"
$AlertLog     = Join-Path $LogDir "ava_v6_alerts.jsonl"
$TangleLog    = Join-Path $LogDir "ava_v6_tangle.jsonl"
$TangleState  = Join-Path $StateDir "tangle_state.json"
$BaselinePath = Join-Path $StateDir "baseline.json"

$RiskPorts = @(21,23,135,139,445,3389,5985,5986)

foreach ($d in @($Root,$LogDir,$StateDir,$ReportDir)) {
    if (-not (Test-Path -LiteralPath $d)) {
        New-Item -ItemType Directory -Force -Path $d | Out-Null
    }
}

function ConvertTo-HtmlEncoded {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return "" }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-Sha256Text {
    param([string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join "")
}

function Write-JsonLine {
    param([string]$Path,[object]$Object)
    $Object | ConvertTo-Json -Depth 30 -Compress | Add-Content -LiteralPath $Path -Encoding UTF8
}

function Write-Tangle {
    param([string]$Type,[string]$Summary,[object]$Data)

    $prev = $null
    if (Test-Path -LiteralPath $TangleState) {
        try {
            $prev = (Get-Content -LiteralPath $TangleState -Raw | ConvertFrom-Json).last_hash
        } catch {
            $prev = $null
        }
    }

    $chainEntry = [ordered]@{
        time          = (Get-Date).ToString("o")
        computer      = $env:COMPUTERNAME
        user          = $env:USERNAME
        type          = $Type
        summary       = $Summary
        previous_hash = $prev
        data          = $Data
    }

    $raw = $chainEntry | ConvertTo-Json -Depth 30 -Compress
    $hash = Get-Sha256Text $raw
    $chainEntry["hash"] = $hash

    Write-JsonLine -Path $TangleLog -Object $chainEntry

    [pscustomobject]@{
        updated   = (Get-Date).ToString("o")
        last_hash = $hash
    } | ConvertTo-Json | Set-Content -LiteralPath $TangleState -Encoding UTF8
}

function Add-TimelineEvent {
    param([string]$Category,[string]$Title,[string]$Message,[string]$Severity,[object]$Data)

    Write-JsonLine -Path $TimelineLog -Object ([ordered]@{
        time     = (Get-Date).ToString("o")
        category = $Category
        title    = $Title
        message  = $Message
        severity = $Severity
        data     = $Data
    })
}

function Add-Alert {
    param([string]$Severity,[string]$Title,[string]$Message,[int]$Score,[object]$Data)

    $alert = [ordered]@{
        time     = (Get-Date).ToString("o")
        severity = $Severity
        title    = $Title
        message  = $Message
        score    = $Score
        data     = $Data
    }

    Write-JsonLine -Path $AlertLog -Object $alert
    Add-TimelineEvent -Category "Alert" -Title $Title -Message $Message -Severity $Severity -Data $Data
    return $alert
}

function Get-WlanNetworksSafe {
    try {
        $raw = netsh wlan show networks mode=bssid 2>&1 | Out-String
    } catch {
        return @([pscustomobject]@{ Error = $_.Exception.Message })
    }

    $items = New-Object System.Collections.Generic.List[object]
    $ssid = $null
    $auth = $null
    $enc  = $null

    foreach ($line in ($raw -split "`r?`n")) {
        $l = $line.Trim()

        if ($l -match "^SSID\s+\d+\s+:\s+(.*)$") {
            $ssid = $Matches[1]
            $auth = $null
            $enc  = $null
        }
        elseif ($l -match "^Authentication\s+:\s+(.*)$") {
            $auth = $Matches[1]
        }
        elseif ($l -match "^Encryption\s+:\s+(.*)$") {
            $enc = $Matches[1]
        }
        elseif ($l -match "^BSSID\s+\d+\s+:\s+(.*)$") {
            $items.Add([pscustomobject]@{
                SSID           = $ssid
                BSSID          = $Matches[1]
                Authentication = $auth
                Encryption     = $enc
                Signal         = $null
                RadioType      = $null
                Channel        = $null
            }) | Out-Null
        }
        elseif ($l -match "^Signal\s+:\s+(.*)$") {
            if ($items.Count -gt 0) { $items[$items.Count - 1].Signal = $Matches[1] }
        }
        elseif ($l -match "^Radio type\s+:\s+(.*)$") {
            if ($items.Count -gt 0) { $items[$items.Count - 1].RadioType = $Matches[1] }
        }
        elseif ($l -match "^Channel\s+:\s+(.*)$") {
            if ($items.Count -gt 0) { $items[$items.Count - 1].Channel = $Matches[1] }
        }
    }

    return $items
}

function Get-Snapshot {
    $procMap = @{}
    try { Get-Process | ForEach-Object { $procMap[$_.Id] = $_.ProcessName } } catch { $procMap = @{} }

    $connections = try {
        Get-NetTCPConnection -State Established | ForEach-Object {
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
    } catch {
        @([pscustomobject]@{ Error = $_.Exception.Message })
    }

    [ordered]@{
        time        = (Get-Date).ToString("o")
        computer    = $env:COMPUTERNAME
        user        = $env:USERNAME
        mode        = "LOCAL_DEFENSIVE_READ_ONLY"

        defender    = try { Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled,AntivirusEnabled,AntivirusSignatureLastUpdated } catch { [pscustomobject]@{ Error=$_.Exception.Message } }
        firewall    = try { Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction } catch { @([pscustomobject]@{ Error=$_.Exception.Message }) }
        adapters    = try { Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,MacAddress,LinkSpeed } catch { @([pscustomobject]@{ Error=$_.Exception.Message }) }
        neighbors   = try { Get-NetNeighbor -AddressFamily IPv4 | Where-Object { $_.State -ne "Unreachable" } | Select-Object InterfaceAlias,IPAddress,LinkLayerAddress,State } catch { @([pscustomobject]@{ Error=$_.Exception.Message }) }
        wlan        = Get-WlanNetworksSafe
        processes   = try { Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine } catch { @([pscustomobject]@{ Error=$_.Exception.Message }) }
        connections = $connections
        services    = try { Get-CimInstance Win32_Service | Where-Object State -eq "Running" | Select-Object Name,DisplayName,State,StartMode,StartName } catch { @([pscustomobject]@{ Error=$_.Exception.Message }) }
        tasks       = try { Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" } | Select-Object TaskName,TaskPath,State } catch { @([pscustomobject]@{ Error=$_.Exception.Message }) }
    }
}

function Get-BaselineSnapshot {
    if (Test-Path -LiteralPath $BaselinePath) {
        try {
            return Get-Content -LiteralPath $BaselinePath -Raw | ConvertFrom-Json
        } catch {
            return $null
        }
    }
    return $null
}

function Save-Baseline {
    param([object]$Snapshot)
    $Snapshot | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $BaselinePath -Encoding UTF8
}

function Measure-SnapshotRisk {
    param([object]$Snapshot)

    $alerts = New-Object System.Collections.Generic.List[object]
    $score = 0

    if ($Snapshot.defender.RealTimeProtectionEnabled -eq $false) {
        $score += 100
        $alerts.Add((Add-Alert "CRITICAL" "Defender Echtzeitschutz deaktiviert" "Windows Defender Echtzeitschutz ist aus." 100 $Snapshot.defender)) | Out-Null
    }

    foreach ($fw in @($Snapshot.firewall)) {
        if ($fw.Enabled -eq $false) {
            $score += 80
            $alerts.Add((Add-Alert "HIGH" "Firewall deaktiviert" "Firewall-Profil deaktiviert: $($fw.Name)" 80 $fw)) | Out-Null
        }
    }

    foreach ($c in @($Snapshot.connections)) {
        if ($null -ne $c.RemotePort -and ($RiskPorts -contains [int]$c.RemotePort)) {
            $s = 45
            $sev = "MEDIUM"
            if ([int]$c.RemotePort -in @(445,3389,5985,5986)) {
                $s = 75
                $sev = "HIGH"
            }
            $score += $s
            $alerts.Add((Add-Alert $sev "Risiko-Port Verbindung" "$($c.RemoteAddress):$($c.RemotePort) durch $($c.Process)" $s $c)) | Out-Null
        }
    }

    $baseline = Get-BaselineSnapshot
    $delta = [ordered]@{
        baseline_exists = $null -ne $baseline
        new_neighbors   = @()
        new_wlan_bssid  = @()
        new_processes   = @()
        new_services    = @()
        new_tasks       = @()
    }

    if ($null -eq $baseline) {
        Save-Baseline $Snapshot
        Add-TimelineEvent "Baseline" "Baseline erstellt" "Erster Snapshot wurde als Baseline gespeichert." "INFO" $null
    } else {
        $oldNeighbors = @($baseline.neighbors | ForEach-Object { "$($_.IPAddress)|$($_.LinkLayerAddress)" })
        foreach ($n in @($Snapshot.neighbors)) {
            $key = "$($n.IPAddress)|$($n.LinkLayerAddress)"
            if ($n.IPAddress -and ($oldNeighbors -notcontains $key)) {
                $delta.new_neighbors += $n
                $score += 20
            }
        }

        $oldBssid = @($baseline.wlan | ForEach-Object { $_.BSSID })
        foreach ($w in @($Snapshot.wlan)) {
            if ($w.BSSID -and ($oldBssid -notcontains $w.BSSID)) {
                $delta.new_wlan_bssid += $w
                $score += 10
            }
        }

        $oldProc = @($baseline.processes | ForEach-Object { $_.Name } | Sort-Object -Unique)
        foreach ($p in @($Snapshot.processes)) {
            if ($p.Name -and ($oldProc -notcontains $p.Name)) {
                $delta.new_processes += $p.Name
                $score += 5
            }
        }

        $oldServices = @($baseline.services | ForEach-Object { $_.Name })
        foreach ($s in @($Snapshot.services)) {
            if ($s.Name -and ($oldServices -notcontains $s.Name)) {
                $delta.new_services += $s
                $score += 20
            }
        }

        $oldTasks = @($baseline.tasks | ForEach-Object { "$($_.TaskPath)$($_.TaskName)" })
        foreach ($t in @($Snapshot.tasks)) {
            $key = "$($t.TaskPath)$($t.TaskName)"
            if ($t.TaskName -and ($oldTasks -notcontains $key)) {
                $delta.new_tasks += $t
                $score += 25
            }
        }

        if (@($delta.new_neighbors).Count -gt 0) {
            Add-TimelineEvent "Delta" "Neue LAN-Nachbarn" "$(@($delta.new_neighbors).Count) neue Nachbarn seit Baseline." "WARN" $delta.new_neighbors
        }

        if (@($delta.new_wlan_bssid).Count -gt 0) {
            Add-TimelineEvent "Delta" "Neue WLAN-BSSID" "$(@($delta.new_wlan_bssid).Count) neue WLAN-BSSID seit Baseline." "INFO" $delta.new_wlan_bssid
        }
    }

    [ordered]@{
        time        = (Get-Date).ToString("o")
        score       = [Math]::Min($score,999)
        alert_count = @($alerts).Count
        alerts      = $alerts
        delta       = $delta
    }
}

function ConvertTo-TableRow {
    param([object[]]$Items,[string[]]$Props,[string]$Empty="Keine Daten gefunden.")

    $rows = foreach ($item in @($Items)) {
        $tds = foreach ($p in $Props) { "<td>$(ConvertTo-HtmlEncoded $item.$p)</td>" }
        "<tr>$($tds -join '')</tr>"
    }

    if (-not $rows) {
        return "<tr><td colspan='$($Props.Count)'>$(ConvertTo-HtmlEncoded $Empty)</td></tr>"
    }

    return $rows
}

function Read-TimelineLast {
    if (Test-Path -LiteralPath $TimelineLog) {
        try {
            return Get-Content -LiteralPath $TimelineLog -Tail 100 | ForEach-Object { $_ | ConvertFrom-Json }
        } catch {
            return @()
        }
    }
    return @()
}

function Write-Portal {
    param([object]$Snapshot,[object]$Analysis)

    $score = [int]$Analysis.score
    $health = "OK"
    if ($score -ge 150) { $health = "WARN" }
    if ($score -ge 300) { $health = "HIGH" }
    if ($score -ge 500) { $health = "CRITICAL" }

    $lastHash = "N/A"
    if (Test-Path -LiteralPath $TangleState) {
        try {
            $lastHash = (Get-Content -LiteralPath $TangleState -Raw | ConvertFrom-Json).last_hash
        } catch {
            $lastHash = "N/A"
        }
    }

    $alertRows   = ConvertTo-TableRow @($Analysis.alerts) @("severity","title","message","score","time") "Keine Alerts gefunden."
    $wlanRows    = ConvertTo-TableRow @($Snapshot.wlan) @("SSID","BSSID","Authentication","Encryption","Signal","RadioType","Channel")
    $neiRows     = ConvertTo-TableRow @($Snapshot.neighbors) @("InterfaceAlias","IPAddress","LinkLayerAddress","State")
    $adpRows     = ConvertTo-TableRow @($Snapshot.adapters) @("Name","InterfaceDescription","Status","MacAddress","LinkSpeed")
    $connRows    = ConvertTo-TableRow (@($Snapshot.connections) | Select-Object -First 100) @("Process","PID","LocalAddress","LocalPort","RemoteAddress","RemotePort","State")
    $procRows    = ConvertTo-TableRow (@($Snapshot.processes) | Select-Object -First 100) @("Name","ProcessId","ParentProcessId","ExecutablePath","CommandLine")
    $fwRows      = ConvertTo-TableRow @($Snapshot.firewall) @("Name","Enabled","DefaultInboundAction","DefaultOutboundAction")
    $svcRows     = ConvertTo-TableRow (@($Snapshot.services) | Select-Object -First 100) @("Name","DisplayName","StartMode","StartName")
    $taskRows    = ConvertTo-TableRow (@($Snapshot.tasks) | Select-Object -First 100) @("TaskName","TaskPath","State")

    $timelineRows = foreach ($t in (Read-TimelineLast)) {
        "<tr><td>$(ConvertTo-HtmlEncoded $t.time)</td><td>$(ConvertTo-HtmlEncoded $t.category)</td><td>$(ConvertTo-HtmlEncoded $t.severity)</td><td>$(ConvertTo-HtmlEncoded $t.title)</td><td>$(ConvertTo-HtmlEncoded $t.message)</td></tr>"
    }
    if (-not $timelineRows) { $timelineRows = @("<tr><td colspan='5'>Noch keine Timeline Events.</td></tr>") }

    @"
<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<title>AVA SOC PORTAL V6 SAFE</title>
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
<div class="badge">AVA SOC PORTAL V6 SAFE</div>
<div class="badge">LOCAL / READ ONLY / DEFENSIVE</div>
<div class="badge">$(ConvertTo-HtmlEncoded $Now)</div>
</div>

<div>
<div class="subtitle">// SECURITY OPERATIONS VISIBILITY</div>
<h1>AVA SOC <span>PORTAL V6</span> SAFE</h1>
<div class="subtitle">BASELINE &middot; DELTA &middot; TANGLE &middot; DEFENDER &middot; WLAN &middot; NETWORK &middot; PROCESS &middot; TIMELINE</div>
</div>

<div class="grid">
<div class="card"><h2>Health</h2><div class="big status-$health">$health</div><div class="small">Score: $score / 999</div></div>
<div class="card"><h2>Alerts</h2><div class="big">$($Analysis.alert_count)</div><div class="small">Risk Events</div></div>
<div class="card"><h2>Connections</h2><div class="big">$(@($Snapshot.connections).Count)</div><div class="small">Established TCP</div></div>
<div class="card"><h2>Processes</h2><div class="big">$(@($Snapshot.processes).Count)</div><div class="small">Local Processes</div></div>
<div class="card"><h2>WLAN</h2><div class="big">$(@($Snapshot.wlan).Count)</div><div class="small">Visible BSSID</div></div>
<div class="card"><h2>Neighbors</h2><div class="big">$(@($Snapshot.neighbors).Count)</div><div class="small">LAN / ARP</div></div>
<div class="card"><h2>Computer</h2><div class="big" style="font-size:16px">$(ConvertTo-HtmlEncoded $Snapshot.computer)</div><div class="small">$(ConvertTo-HtmlEncoded $Snapshot.user)</div></div>
</div>

<div class="section legal">
<b>AVA SOC V6 SAFE EDITION:</b> Dieses System ist lokal, defensiv und read-only.<br>
Keine Angriffe &bull; Keine Exploits &bull; Keine Fremdscans &bull; Keine Systemänderungen.
</div>

<div class="section card">
<h2>Tangle Hash Chain</h2>
<div class="small">Letzter Hash:</div>
<div class="hash">$(ConvertTo-HtmlEncoded $lastHash)</div>
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
<h2>Timeline (letzte 100 Events)</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Time</th><th>Category</th><th>Severity</th><th>Title</th><th>Message</th></tr></thead>
<tbody>
$($timelineRows -join "`n")
</tbody>
</table>
</div>
</div>

<div class="section card">
<h2>Firewall Profile</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Name</th><th>Enabled</th><th>Inbound</th><th>Outbound</th></tr></thead>
<tbody>
$($fwRows -join "`n")
</tbody>
</table>
</div>
</div>

<div class="section card">
<h2>Netzwerkadapter</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Name</th><th>Description</th><th>Status</th><th>MAC</th><th>Speed</th></tr></thead>
<tbody>
$($adpRows -join "`n")
</tbody>
</table>
</div>
</div>

<div class="section card">
<h2>LAN Neighbors (ARP)</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Interface</th><th>IP</th><th>MAC</th><th>State</th></tr></thead>
<tbody>
$($neiRows -join "`n")
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
<h2>Established Connections</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Process</th><th>PID</th><th>Local</th><th>LPort</th><th>Remote</th><th>RPort</th><th>State</th></tr></thead>
<tbody>
$($connRows -join "`n")
</tbody>
</table>
</div>
</div>

<div class="section card">
<h2>Processes (top 100)</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Name</th><th>PID</th><th>PPID</th><th>Path</th><th>CommandLine</th></tr></thead>
<tbody>
$($procRows -join "`n")
</tbody>
</table>
</div>
</div>

<div class="section card">
<h2>Laufende Dienste</h2>
<div class="table-wrap">
<table>
<thead><tr><th>Name</th><th>DisplayName</th><th>StartMode</th><th>StartName</th></tr></thead>
<tbody>
$($svcRows -join "`n")
</tbody>
</table>
</div>
</div>

<div class="section card">
<h2>Geplante Aufgaben (non-Microsoft)</h2>
<div class="table-wrap">
<table>
<thead><tr><th>TaskName</th><th>TaskPath</th><th>State</th></tr></thead>
<tbody>
$($taskRows -join "`n")
</tbody>
</table>
</div>
</div>

<div class="section notice">
<b>AVA Hinweis:</b> Wichtig sind Veränderungen: neue LAN-Nachbarn, neue BSSID, Risiko-Ports,
neue Dienste oder Tasks, deaktivierter Defender oder deaktivierte Firewall.
</div>

<div class="footer">
<div>AVA SOC PORTAL V6 SAFE EDITION &bull; LOKAL / DEFENSIV / READ-ONLY</div>
<div>$(ConvertTo-HtmlEncoded $Snapshot.time)</div>
</div>

</div>
</body>
</html>
"@ | Set-Content -LiteralPath $PortalHtml -Encoding UTF8
}

Write-Host ""
Write-Host "AVA SOC PORTAL V6 SAFE startet..." -ForegroundColor Cyan

$snapshot = Get-Snapshot
$analysis = Measure-SnapshotRisk $snapshot

$snapshot | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $SnapshotJson -Encoding UTF8
$analysis | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $AnalysisJson -Encoding UTF8

Write-Tangle -Type "AVA_SOC_V6_SAFE_SNAPSHOT" -Summary "Lokaler defensiver Snapshot erstellt" -Data @{
    score    = $analysis.score
    alerts   = $analysis.alert_count
    computer = $snapshot.computer
    time     = $snapshot.time
}

Write-Portal -Snapshot $snapshot -Analysis $analysis

Write-Host "AVA SOC PORTAL V6 SAFE abgeschlossen." -ForegroundColor Green
Write-Host "Score: $($analysis.score)" -ForegroundColor Yellow
Write-Host "Portal: $PortalHtml" -ForegroundColor Cyan
Write-Host ""

Start-Process $PortalHtml
