<#
AVA SAFE STANDARD (V6)
Lokal / Defensiv / Read-Only
Keine Angriffe / Keine Exploits / Keine Fremdscans / Keine automatische Ausbreitung / Keine Änderungen am System
#>

#requires -RunAsAdministrator
<#
AVA v4 PORTAL + LIVE DASHBOARD + TANGLE SAFE + AUTO DEFENSE MODE
Lokal / Defensiv / Kontrolliert

Start:
powershell -ExecutionPolicy Bypass -File .\AVA_v4_Portal.ps1 -RunOnce

Live-Modus:
powershell -ExecutionPolicy Bypass -File .\AVA_v4_Portal.ps1 -Live

Kontrollierter Auto-Defense-Modus:
powershell -ExecutionPolicy Bypass -File .\AVA_v4_Portal.ps1 -Live -AutoDefense

Rollback aller AVA-Block-Regeln:
powershell -ExecutionPolicy Bypass -File .\AVA_v4_Portal.ps1 -RollbackBlocks
#>

param(
    [switch]$RunOnce,
    [switch]$Live,
    [switch]$AutoDefense,
    [switch]$RollbackBlocks,
    [int]$IntervalSeconds = 10
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# =========================
# CONFIG
# =========================
$Root      = "C:\Windows\SecurityGuardian"
$LogDir    = Join-Path $Root "Logs"
$ReportDir = Join-Path $Root "Reports"
$StateDir  = Join-Path $Root "State"

$PortalHtml = Join-Path $ReportDir "ava_v4_portal_live.html"
$GraphJson  = Join-Path $ReportDir "ava_v4_graph.json"
$EventLog   = Join-Path $LogDir "ava_v4_events.jsonl"
$AlertLog   = Join-Path $LogDir "ava_v4_alerts.jsonl"
$ChainFile  = Join-Path $StateDir "ava_v4_tangle_chain.jsonl"
$BlockState = Join-Path $StateDir "ava_v4_blocks.jsonl"

$RulePrefix = "AVA_v4_Block_"

$HighRiskPorts = @(21,23,135,139,445,3389,4444,5555,5900,5985,5986,8080,8443,9001,1337)

$NeverBlockIPs = @(
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "::",
    "255.255.255.255"
)

$AllowedPrivatePrefixes = @(
    "^10\.",
    "^192\.168\.",
    "^172\.(1[6-9]|2[0-9]|3[0-1])\.",
    "^169\.254\."
)

$SuspiciousPSFlags = @(
    "-enc",
    "encodedcommand",
    "-nop",
    "-w hidden",
    "windowstyle hidden",
    "-executionpolicy bypass",
    "-ep bypass",
    "iex ",
    "invoke-expression"
)

foreach ($d in @($Root,$LogDir,$ReportDir,$StateDir)) {
    if (-not (Test-Path -LiteralPath $d)) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
    }
}

# =========================
# HELPERS
# =========================
function Write-JsonLine {
    param([string]$Path,[object]$Object)
    $Object | ConvertTo-Json -Depth 20 -Compress | Add-Content -Path $Path -Encoding UTF8
}

function Get-FileSha256 {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return "" }
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash
}

function New-HashString {
    param([string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    $hash = $sha.ComputeHash($bytes)
    return ([BitConverter]::ToString($hash)).Replace("-","").ToLowerInvariant()
}

function Is-PrivateIP {
    param([string]$IP)
    foreach ($p in $AllowedPrivatePrefixes) {
        if ($IP -match $p) { return $true }
    }
    return $false
}

function HtmlEncode {
    param([object]$Value)
    return [System.Net.WebUtility]::HtmlEncode(($Value | Out-String).Trim())
}

function Add-TangleEvent {
    param(
        [string]$Type,
        [string]$Severity,
        [int]$Score,
        [string]$Summary,
        [object]$Details
    )

    $lastHash = ""
    if (Test-Path -LiteralPath $ChainFile) {
        $lastLine = Get-Content -LiteralPath $ChainFile -Tail 1 -ErrorAction SilentlyContinue
        if ($lastLine) {
            try {
                $lastObj = $lastLine | ConvertFrom-Json
                $lastHash = $lastObj.Hash
            } catch { Write-Debug "Could not parse chain entry: $($_.Exception.Message)" }
        }
    }

    $eventEntry = [ordered]@{
        Time       = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Type       = $Type
        Severity   = $Severity
        Score      = $Score
        Summary    = $Summary
        ParentHash = $lastHash
        Details    = $Details
    }

    $raw = ($eventEntry | ConvertTo-Json -Depth 20 -Compress)
    $hash = New-HashString $raw
    $eventEntry["Hash"] = $hash

    $obj = [PSCustomObject]$eventEntry

    Write-JsonLine -Path $EventLog -Object $obj
    Write-JsonLine -Path $ChainFile -Object $obj

    if ($Severity -in @("MEDIUM","HIGH","CRITICAL")) {
        Write-JsonLine -Path $AlertLog -Object $obj
    }

    return $obj
}

function Rollback-Blocks {
    $rules = Get-NetFirewallRule -DisplayName "$RulePrefix*" -ErrorAction SilentlyContinue
    if (-not $rules) {
        Write-Host "Keine AVA v4 Block-Regeln gefunden." -ForegroundColor Yellow
        return
    }

    foreach ($r in $rules) {
        Remove-NetFirewallRule -Name $r.Name -ErrorAction SilentlyContinue
        Write-Host "Entfernt: $($r.DisplayName)" -ForegroundColor Green
    }
}

function Safe-BlockIP {
    param([string]$RemoteIP,[string]$Reason)

    if (-not $AutoDefense) {
        Add-TangleEvent -Type "auto_defense_preview" -Severity "MEDIUM" -Score 40 -Summary "AutoDefense wäre ausgelöst worden, ist aber deaktiviert" -Details @{
            RemoteIP = $RemoteIP
            Reason   = $Reason
            Action   = "Preview only"
        } | Out-Null
        return
    }

    if (-not $RemoteIP) { return }
    if ($NeverBlockIPs -contains $RemoteIP) { return }

    if (Is-PrivateIP $RemoteIP) {
        Add-TangleEvent -Type "auto_defense_skip" -Severity "INFO" -Score 0 -Summary "Private/lokale IP nicht automatisch geblockt" -Details @{
            RemoteIP = $RemoteIP
            Reason = $Reason
        } | Out-Null
        return
    }

    $safeName = ($RemoteIP -replace "[^a-zA-Z0-9\.\-]", "_")
    $ruleName = "$RulePrefix$safeName"

    $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
    if ($existing) { return }

    New-NetFirewallRule `
        -DisplayName $ruleName `
        -Direction Inbound `
        -Action Block `
        -RemoteAddress $RemoteIP `
        -Profile Any `
        -Description "AVA v4 AutoDefense: $Reason" | Out-Null

    $entry = [PSCustomObject]@{
        Time = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        RuleName = $ruleName
        RemoteIP = $RemoteIP
        Reason = $Reason
    }

    Write-JsonLine -Path $BlockState -Object $entry

    Add-TangleEvent -Type "auto_defense_block" -Severity "HIGH" -Score 85 -Summary "Remote-IP automatisch geblockt" -Details $entry | Out-Null
}

if ($RollbackBlocks) {
    Rollback-Blocks
    return
}

# =========================
# SNAPSHOT ENGINE
# =========================
function Invoke-AVA-Snapshot {

    $events = New-Object System.Collections.Generic.List[object]
    $risk = 0

    $system = [PSCustomObject]@{
        Computer    = $env:COMPUTERNAME
        User        = $env:USERNAME
        Time        = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        AutoDefense = [bool]$AutoDefense
    }

    $events.Add((Add-TangleEvent -Type "system" -Severity "INFO" -Score 0 -Summary "AVA v4 Snapshot gestartet" -Details $system)) | Out-Null

    # Firewall
    try {
        $fw = Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction
        foreach ($p in $fw) {
            if (-not $p.Enabled) {
                $risk += 100
                $events.Add((Add-TangleEvent -Type "firewall" -Severity "CRITICAL" -Score 100 -Summary "Firewall Profil deaktiviert" -Details $p)) | Out-Null
            }
        }
    } catch { Write-Debug "Firewall status unavailable: $($_.Exception.Message)" }

    # Defender
    try {
        $def = Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,IsTamperProtected,AntivirusSignatureLastUpdated
        if (-not $def.RealTimeProtectionEnabled) {
            $risk += 100
            $events.Add((Add-TangleEvent -Type "defender" -Severity "CRITICAL" -Score 100 -Summary "Defender Echtzeitschutz deaktiviert" -Details $def)) | Out-Null
        } else {
            $events.Add((Add-TangleEvent -Type "defender" -Severity "INFO" -Score 0 -Summary "Defender Echtzeitschutz aktiv" -Details $def)) | Out-Null
        }
    } catch {
        $risk += 30
        $events.Add((Add-TangleEvent -Type "defender" -Severity "MEDIUM" -Score 30 -Summary "Defender Status konnte nicht gelesen werden" -Details $_.Exception.Message)) | Out-Null
    }

    # TCP + Process
    $connections = @()
    try {
        $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue |
            Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess

        $procMap = @{}
        Get-Process | ForEach-Object { $procMap[$_.Id] = $_.ProcessName }

        $connProc = $connections | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,
            @{Name="ProcessName";Expression={
                if ($procMap.ContainsKey($_.OwningProcess)) { $procMap[$_.OwningProcess] } else { "Unknown" }
            }}

        $listenRisk = $connProc | Where-Object { $_.State -eq "Listen" -and ($HighRiskPorts -contains $_.LocalPort) }
        if ($listenRisk) {
            $risk += 80
            $events.Add((Add-TangleEvent -Type "network" -Severity "HIGH" -Score 80 -Summary "Auffällige Listening Ports erkannt" -Details $listenRisk)) | Out-Null
        }

        $remoteGroups = $connProc |
            Where-Object {
                $_.RemoteAddress -and
                $_.RemoteAddress -notin $NeverBlockIPs -and
                $_.RemoteAddress -notlike "fe80*"
            } |
            Group-Object RemoteAddress |
            Sort-Object Count -Descending

        $topRemote = $remoteGroups | Select-Object -First 10 Name,Count

        $events.Add((Add-TangleEvent -Type "network" -Severity "INFO" -Score 0 -Summary "Top Remote IPs erfasst" -Details $topRemote)) | Out-Null

        foreach ($g in $remoteGroups) {
            if ($g.Count -ge 40) {
                $risk += 85
                $details = @{
                    RemoteIP    = $g.Name
                    Connections = $g.Count
                    Reason      = "Viele TCP-Verbindungen von einer Quelle"
                }

                $events.Add((Add-TangleEvent -Type "scan_detection" -Severity "HIGH" -Score 85 -Summary "Mögliches Scan-/Flood-Muster erkannt" -Details $details)) | Out-Null
                Safe-BlockIP -RemoteIP $g.Name -Reason "Viele TCP-Verbindungen von einer Quelle"
            }
        }
    } catch {
        $risk += 30
        $events.Add((Add-TangleEvent -Type "network" -Severity "MEDIUM" -Score 30 -Summary "Netzwerk-Analyse fehlgeschlagen" -Details $_.Exception.Message)) | Out-Null
    }

    # PowerShell audit
    try {
        $ps = Get-CimInstance Win32_Process |
            Where-Object { $_.Name -in @("powershell.exe","pwsh.exe") } |
            Select-Object ProcessId,Name,CommandLine,CreationDate

        foreach ($p in $ps) {
            $cmd = ""
            if ($p.CommandLine) { $cmd = $p.CommandLine.ToLowerInvariant() }

            $hits = @(foreach ($flag in $SuspiciousPSFlags) {
                if ($cmd.Contains($flag)) { $flag }
            })

            if ($hits.Count -gt 0) {
                $risk += 95
                $events.Add((Add-TangleEvent -Type "process" -Severity "CRITICAL" -Score 95 -Summary "Auffälliger PowerShell Prozess erkannt" -Details @{
                    PID         = $p.ProcessId
                    Name        = $p.Name
                    Flags       = $hits
                    CommandLine = $p.CommandLine
                })) | Out-Null
            }
        }
    } catch { Write-Debug "PowerShell process audit unavailable: $($_.Exception.Message)" }

    # Admins
    try {
        $admins = Get-LocalGroupMember -Group "Administrators" | Select-Object Name,ObjectClass,PrincipalSource,SID
        $events.Add((Add-TangleEvent -Type "identity" -Severity "INFO" -Score 0 -Summary "Lokale Administratoren erfasst" -Details $admins)) | Out-Null
    } catch { Write-Debug "Admins not available: $($_.Exception.Message)" }

    # Tasks
    try {
        $tasks = Get-ScheduledTask |
            Where-Object { $_.TaskPath -notlike "\Microsoft*" } |
            Select-Object TaskName,TaskPath,State

        $events.Add((Add-TangleEvent -Type "persistence_audit" -Severity "INFO" -Score 0 -Summary "Nicht-Microsoft Scheduled Tasks erfasst" -Details $tasks)) | Out-Null
    } catch { Write-Debug "Scheduled tasks unavailable: $($_.Exception.Message)" }

    # Health
    try {
        $cpu = (Get-CimInstance Win32_Processor | Measure-Object LoadPercentage -Average).Average
        $os = Get-CimInstance Win32_OperatingSystem
        $ramUsedGB  = [math]::Round(($os.TotalVisibleMemorySize - $os.FreePhysicalMemory) / 1MB, 2)
        $ramTotalGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 2)

        $health = [PSCustomObject]@{
            CpuLoadPercent = [math]::Round($cpu,2)
            RamUsedGB      = $ramUsedGB
            RamTotalGB     = $ramTotalGB
            Uptime         = ((Get-Date) - $os.LastBootUpTime).ToString()
        }

        if ($cpu -gt 85) {
            $risk += 35
            $events.Add((Add-TangleEvent -Type "health" -Severity "MEDIUM" -Score 35 -Summary "Hohe CPU Last" -Details $health)) | Out-Null
        } else {
            $events.Add((Add-TangleEvent -Type "health" -Severity "INFO" -Score 0 -Summary "System Health erfasst" -Details $health)) | Out-Null
        }
    } catch { Write-Debug "System health unavailable: $($_.Exception.Message)" }

    $maxRisk = 0
    if ($events.Count -gt 0) {
        $maxRisk = ($events | Measure-Object Score -Maximum).Maximum
    }

    $status = "STABLE"
    if ($maxRisk -ge 90)     { $status = "CRITICAL" }
    elseif ($maxRisk -ge 70) { $status = "ELEVATED" }
    elseif ($maxRisk -ge 30) { $status = "WATCH" }

    $summary = [PSCustomObject]@{
        Time        = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Status      = $status
        MaxRisk     = $maxRisk
        AutoDefense = [bool]$AutoDefense
        EventCount  = $events.Count
        Root        = $Root
        Portal      = $PortalHtml
    }

    # Graph JSON
    $nodes = @(
        @{ id="system";       label="AVA / System";  group="core"     },
        @{ id="network";      label="Network";        group="sensor"   },
        @{ id="defender";     label="Defender";       group="sensor"   },
        @{ id="firewall";     label="Firewall";       group="sensor"   },
        @{ id="process";      label="Process";        group="sensor"   },
        @{ id="identity";     label="Identity";       group="sensor"   },
        @{ id="tangle";       label="Tangle Chain";   group="memory"   },
        @{ id="auto_defense"; label="Auto Defense";   group="response" }
    )

    $links = @(
        @{ source="system";  target="network";      label="observes"           },
        @{ source="system";  target="defender";     label="checks"             },
        @{ source="system";  target="firewall";     label="checks"             },
        @{ source="network"; target="process";      label="maps pid"           },
        @{ source="system";  target="identity";     label="audits"             },
        @{ source="system";  target="tangle";       label="writes hash"        },
        @{ source="network"; target="auto_defense"; label="controlled reaction" }
    )

    $graph = [PSCustomObject]@{
        Summary      = $summary
        Nodes        = $nodes
        Links        = $links
        RecentEvents = $events | Select-Object -Last 50
    }

    $graph | ConvertTo-Json -Depth 20 | Set-Content -Path $GraphJson -Encoding UTF8

    New-AVA-PortalHtml -Summary $summary -Events $events

    return $summary
}

# =========================
# PORTAL HTML
# =========================
function New-AVA-PortalHtml {
    param([object]$Summary,[object[]]$Events)

    $chainHash   = Get-FileSha256 $ChainFile
    $statusClass = $Summary.Status.ToLowerInvariant()

    $riskColor = switch ($Summary.Status) {
        "CRITICAL" { "#ef4444" }
        "ELEVATED" { "#f97316" }
        "WATCH"    { "#eab308" }
        default    { "#22c55e" }
    }

    # Escape '</script>' sequences that could appear inside Details JSON
    $graphData = (Get-Content -Path $GraphJson -Raw -ErrorAction SilentlyContinue) -replace '</', '<\/'
    if (-not $graphData) { $graphData = '{"nodes":[],"links":[]}' }

    $rows = foreach ($e in ($Events | Sort-Object Time -Descending | Select-Object -First 50)) {
        $sevSafe  = [string]$e.Severity -replace '[^a-zA-Z0-9]', ''
        $sevCls   = $sevSafe.ToLower()
        $sevBadge = $sevSafe.ToUpper()
        $score    = 0; try { $score = [int]$e.Score } catch { Write-Debug "Score cast failed: $($_.Exception.Message)" }
        $hashShort = if ($e.Hash) { $e.Hash.Substring(0,[Math]::Min(12,$e.Hash.Length)) } else { "" }
        "<tr class='row-$sevCls'><td>$(HtmlEncode $e.Time)</td><td><span class='badge badge-$sevBadge'>$(HtmlEncode $e.Severity)</span></td><td>$score</td><td>$(HtmlEncode $e.Type)</td><td>$(HtmlEncode $e.Summary)</td><td><code>$hashShort</code></td></tr>"
    }

    $tableContent = if ($rows) {
        "<table><thead><tr><th>Time</th><th>Severity</th><th>Score</th><th>Type</th><th>Summary</th><th>Hash</th></tr></thead><tbody>$($rows -join '')</tbody></table>"
    } else {
        "<p class='no-data'>No events recorded.</p>"
    }

    $autoDefenseLabel = if ($Summary.AutoDefense) { "ACTIVE" } else { "PREVIEW" }
    $autoDefenseColor = if ($Summary.AutoDefense) { "#ef4444" } else { "#eab308" }
    $chainHashShort   = if ($chainHash) { $chainHash.Substring(0,[Math]::Min(16,$chainHash.Length)) } else { "—" }
    $generatedAt      = $Summary.Time

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="refresh" content="$IntervalSeconds">
  <title>AVA v4 Portal &mdash; Live</title>
  <script src="https://cdn.jsdelivr.net/npm/d3@7/dist/d3.min.js"></script>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', Tahoma, Arial, sans-serif; background: #0d1117; color: #e6edf3; padding: 24px; }
    h1 { color: #00ffcc; border-bottom: 2px solid #00ffcc; padding-bottom: 10px; margin-bottom: 6px; font-size: 1.7rem; letter-spacing: 2px; }
    .subtitle { color: #8b949e; font-size: 0.82rem; margin-bottom: 28px; }
    .stats { display: flex; gap: 16px; margin-bottom: 28px; flex-wrap: wrap; align-items: stretch; }
    .stat-card { background: #161b22; border-radius: 10px; padding: 18px 24px; min-width: 130px; text-align: center; border-top: 3px solid #30363d; }
    .stat-card.risk     { border-top-color: $riskColor; min-width: 160px; }
    .stat-card.events   { border-top-color: #3b82f6; }
    .stat-card.chain    { border-top-color: #a855f7; }
    .stat-card.defense  { border-top-color: $autoDefenseColor; }
    .stat-number { font-size: 2.2rem; font-weight: bold; }
    .stat-label  { font-size: 0.78rem; color: #8b949e; margin-top: 4px; text-transform: uppercase; letter-spacing: 1px; }
    .risk-badge  { display: inline-block; padding: 4px 12px; border-radius: 6px; font-size: 0.9rem; font-weight: bold; background: $riskColor; color: #fff; margin-top: 6px; }
    .defense-badge { display: inline-block; padding: 4px 12px; border-radius: 6px; font-size: 0.9rem; font-weight: bold; background: $autoDefenseColor; color: #000; margin-top: 6px; }
    h2 { color: #00ffcc; font-size: 1.05rem; margin: 28px 0 10px; letter-spacing: 1px; }
    table { width: 100%; border-collapse: collapse; font-size: 0.83rem; }
    thead tr { background: #161b22; }
    th { padding: 10px 12px; text-align: left; color: #8b949e; font-weight: 600; border-bottom: 1px solid #30363d; white-space: nowrap; }
    td { padding: 7px 12px; border-bottom: 1px solid #161b22; word-break: break-word; }
    tbody tr:hover { background: #1c2128; }
    .row-critical td { background: #2d1515; color: #fca5a5; }
    .row-high     td { background: #2d1f0f; color: #fdba74; }
    .row-medium   td { background: #2a260a; color: #fde68a; }
    .row-low      td { color: #86efac; }
    .badge          { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.72rem; font-weight: bold; }
    .badge-CRITICAL { background: #ef4444; color: #fff; }
    .badge-HIGH     { background: #f97316; color: #fff; }
    .badge-MEDIUM   { background: #eab308; color: #000; }
    .badge-LOW      { background: #22c55e; color: #000; }
    .badge-INFO     { background: #3b82f6; color: #fff; }
    .no-data { color: #6b7280; font-style: italic; padding: 12px 0; }
    code { font-family: 'Consolas', monospace; font-size: 0.78rem; color: #a855f7; }
    #graph-panel { background: #161b22; border-radius: 10px; margin-bottom: 28px; overflow: hidden; border: 1px solid #30363d; }
    #graph-panel h2 { padding: 14px 20px 0; margin: 0 0 4px; }
    #graph-legend { display: flex; flex-wrap: wrap; gap: 10px; padding: 8px 20px 12px; font-size: 0.75rem; }
    .legend-item { display: flex; align-items: center; gap: 5px; color: #8b949e; }
    .legend-dot  { width: 11px; height: 11px; border-radius: 50%; flex-shrink: 0; }
    #graph-svg { width: 100%; height: 460px; display: block; cursor: grab; }
    #graph-svg:active { cursor: grabbing; }
    .link { stroke: #30363d; stroke-opacity: 0.75; }
    .node circle { cursor: pointer; stroke-width: 1.5px; }
    .node circle:hover { stroke: #00ffcc !important; stroke-width: 2.5px; }
    .node-label { font-size: 10px; fill: #c9d1d9; pointer-events: none; }
    #tooltip { position: fixed; background: #1c2128; border: 1px solid #30363d; border-radius: 6px;
               padding: 8px 12px; font-size: 0.78rem; color: #e6edf3; pointer-events: none;
               opacity: 0; z-index: 1000; max-width: 280px; word-break: break-word;
               transition: opacity 0.12s; line-height: 1.5; }
    footer { margin-top: 40px; font-size: 0.73rem; color: #4b5563; border-top: 1px solid #21262d; padding-top: 12px; }
  </style>
</head>
<body>

<div id="tooltip"></div>

<h1>&#x1F6E1; AVA v4 PORTAL &mdash; Live Dashboard</h1>
<div class="subtitle">
  Generated: $generatedAt &nbsp;|&nbsp; Host: $env:COMPUTERNAME &nbsp;|&nbsp; User: $env:USERNAME
  &nbsp;|&nbsp; Auto-refresh: ${IntervalSeconds}s
</div>

<div class="stats">
  <div class="stat-card risk">
    <div class="stat-number" style="color:$riskColor">$($Summary.MaxRisk)</div>
    <div class="stat-label">Risk Score</div>
    <div class="risk-badge">$($Summary.Status)</div>
  </div>
  <div class="stat-card events">
    <div class="stat-number">$($Summary.EventCount)</div>
    <div class="stat-label">Events (this run)</div>
  </div>
  <div class="stat-card defense">
    <div class="stat-number" style="font-size:1.3rem; padding-top:6px">$autoDefenseLabel</div>
    <div class="stat-label">Auto Defense</div>
    <div class="defense-badge">$autoDefenseLabel</div>
  </div>
  <div class="stat-card chain">
    <div class="stat-number" style="font-size:0.9rem; padding-top:10px"><code>$chainHashShort</code></div>
    <div class="stat-label">Tangle Chain Hash</div>
  </div>
</div>

<div id="graph-panel">
  <h2>&#x1F578; AVA Component Graph</h2>
  <div id="graph-legend">
    <span class="legend-item"><span class="legend-dot" style="background:#3b82f6"></span>Core</span>
    <span class="legend-item"><span class="legend-dot" style="background:#22c55e"></span>Sensor</span>
    <span class="legend-item"><span class="legend-dot" style="background:#a855f7"></span>Memory</span>
    <span class="legend-item"><span class="legend-dot" style="background:#ef4444"></span>Response</span>
  </div>
  <svg id="graph-svg"></svg>
</div>

<h2>&#x1F4CB; Snapshot Events (last 50, newest first)</h2>
$tableContent

<footer>
  AVA v4 Portal &mdash; Lokal / Defensiv / Kontrolliert &mdash;
  Chain: $ChainFile &nbsp;|&nbsp; Events: $EventLog &nbsp;|&nbsp; Blocks: $BlockState
</footer>

<script>
(function () {
  var graphData = $graphData;
  var summary   = graphData.Summary || {};
  var rawNodes  = (graphData.Nodes  || graphData.nodes  || []);
  var rawLinks  = (graphData.Links  || graphData.links  || []);

  var groupColor = { core:"#3b82f6", sensor:"#22c55e", memory:"#a855f7", response:"#ef4444" };
  function nodeColor(g) { return groupColor[g] || "#8b949e"; }

  var svgEl = document.getElementById("graph-svg");
  var W = svgEl.parentElement.clientWidth || 900;
  var H = 460;

  var svg = d3.select("#graph-svg").attr("viewBox","0 0 "+W+" "+H);
  var g   = svg.append("g");

  svg.call(
    d3.zoom().scaleExtent([0.2,5])
      .on("zoom", function(ev){ g.attr("transform", ev.transform); })
  );

  var nodes = rawNodes.map(function(n){
    return { id:n.id, label:n.label, group:n.group, score:n.score||0 };
  });

  var links = rawLinks.map(function(l){
    return { source:l.source, target:l.target, label:l.label };
  });

  var defs = svg.append("defs");
  defs.append("marker")
    .attr("id","arrow").attr("viewBox","0 -5 10 10")
    .attr("refX",22).attr("refY",0)
    .attr("markerWidth",6).attr("markerHeight",6)
    .attr("orient","auto")
    .append("path").attr("d","M0,-5L10,0L0,5").attr("fill","#374151");

  var linkSel = g.append("g").selectAll("line").data(links).enter()
    .append("line").attr("class","link").attr("stroke-width",1.5)
    .attr("marker-end","url(#arrow)");

  var tooltip = document.getElementById("tooltip");

  var nodeSel = g.append("g").selectAll("g").data(nodes).enter()
    .append("g").attr("class","node")
    .call(
      d3.drag()
        .on("start",function(ev,d){ if(!ev.active) sim.alphaTarget(0.3).restart(); d.fx=d.x; d.fy=d.y; })
        .on("drag", function(ev,d){ d.fx=ev.x; d.fy=ev.y; })
        .on("end",  function(ev,d){ if(!ev.active) sim.alphaTarget(0); d.fx=null; d.fy=null; })
    );

  nodeSel.append("circle")
    .attr("r",18)
    .attr("fill", function(d){ return nodeColor(d.group); })
    .attr("stroke","#0d1117")
    .on("mouseover",function(ev,d){
      tooltip.innerHTML = "<strong>"+(d.label||d.id)+"</strong><br>Group: "+d.group;
      tooltip.style.opacity="1";
    })
    .on("mousemove",function(ev){
      tooltip.style.left=(ev.clientX+14)+"px";
      tooltip.style.top=(ev.clientY-36)+"px";
    })
    .on("mouseout",function(){ tooltip.style.opacity="0"; });

  nodeSel.append("text")
    .attr("class","node-label")
    .attr("dx",21).attr("dy","0.35em")
    .text(function(d){
      var lbl = d.label||d.id;
      return lbl.length>20 ? lbl.substring(0,18)+".." : lbl;
    });

  var sim = d3.forceSimulation(nodes)
    .force("link",   d3.forceLink(links).id(function(d){return d.id;}).distance(150))
    .force("charge", d3.forceManyBody().strength(-350))
    .force("center", d3.forceCenter(W/2, H/2))
    .force("collide",d3.forceCollide(30));

  sim.on("tick",function(){
    linkSel
      .attr("x1",function(d){return d.source.x;})
      .attr("y1",function(d){return d.source.y;})
      .attr("x2",function(d){return d.target.x;})
      .attr("y2",function(d){return d.target.y;});
    nodeSel.attr("transform",function(d){return "translate("+d.x+","+d.y+")";});
  });
}());
</script>

</body>
</html>
"@

    $html | Set-Content -Path $PortalHtml -Encoding UTF8
}

# =========================
# RUN
# =========================
Write-Host ""
Write-Host "AVA v4 Portal startet..." -ForegroundColor Green
Write-Host "AutoDefense: $AutoDefense" -ForegroundColor Cyan
Write-Host "Portal: $PortalHtml" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path -LiteralPath $PortalHtml)) {
    $s = Invoke-AVA-Snapshot
    Start-Process $PortalHtml
} else {
    Start-Process $PortalHtml
}

if ($Live) {
    while ($true) {
        $summary = Invoke-AVA-Snapshot
        Write-Host ("[{0}] Status={1} Risk={2} AutoDefense={3}" -f $summary.Time,$summary.Status,$summary.MaxRisk,$summary.AutoDefense) -ForegroundColor Green
        Start-Sleep -Seconds $IntervalSeconds
    }
} elseif ($RunOnce) {
    $summary = Invoke-AVA-Snapshot
    Write-Host ("Fertig. Status={0} Risk={1}" -f $summary.Status,$summary.MaxRisk) -ForegroundColor Green
} else {
    $summary = Invoke-AVA-Snapshot
    Write-Host ("Fertig. Status={0} Risk={1}" -f $summary.Status,$summary.MaxRisk) -ForegroundColor Green
}
