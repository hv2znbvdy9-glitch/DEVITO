#requires -RunAsAdministrator
<#
AVA PORTAL V4
Defensiv / Lokal / Read-Only
Visual Portal + Graph Engine für AVA SOC CORE

Keine Angriffe. Keine Exploits. Keine fremden Systeme.
Liest nur lokale AVA Logs und erzeugt ein HTML-Dashboard.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root      = "C:\Windows\SecurityGuardian"
$LogDir    = Join-Path $Root "Logs"
$ReportDir = Join-Path $Root "Reports"
$StateDir  = Join-Path $Root "State"

$EventLog   = Join-Path $LogDir "events.jsonl"
$AlertLog   = Join-Path $LogDir "alerts.jsonl"
$GraphJson  = Join-Path $ReportDir "graph_v4.json"
$PortalHtml = Join-Path $ReportDir "ava_portal_v4.html"

function Ensure-Dirs {
    foreach ($d in @($Root,$LogDir,$ReportDir,$StateDir)) {
        if (-not (Test-Path -LiteralPath $d)) {
            New-Item -ItemType Directory -Path $d -Force | Out-Null
        }
    }
}

function Html {
    param([object]$Value)
    if ($null -eq $Value) { return "" }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Read-JsonLines {
    param(
        [string]$Path,
        [int]$Tail = 300
    )

    if (-not (Test-Path -LiteralPath $Path)) { return @() }

    @(Get-Content -Path $Path -Tail $Tail | ForEach-Object {
        try { $_ | ConvertFrom-Json } catch { $null }
    } | Where-Object { $_ })
}

function Add-Node {
    param(
        [hashtable]$Nodes,
        [string]$Id,
        [string]$Label,
        [string]$Type,
        [int]$Score = 0
    )

    if (-not $Nodes.ContainsKey($Id)) {
        $Nodes[$Id] = [ordered]@{
            id    = $Id
            label = $Label
            type  = $Type
            score = $Score
        }
    } else {
        if ($Score -gt [int]$Nodes[$Id].score) {
            $Nodes[$Id].score = $Score
        }
    }
}

function Add-Link {
    param(
        [System.Collections.Generic.List[object]]$Links,
        [string]$Source,
        [string]$Target,
        [string]$Reason,
        [int]$Weight = 1
    )

    $Links.Add([ordered]@{
        source = $Source
        target = $Target
        reason = $Reason
        weight = $Weight
    }) | Out-Null
}

function Build-Graph {
    param(
        [object[]]$Events,
        [object[]]$Alerts
    )

    $nodes = @{}
    $links = New-Object System.Collections.Generic.List[object]

    $hostId = "host:$env:COMPUTERNAME"
    $userId = "user:$env:USERNAME"

    Add-Node $nodes $hostId $env:COMPUTERNAME "host" 0
    Add-Node $nodes $userId $env:USERNAME "user" 0
    Add-Link $links $hostId $userId "current_user" 1

    foreach ($e in $Events) {
        $eventId = "event:$($e.type):$($e.time)"
        Add-Node $nodes $eventId "$($e.type)" "event" 10
        Add-Link $links $hostId $eventId "event_on_host" 1

        if ($e.severity) {
            $sevId = "severity:$($e.severity)"
            Add-Node $nodes $sevId "$($e.severity)" "severity" 0
            Add-Link $links $eventId $sevId "has_severity" 1
        }
    }

    foreach ($a in $Alerts) {
        $score = 0
        try { $score = [int]$a.score } catch { $score = 0 }

        $alertId = "alert:$($a.title):$($a.time)"
        Add-Node $nodes $alertId "$($a.title)" "alert" $score
        Add-Link $links $hostId $alertId "alert_on_host" 3

        if ($a.severity) {
            $sevId = "severity:$($a.severity)"
            Add-Node $nodes $sevId "$($a.severity)" "severity" $score
            Add-Link $links $alertId $sevId "alert_severity" 2
        }

        if ($a.reason) {
            $reasonId = "reason:$($a.reason)"
            Add-Node $nodes $reasonId "$($a.reason)" "reason" $score
            Add-Link $links $alertId $reasonId "alert_reason" 1
        }

        if ($a.data.ProcessName) {
            $procId = "process:$($a.data.ProcessName)"
            Add-Node $nodes $procId "$($a.data.ProcessName)" "process" $score
            Add-Link $links $alertId $procId "related_process" 2
        }

        if ($a.data.RemotePort) {
            $portId = "port:$($a.data.RemotePort)"
            Add-Node $nodes $portId "Port $($a.data.RemotePort)" "port" $score
            Add-Link $links $alertId $portId "related_port" 2
        }

        if ($a.data.Name) {
            $nameId = "object:$($a.data.Name)"
            Add-Node $nodes $nameId "$($a.data.Name)" "object" $score
            Add-Link $links $alertId $nameId "related_object" 2
        }
    }

    [ordered]@{
        generated = (Get-Date).ToString("o")
        host      = $env:COMPUTERNAME
        user      = $env:USERNAME
        nodes     = @($nodes.Values)
        links     = @($links)
    }
}

function Get-Risk {
    param([object[]]$Alerts)

    if ($Alerts.Count -eq 0) {
        return [pscustomobject]@{
            Score = 0
            Level = "OK"
            Critical = 0
            High = 0
            Medium = 0
            Low = 0
        }
    }

    $critical = @($Alerts | Where-Object { $_.severity -eq "CRITICAL" }).Count
    $high     = @($Alerts | Where-Object { $_.severity -eq "HIGH" }).Count
    $medium   = @($Alerts | Where-Object { $_.severity -eq "MEDIUM" }).Count
    $low      = @($Alerts | Where-Object { $_.severity -eq "LOW" }).Count

    $max = 0
    foreach ($a in $Alerts) {
        try {
            if ([int]$a.score -gt $max) { $max = [int]$a.score }
        } catch {}
    }

    $level = "OK"
    if ($max -ge 90) { $level = "CRITICAL" }
    elseif ($max -ge 75) { $level = "HIGH" }
    elseif ($max -ge 50) { $level = "MEDIUM" }
    elseif ($max -gt 0) { $level = "LOW" }

    [pscustomobject]@{
        Score = $max
        Level = $level
        Critical = $critical
        High = $high
        Medium = $medium
        Low = $low
    }
}

function Build-Portal {
    param(
        [object[]]$Events,
        [object[]]$Alerts,
        [object]$Graph
    )

    $risk = Get-Risk -Alerts $Alerts

    $alertRows = foreach ($a in ($Alerts | Sort-Object score -Descending | Select-Object -First 25)) {
        $cls = "$(Html $a.severity)".ToLower()
        "<tr class=`"row-$cls`"><td>$(Html $a.time)</td><td class=`"sev-$cls`">$(Html $a.severity)</td><td>$(Html $a.score)</td><td>$(Html $a.title)</td><td>$(Html $a.reason)</td></tr>"
    }

    $eventRows = foreach ($e in ($Events | Select-Object -Last 40)) {
        $cls = "$(Html $e.severity)".ToLower()
        "<tr><td>$(Html $e.time)</td><td class=`"sev-$cls`">$(Html $e.severity)</td><td>$(Html $e.type)</td><td>$(Html $e.summary)</td></tr>"
    }

    $alertRowsHtml  = if ($alertRows)  { $alertRows  -join "`n" } else { "<tr><td colspan='5' class='empty'>Keine Alerts vorhanden</td></tr>" }
    $eventRowsHtml  = if ($eventRows)  { $eventRows  -join "`n" } else { "<tr><td colspan='4' class='empty'>Keine Events vorhanden</td></tr>" }
    $graphData      = $Graph | ConvertTo-Json -Depth 20 -Compress

    $riskLevelClass = $risk.Level.ToLower()
    $generatedAt    = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $hostName       = Html $env:COMPUTERNAME
    $userName       = Html $env:USERNAME

$html = @"
<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AVA PORTAL V4 - $hostName</title>
<style>
  :root {
    --bg: #0d1117;
    --surface: #161b22;
    --border: #30363d;
    --text: #c9d1d9;
    --text-dim: #8b949e;
    --ok: #3fb950;
    --low: #d29922;
    --medium: #e3b341;
    --high: #f85149;
    --critical: #ff0000;
    --accent: #58a6ff;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', Consolas, monospace; font-size: 13px; }
  header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 14px 24px; display: flex; align-items: center; justify-content: space-between; }
  header h1 { font-size: 18px; color: var(--accent); letter-spacing: 2px; }
  header .meta { color: var(--text-dim); font-size: 11px; text-align: right; line-height: 1.6; }
  .main { padding: 20px 24px; display: grid; gap: 20px; }
  .risk-banner { background: var(--surface); border: 2px solid var(--border); border-radius: 8px; padding: 18px 24px; display: flex; align-items: center; gap: 24px; }
  .risk-score { font-size: 52px; font-weight: bold; line-height: 1; }
  .risk-info h2 { font-size: 20px; letter-spacing: 1px; }
  .risk-info .counts { display: flex; gap: 16px; margin-top: 8px; font-size: 12px; color: var(--text-dim); }
  .risk-info .counts span strong { margin-right: 2px; }
  .level-ok      { color: var(--ok);       border-color: var(--ok); }
  .level-low     { color: var(--low);      border-color: var(--low); }
  .level-medium  { color: var(--medium);   border-color: var(--medium); }
  .level-high    { color: var(--high);     border-color: var(--high); }
  .level-critical{ color: var(--critical); border-color: var(--critical); }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
  .card-header { padding: 10px 16px; font-size: 12px; font-weight: bold; letter-spacing: 1px; color: var(--text-dim); border-bottom: 1px solid var(--border); text-transform: uppercase; }
  table { width: 100%; border-collapse: collapse; }
  th { padding: 8px 12px; text-align: left; font-size: 11px; color: var(--text-dim); border-bottom: 1px solid var(--border); background: var(--bg); }
  td { padding: 7px 12px; border-bottom: 1px solid var(--border); vertical-align: top; word-break: break-word; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: rgba(88,166,255,0.04); }
  .sev-critical { color: var(--critical); font-weight: bold; }
  .sev-high     { color: var(--high);     font-weight: bold; }
  .sev-medium   { color: var(--medium); }
  .sev-low      { color: var(--low); }
  .row-critical td:first-child { border-left: 3px solid var(--critical); }
  .row-high     td:first-child { border-left: 3px solid var(--high); }
  .row-medium   td:first-child { border-left: 3px solid var(--medium); }
  .row-low      td:first-child { border-left: 3px solid var(--low); }
  .empty { color: var(--text-dim); text-align: center; padding: 16px; font-style: italic; }
  #graph-canvas { display: block; width: 100%; height: 420px; background: var(--bg); }
  .legend { display: flex; gap: 16px; padding: 10px 16px; border-top: 1px solid var(--border); flex-wrap: wrap; }
  .legend-item { display: flex; align-items: center; gap: 6px; font-size: 11px; color: var(--text-dim); }
  .legend-dot { width: 10px; height: 10px; border-radius: 50%; }
  footer { text-align: center; padding: 16px; color: var(--text-dim); font-size: 11px; border-top: 1px solid var(--border); margin-top: 8px; }
</style>
</head>
<body>
<header>
  <h1>&#x1F6E1; AVA PORTAL V4</h1>
  <div class="meta">
    <div>Host: <strong>$hostName</strong> &nbsp;|&nbsp; User: <strong>$userName</strong></div>
    <div>Generiert: $generatedAt &nbsp;|&nbsp; Modus: Read-Only / Defensiv / Lokal</div>
  </div>
</header>
<div class="main">
  <!-- Risk Banner -->
  <div class="risk-banner level-$riskLevelClass">
    <div class="risk-score level-$riskLevelClass">$($risk.Score)</div>
    <div class="risk-info">
      <h2>RISIKO: $($risk.Level)</h2>
      <div class="counts">
        <span><strong style="color:var(--critical)">&#x25CF;</strong> CRITICAL: $($risk.Critical)</span>
        <span><strong style="color:var(--high)">&#x25CF;</strong> HIGH: $($risk.High)</span>
        <span><strong style="color:var(--medium)">&#x25CF;</strong> MEDIUM: $($risk.Medium)</span>
        <span><strong style="color:var(--low)">&#x25CF;</strong> LOW: $($risk.Low)</span>
      </div>
    </div>
  </div>

  <!-- Alerts Table -->
  <div class="card">
    <div class="card-header">&#x26A0; Alerts (Top 25, nach Score sortiert)</div>
    <table>
      <thead><tr><th>Zeit</th><th>Severity</th><th>Score</th><th>Titel</th><th>Grund</th></tr></thead>
      <tbody>$alertRowsHtml</tbody>
    </table>
  </div>

  <!-- Events Table -->
  <div class="card">
    <div class="card-header">&#x1F4CB; Events (letzte 40)</div>
    <table>
      <thead><tr><th>Zeit</th><th>Severity</th><th>Typ</th><th>Zusammenfassung</th></tr></thead>
      <tbody>$eventRowsHtml</tbody>
    </table>
  </div>

  <!-- Graph -->
  <div class="card">
    <div class="card-header">&#x1F578; Entitätsgraph</div>
    <canvas id="graph-canvas"></canvas>
    <div class="legend">
      <span class="legend-item"><span class="legend-dot" style="background:#58a6ff"></span>Host</span>
      <span class="legend-item"><span class="legend-dot" style="background:#3fb950"></span>User</span>
      <span class="legend-item"><span class="legend-dot" style="background:#f85149"></span>Alert</span>
      <span class="legend-item"><span class="legend-dot" style="background:#e3b341"></span>Event</span>
      <span class="legend-item"><span class="legend-dot" style="background:#bc8cff"></span>Process</span>
      <span class="legend-item"><span class="legend-dot" style="background:#79c0ff"></span>Port</span>
      <span class="legend-item"><span class="legend-dot" style="background:#8b949e"></span>Severity/Reason/Object</span>
    </div>
  </div>
</div>
<footer>AVA PORTAL V4 &mdash; Defensiv / Lokal / Read-Only &mdash; Keine Angriffe. Keine Exploits. Keine fremden Systeme.</footer>

<script>
(function() {
  var graphData = $graphData;

  var canvas = document.getElementById('graph-canvas');
  var rect = canvas.getBoundingClientRect();
  var W = canvas.offsetWidth || 900;
  var H = 420;
  canvas.width  = W;
  canvas.height = H;
  var ctx = canvas.getContext('2d');

  var REPULSION_FORCE  = 1800;
  var BASE_LINK_LENGTH = 90;
  var MAX_LABEL_LENGTH = 20;
  var TRUNCATE_AT      = 18;

  var NODE_COLORS = {
    host:     '#58a6ff',
    user:     '#3fb950',
    alert:    '#f85149',
    event:    '#e3b341',
    process:  '#bc8cff',
    port:     '#79c0ff',
    severity: '#8b949e',
    reason:   '#8b949e',
    object:   '#8b949e'
  };

  var nodes = (graphData.nodes || []).map(function(n, i) {
    return {
      id:    n.id,
      label: n.label,
      type:  n.type,
      score: n.score || 0,
      x: W * 0.1 + Math.random() * W * 0.8,
      y: H * 0.1 + Math.random() * H * 0.8,
      vx: 0, vy: 0
    };
  });

  var nodeById = {};
  nodes.forEach(function(n) { nodeById[n.id] = n; });

  var links = (graphData.links || []).map(function(l) {
    return {
      source: nodeById[l.source],
      target: nodeById[l.target],
      reason: l.reason,
      weight: l.weight || 1
    };
  }).filter(function(l) { return l.source && l.target; });

  function radius(n) { return n.type === 'host' ? 14 : n.type === 'alert' ? 10 : 7; }

  function tick() {
    // Repulsion
    for (var i = 0; i < nodes.length; i++) {
      for (var j = i + 1; j < nodes.length; j++) {
        var a = nodes[i], b = nodes[j];
        var dx = b.x - a.x, dy = b.y - a.y;
        var dist = Math.sqrt(dx * dx + dy * dy) || 1;
        var force = REPULSION_FORCE / (dist * dist);
        var fx = (dx / dist) * force, fy = (dy / dist) * force;
        a.vx -= fx; a.vy -= fy;
        b.vx += fx; b.vy += fy;
      }
    }
    // Attraction along links
    links.forEach(function(l) {
      var dx = l.target.x - l.source.x, dy = l.target.y - l.source.y;
      var dist = Math.sqrt(dx * dx + dy * dy) || 1;
      var rest = BASE_LINK_LENGTH * l.weight;
      var force = (dist - rest) * 0.04;
      var fx = (dx / dist) * force, fy = (dy / dist) * force;
      l.source.vx += fx; l.source.vy += fy;
      l.target.vx -= fx; l.target.vy -= fy;
    });
    // Center gravity
    nodes.forEach(function(n) {
      n.vx += (W / 2 - n.x) * 0.003;
      n.vy += (H / 2 - n.y) * 0.003;
      n.vx *= 0.75; n.vy *= 0.75;
      n.x += n.vx; n.y += n.vy;
      n.x = Math.max(20, Math.min(W - 20, n.x));
      n.y = Math.max(20, Math.min(H - 20, n.y));
    });
  }

  function draw() {
    ctx.clearRect(0, 0, W, H);

    // Edges
    ctx.lineWidth = 1;
    links.forEach(function(l) {
      ctx.beginPath();
      ctx.moveTo(l.source.x, l.source.y);
      ctx.lineTo(l.target.x, l.target.y);
      ctx.strokeStyle = 'rgba(139,148,158,0.3)';
      ctx.stroke();
    });

    // Nodes
    nodes.forEach(function(n) {
      var r = radius(n);
      var color = NODE_COLORS[n.type] || '#8b949e';
      ctx.beginPath();
      ctx.arc(n.x, n.y, r, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();
      if (n.score >= 75) {
        ctx.lineWidth = 2;
        ctx.strokeStyle = '#f85149';
        ctx.stroke();
      }

      // Label for prominent nodes
      if (n.type === 'host' || n.type === 'user' || n.score >= 50) {
        ctx.font = '10px Consolas, monospace';
        ctx.fillStyle = '#c9d1d9';
        ctx.textAlign = 'center';
        var lbl = n.label.length > MAX_LABEL_LENGTH ? n.label.substring(0, TRUNCATE_AT) + '..' : n.label;
        ctx.fillText(lbl, n.x, n.y + r + 12);
      }
    });
  }

  var iteration = 0;
  var maxIter   = 200;
  function step() {
    tick();
    draw();
    iteration++;
    if (iteration < maxIter) {
      requestAnimationFrame(step);
    }
  }

  if (nodes.length > 0) {
    step();
  } else {
    ctx.fillStyle = '#8b949e';
    ctx.font = '13px Consolas, monospace';
    ctx.textAlign = 'center';
    ctx.fillText('Keine Graph-Daten vorhanden', W / 2, H / 2);
  }
})();
</script>
</body>
</html>
"@

    $html | Set-Content -Path $PortalHtml -Encoding UTF8
}

Ensure-Dirs

$events = @(Read-JsonLines -Path $EventLog -Tail 300)
$alerts = @(Read-JsonLines -Path $AlertLog -Tail 300)

$graph = Build-Graph -Events $events -Alerts $alerts
$graph | ConvertTo-Json -Depth 20 | Set-Content -Path $GraphJson -Encoding UTF8

Build-Portal -Events $events -Alerts $alerts -Graph $graph

Write-Host ""
Write-Host "AVA PORTAL V4 gebaut." -ForegroundColor Cyan
Write-Host "Portal: $PortalHtml" -ForegroundColor Green
Write-Host "Graph:  $GraphJson" -ForegroundColor Yellow

Start-Process $PortalHtml
