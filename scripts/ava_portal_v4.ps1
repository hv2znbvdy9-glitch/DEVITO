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
            Score    = 0
            Level    = "OK"
            Critical = 0
            High     = 0
            Medium   = 0
            Low      = 0
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
        } catch { Write-Debug "Score cast failed: $($_.Exception.Message)" }
    }

    $level = "OK"
    if ($max -ge 90) { $level = "CRITICAL" }
    elseif ($max -ge 75) { $level = "HIGH" }
    elseif ($max -ge 50) { $level = "MEDIUM" }
    elseif ($max -gt 0)  { $level = "LOW" }

    [pscustomobject]@{
        Score    = $max
        Level    = $level
        Critical = $critical
        High     = $high
        Medium   = $medium
        Low      = $low
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
        # Sanitise severity to alphanumeric-only before inserting into CSS class attributes
        $sevSafe  = [string]$a.severity -replace '[^a-zA-Z0-9]', ''
        $sevCls   = $sevSafe.ToLower()   # used for row highlighting:  row-critical
        $sevBadge = $sevSafe.ToUpper()   # used for badge colouring:   badge-CRITICAL
        $score    = 0; try { $score = [int]$a.score } catch { Write-Debug "Score cast failed: $($_.Exception.Message)" }
        "<tr class='row-$sevCls'><td>$(Html $a.time)</td><td><span class='badge badge-$sevBadge'>$(Html $a.severity)</span></td><td>$(Html $score)</td><td>$(Html $a.title)</td><td>$(Html $a.reason)</td></tr>"
    }

    $eventRows = foreach ($e in ($Events | Select-Object -Last 40)) {
        "<tr><td>$(Html $e.time)</td><td>$(Html $e.severity)</td><td>$(Html $e.type)</td><td>$(Html $e.summary)</td></tr>"
    }

    # Escape '</' to prevent premature </script> tag close when embedded in HTML
    $graphData   = ($Graph | ConvertTo-Json -Depth 20 -Compress) -replace '</', '<\/'
    $generatedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

    $riskColor = switch ($risk.Level) {
        "CRITICAL" { "#ef4444" }
        "HIGH"     { "#f97316" }
        "MEDIUM"   { "#eab308" }
        "LOW"      { "#22c55e" }
        default    { "#6b7280" }
    }

    $alertTableContent = if ($alertRows) {
        "<table><thead><tr><th>Time</th><th>Severity</th><th>Score</th><th>Title</th><th>Reason</th></tr></thead><tbody>$($alertRows -join '')</tbody></table>"
    } else {
        "<p class='no-data'>No alerts recorded.</p>"
    }

    $eventTableContent = if ($eventRows) {
        "<table><thead><tr><th>Time</th><th>Severity</th><th>Type</th><th>Summary</th></tr></thead><tbody>$($eventRows -join '')</tbody></table>"
    } else {
        "<p class='no-data'>No events recorded.</p>"
    }

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AVA PORTAL V4</title>
  <script src="https://cdn.jsdelivr.net/npm/d3@7/dist/d3.min.js"></script>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', Tahoma, Arial, sans-serif; background: #0d1117; color: #e6edf3; padding: 24px; }
    h1 { color: #00ffcc; border-bottom: 2px solid #00ffcc; padding-bottom: 10px; margin-bottom: 6px; font-size: 1.7rem; letter-spacing: 2px; }
    .subtitle { color: #8b949e; font-size: 0.82rem; margin-bottom: 28px; }
    .stats { display: flex; gap: 16px; margin-bottom: 28px; flex-wrap: wrap; align-items: stretch; }
    .stat-card { background: #161b22; border-radius: 10px; padding: 18px 24px; min-width: 130px; text-align: center; border-top: 3px solid #30363d; }
    .stat-card.risk     { border-top-color: $riskColor; min-width: 160px; }
    .stat-card.critical { border-top-color: #ef4444; }
    .stat-card.high     { border-top-color: #f97316; }
    .stat-card.medium   { border-top-color: #eab308; }
    .stat-card.low-card { border-top-color: #22c55e; }
    .stat-number { font-size: 2.2rem; font-weight: bold; }
    .stat-label  { font-size: 0.78rem; color: #8b949e; margin-top: 4px; text-transform: uppercase; letter-spacing: 1px; }
    .risk-badge  { display: inline-block; padding: 4px 12px; border-radius: 6px; font-size: 0.9rem; font-weight: bold; background: $riskColor; color: #fff; margin-top: 6px; }
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
    .badge-WARN     { background: #f59e0b; color: #000; }
    .no-data { color: #6b7280; font-style: italic; padding: 12px 0; }
    #graph-panel { background: #161b22; border-radius: 10px; margin-bottom: 28px; overflow: hidden; border: 1px solid #30363d; }
    #graph-panel h2 { padding: 14px 20px 0; margin: 0 0 4px; }
    #graph-legend { display: flex; flex-wrap: wrap; gap: 10px; padding: 8px 20px 12px; font-size: 0.75rem; }
    .legend-item { display: flex; align-items: center; gap: 5px; color: #8b949e; }
    .legend-dot  { width: 11px; height: 11px; border-radius: 50%; flex-shrink: 0; }
    #graph-svg { width: 100%; height: 520px; display: block; cursor: grab; }
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

<h1>&#x1F6E1; AVA PORTAL V4 &mdash; Visual SOC Dashboard</h1>
<div class="subtitle">
  Generated: $generatedAt &nbsp;|&nbsp; Host: $env:COMPUTERNAME &nbsp;|&nbsp; User: $env:USERNAME
</div>

<div class="stats">
  <div class="stat-card risk">
    <div class="stat-number" style="color:$riskColor">$($risk.Score)</div>
    <div class="stat-label">Risk Score</div>
    <div class="risk-badge">$($risk.Level)</div>
  </div>
  <div class="stat-card critical">
    <div class="stat-number">$($risk.Critical)</div>
    <div class="stat-label">Critical</div>
  </div>
  <div class="stat-card high">
    <div class="stat-number">$($risk.High)</div>
    <div class="stat-label">High</div>
  </div>
  <div class="stat-card medium">
    <div class="stat-number">$($risk.Medium)</div>
    <div class="stat-label">Medium</div>
  </div>
  <div class="stat-card low-card">
    <div class="stat-number">$($risk.Low)</div>
    <div class="stat-label">Low</div>
  </div>
</div>

<div id="graph-panel">
  <h2>&#x1F578; Entity Relationship Graph</h2>
  <div id="graph-legend">
    <span class="legend-item"><span class="legend-dot" style="background:#3b82f6"></span>Host</span>
    <span class="legend-item"><span class="legend-dot" style="background:#22c55e"></span>User</span>
    <span class="legend-item"><span class="legend-dot" style="background:#ef4444"></span>Alert</span>
    <span class="legend-item"><span class="legend-dot" style="background:#6b7280"></span>Event</span>
    <span class="legend-item"><span class="legend-dot" style="background:#eab308"></span>Severity</span>
    <span class="legend-item"><span class="legend-dot" style="background:#a855f7"></span>Reason</span>
    <span class="legend-item"><span class="legend-dot" style="background:#f97316"></span>Process</span>
    <span class="legend-item"><span class="legend-dot" style="background:#ec4899"></span>Port</span>
    <span class="legend-item"><span class="legend-dot" style="background:#06b6d4"></span>Object</span>
  </div>
  <svg id="graph-svg"></svg>
</div>

<h2>&#x26A0; Top Alerts (by Score)</h2>
$alertTableContent

<h2>&#x1F4CB; Recent Events (last 40)</h2>
$eventTableContent

<footer>
  AVA PORTAL V4 &mdash; Defensiv / Lokal / Read-Only &mdash;
  Graph: $GraphJson &nbsp;|&nbsp; Portal: $PortalHtml
</footer>

<script>
(function () {
  var graphData = $graphData;

  var svgEl = document.getElementById("graph-svg");
  var W = svgEl.parentElement.clientWidth || 900;
  var H = 520;

  var svg = d3.select("#graph-svg").attr("viewBox", "0 0 " + W + " " + H);

  var g = svg.append("g");

  svg.call(
    d3.zoom()
      .scaleExtent([0.15, 5])
      .on("zoom", function (event) { g.attr("transform", event.transform); })
  );

  var colorMap = {
    host:     "#3b82f6",
    user:     "#22c55e",
    alert:    "#ef4444",
    event:    "#6b7280",
    severity: "#eab308",
    reason:   "#a855f7",
    process:  "#f97316",
    port:     "#ec4899",
    object:   "#06b6d4"
  };

  function nodeColor(type) { return colorMap[type] || "#8b949e"; }
  function nodeRadius(score) { return 8 + Math.min((score || 0) / 6, 18); }

  var nodes = (graphData.nodes || []).map(function (n) {
    return { id: n.id, label: n.label, type: n.type, score: n.score || 0 };
  });

  var links = (graphData.links || []).map(function (l) {
    return { source: l.source, target: l.target, reason: l.reason, weight: l.weight || 1 };
  });

  var defs = svg.append("defs");
  defs.append("marker")
    .attr("id", "arrow")
    .attr("viewBox", "0 -5 10 10")
    .attr("refX", 22)
    .attr("refY", 0)
    .attr("markerWidth", 6)
    .attr("markerHeight", 6)
    .attr("orient", "auto")
    .append("path")
    .attr("d", "M0,-5L10,0L0,5")
    .attr("fill", "#374151");

  var linkSel = g.append("g")
    .selectAll("line")
    .data(links)
    .enter().append("line")
    .attr("class", "link")
    .attr("stroke-width", function (d) { return Math.max(1, Math.sqrt(d.weight)); })
    .attr("marker-end", "url(#arrow)");

  var nodeSel = g.append("g")
    .selectAll("g")
    .data(nodes)
    .enter().append("g")
    .attr("class", "node")
    .call(
      d3.drag()
        .on("start", function (event, d) {
          if (!event.active) sim.alphaTarget(0.3).restart();
          d.fx = d.x; d.fy = d.y;
        })
        .on("drag", function (event, d) { d.fx = event.x; d.fy = event.y; })
        .on("end", function (event, d) {
          if (!event.active) sim.alphaTarget(0);
          d.fx = null; d.fy = null;
        })
    );

  var tooltip = document.getElementById("tooltip");

  nodeSel.append("circle")
    .attr("r", function (d) { return nodeRadius(d.score); })
    .attr("fill", function (d) { return nodeColor(d.type); })
    .attr("stroke", function (d) {
      var c = d3.color(nodeColor(d.type));
      return c ? c.darker(0.9) : "#111";
    })
    .on("mouseover", function (event, d) {
      var lbl = d.label || d.id;
      tooltip.innerHTML =
        "<strong>" + lbl + "</strong><br>" +
        "Type: " + d.type + "<br>" +
        "Score: " + d.score + "<br>" +
        "<small style='color:#8b949e'>" + d.id + "</small>";
      tooltip.style.opacity = "1";
    })
    .on("mousemove", function (event) {
      tooltip.style.left = (event.clientX + 14) + "px";
      tooltip.style.top  = (event.clientY - 36) + "px";
    })
    .on("mouseout", function () { tooltip.style.opacity = "0"; });

  nodeSel.append("text")
    .attr("class", "node-label")
    .attr("dx", function (d) { return nodeRadius(d.score) + 3; })
    .attr("dy", "0.35em")
    .text(function (d) {
      var lbl = d.label || d.id;
      return lbl.length > 24 ? lbl.substring(0, 22) + ".." : lbl;
    });

  var sim = d3.forceSimulation(nodes)
    .force("link",      d3.forceLink(links).id(function (d) { return d.id; }).distance(120))
    .force("charge",    d3.forceManyBody().strength(-300))
    .force("center",    d3.forceCenter(W / 2, H / 2))
    .force("collision", d3.forceCollide().radius(function (d) { return nodeRadius(d.score) + 5; }));

  sim.on("tick", function () {
    linkSel
      .attr("x1", function (d) { return d.source.x; })
      .attr("y1", function (d) { return d.source.y; })
      .attr("x2", function (d) { return d.target.x; })
      .attr("y2", function (d) { return d.target.y; });

    nodeSel.attr("transform", function (d) {
      return "translate(" + d.x + "," + d.y + ")";
    });
  });
}());
</script>

</body>
</html>
"@

    $html | Set-Content -Path $PortalHtml -Encoding UTF8
}

# =============================================================
# MAIN
# =============================================================
Ensure-Dirs

$events = @(Read-JsonLines -Path $EventLog -Tail 300)
$alerts = @(Read-JsonLines -Path $AlertLog -Tail 300)

$graph = Build-Graph -Events $events -Alerts $alerts
$graph | ConvertTo-Json -Depth 20 | Set-Content -Path $GraphJson -Encoding UTF8

Build-Portal -Events $events -Alerts $alerts -Graph $graph

Write-Host ""
Write-Host "AVA PORTAL V4 gebaut." -ForegroundColor Cyan
Write-Host "Portal: $PortalHtml"   -ForegroundColor Green
Write-Host "Graph:  $GraphJson"    -ForegroundColor Yellow

Start-Process $PortalHtml
