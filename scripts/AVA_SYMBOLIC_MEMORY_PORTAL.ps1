#requires -Version 5.1
<#
AVA SYMBOLIC MEMORY PORTAL
Lokal / Privat / Read-Only / Kein Upload / Keine Überwachung

Erstellt:
- Ordnerstruktur
- JSON Memory-Datei
- CSV Export
- HTML Portal
- Symbolische Mindmap
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root      = Join-Path $env:USERPROFILE "Desktop\AVA_SYMBOLIC_MEMORY_PORTAL"
$DataDir   = Join-Path $Root "Daten"
$PortalDir = Join-Path $Root "Portal"

$JsonPath = Join-Path $DataDir "symbolic_memory.json"
$CsvPath  = Join-Path $DataDir "symbolic_memory.csv"
$HtmlPath = Join-Path $PortalDir "index.html"

function Ensure-Dir {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Force -Path $Path | Out-Null
    }
}

function H {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return "" }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

Ensure-Dir $Root
Ensure-Dir $DataDir
Ensure-Dir $PortalDir

$Memories = @(
    [pscustomobject]@{
        id="sym_001"
        title="AI Tools"
        category="Technik"
        meaning="Werkzeuge, Automatisierung, Assistenz, Kreativität"
        tags="AI;Tools;Automation;Coding;Writing;Design"
        note="KI-Werkzeuge als praktische Helfer: nicht Magie, sondern strukturierte Unterstützung."
    },
    [pscustomobject]@{
        id="sym_002"
        title="Was nicht mein ist"
        category="Affirmation"
        meaning="Loslassen, Schutz, innere Ordnung"
        tags="Schutz;Fokus;Loslassen;Energie;Klarheit"
        note="Was nicht mein ist, soll nicht bleiben. Ich löse mich. Energie kehrt zu mir zurück."
    },
    [pscustomobject]@{
        id="sym_003"
        title="Alte Kulturen und Pyramiden"
        category="Geschichte / Symbolik"
        meaning="Architektur, Zivilisation, Erinnerung, Menschheitsgeschichte"
        tags="Pyramiden;Kulturen;Zeit;Architektur;Geschichte"
        note="Bilder alter Bauwerke als Erinnerung daran, dass Menschen schon immer Muster, Ordnung und Bedeutung gesucht haben."
    },
    [pscustomobject]@{
        id="sym_004"
        title="Geometrie und Goldener Schnitt"
        category="Mathematik / Symbolik"
        meaning="Muster, Verhältnis, Struktur, Form"
        tags="Geometrie;Phi;Goldener Schnitt;Muster;Form"
        note="Mathematik als echte Sprache von Struktur. Symbolische Bedeutung getrennt von wissenschaftlicher Behauptung betrachten."
    },
    [pscustomobject]@{
        id="sym_005"
        title="Klang und Frequenz"
        category="Physik / Wahrnehmung"
        meaning="Schall, Resonanz, Stimme, Atmosphäre"
        tags="Frequenz;Klang;Schall;Resonanz;Stimme"
        note="Reale Physik: Schall ist Druckwelle. Symbolisch: Klang kann Erinnerung und Stimmung stark beeinflussen."
    },
    [pscustomobject]@{
        id="sym_006"
        title="AVA Memory Core"
        category="Systemdenken"
        meaning="Daten zu Ereignissen, Ereignisse zu Mustern, Muster zu Verständnis"
        tags="AVA;Memory;Graph;Timeline;Baseline;Delta"
        note="Fakten vor Angst. Baseline vor Chaos. Sichtbarkeit vor Kontrolle."
    },
    [pscustomobject]@{
        id="sym_007"
        title="LaFamilia bleibt LaFamilia"
        category="Familie / Erinnerung"
        meaning="Verbundenheit, Erinnerung, Schutz, Liebe"
        tags="Familie;Erinnerung;Mama;Bruder;Danny;LaFamilia"
        note="Erinnerungen vor Vergessen. Familie vor Entfernung. Liebe vor Stolz."
    }
)

$Memories | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $JsonPath -Encoding UTF8
$Memories | Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Delimiter ";" -Encoding UTF8

$Cards = foreach ($m in $Memories) {
    $TagChips = foreach ($tag in ($m.tags -split ';' | Where-Object { $_ -and $_.Trim() })) {
        "<span class='chip'>$(H $tag.Trim())</span>"
    }
@"
<article class="card">
  <div class="card-head">
    <span class="id">$(H $m.id)</span>
    <span class="category">$(H $m.category)</span>
  </div>
  <h3>$(H $m.title)</h3>
  <p class="meaning">$(H $m.meaning)</p>
  <p class="note">$(H $m.note)</p>
  <div class="chips">$($TagChips -join '')</div>
</article>
"@
}

$MindNodes = New-Object System.Collections.Generic.List[object]
$MindLinks = New-Object System.Collections.Generic.List[object]
$CenterId = "AVA_CORE"
$CenterLabel = "AVA Symbolic Memory"
$MindNodes.Add([ordered]@{ id = $CenterId; label = $CenterLabel; group = "core" }) | Out-Null

$CategorySeen = @{}
foreach ($m in $Memories) {
    $memoryId = $m.id
    $categoryId = "cat:" + $m.category

    if (-not $CategorySeen.ContainsKey($categoryId)) {
        $MindNodes.Add([ordered]@{ id = $categoryId; label = $m.category; group = "category" }) | Out-Null
        $MindLinks.Add([ordered]@{ source = $CenterId; target = $categoryId }) | Out-Null
        $CategorySeen[$categoryId] = $true
    }

    $MindNodes.Add([ordered]@{ id = $memoryId; label = $m.title; group = "memory" }) | Out-Null
    $MindLinks.Add([ordered]@{ source = $categoryId; target = $memoryId }) | Out-Null
}

$MindmapData = [ordered]@{
    nodes = @($MindNodes)
    links = @($MindLinks)
}

$MindmapJson = ($MindmapData | ConvertTo-Json -Depth 10 -Compress) -replace '</', '<\/'
$GeneratedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')

$Html = @"
<!doctype html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AVA Symbolic Memory Portal</title>
  <style>
    :root {
      --bg: #0b1220;
      --panel: #141d33;
      --text: #e5ecff;
      --muted: #99a9d5;
      --accent: #8ec5ff;
      --chip: #25365f;
      --core: #ffd166;
      --cat: #7bd389;
      --mem: #8ec5ff;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Segoe UI, Roboto, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.4;
    }
    header {
      padding: 22px 20px;
      border-bottom: 1px solid #24365d;
      background: linear-gradient(180deg, #13203a 0%, var(--bg) 100%);
    }
    h1 { margin: 0 0 8px; font-size: 1.6rem; }
    .sub { color: var(--muted); font-size: .95rem; }
    .grid {
      display: grid;
      grid-template-columns: minmax(280px, 1fr) minmax(320px, 1fr);
      gap: 18px;
      padding: 18px;
    }
    .panel {
      background: var(--panel);
      border: 1px solid #24365d;
      border-radius: 14px;
      padding: 16px;
    }
    .cards {
      display: grid;
      gap: 12px;
      max-height: 70vh;
      overflow: auto;
      padding-right: 4px;
    }
    .card {
      background: #111a2f;
      border: 1px solid #283c6b;
      border-radius: 12px;
      padding: 12px;
    }
    .card-head {
      display: flex;
      justify-content: space-between;
      gap: 8px;
      margin-bottom: 6px;
      color: var(--muted);
      font-size: .78rem;
    }
    .card h3 { margin: 0 0 8px; font-size: 1.05rem; }
    .meaning { margin: 0 0 8px; color: var(--accent); }
    .note { margin: 0 0 10px; color: #d7e2ff; }
    .chips { display: flex; flex-wrap: wrap; gap: 6px; }
    .chip {
      display: inline-block;
      background: var(--chip);
      color: #dce9ff;
      border-radius: 999px;
      padding: 3px 9px;
      font-size: .74rem;
    }
    #mindmap {
      width: 100%;
      height: 70vh;
      min-height: 420px;
      border-radius: 10px;
      background: #0f172a;
      border: 1px solid #263a64;
    }
    footer {
      color: var(--muted);
      font-size: .82rem;
      padding: 0 18px 16px;
    }
    @media (max-width: 980px) {
      .grid { grid-template-columns: 1fr; }
      #mindmap { height: 420px; }
      .cards { max-height: none; }
    }
  </style>
</head>
<body>
  <header>
    <h1>AVA Symbolic Memory Portal</h1>
    <div class="sub">Lokal / Privat / Read-Only / Kein Upload / Keine Überwachung</div>
    <div class="sub">Generiert: $GeneratedAt</div>
  </header>

  <main class="grid">
    <section class="panel">
      <h2>Memory Cards</h2>
      <div class="cards">
        $($Cards -join "`n")
      </div>
    </section>

    <section class="panel">
      <h2>Symbolische Mindmap</h2>
      <svg id="mindmap" viewBox="0 0 900 700" preserveAspectRatio="xMidYMid meet" aria-label="Symbolische Mindmap"></svg>
    </section>
  </main>

  <footer>
    JSON: $(H $JsonPath) &nbsp;|&nbsp; CSV: $(H $CsvPath) &nbsp;|&nbsp; Portal: $(H $HtmlPath)
  </footer>

  <script>
    (function () {
      var graph = $MindmapJson;
      var svg = document.getElementById("mindmap");
      var ns = "http://www.w3.org/2000/svg";
      var width = 900;
      var height = 700;
      var cx = width / 2;
      var cy = height / 2;

      function colorFor(group) {
        if (group === "core") return "var(--core)";
        if (group === "category") return "var(--cat)";
        return "var(--mem)";
      }

      function nodeRadius(group) {
        if (group === "core") return 28;
        if (group === "category") return 17;
        return 12;
      }

      var nodesById = {};
      (graph.nodes || []).forEach(function (n) { nodesById[n.id] = n; });

      var core = graph.nodes.find(function (n) { return n.group === "core"; });
      if (!core) { return; }
      core.x = cx;
      core.y = cy;

      var categories = graph.nodes.filter(function (n) { return n.group === "category"; });
      var memories = graph.nodes.filter(function (n) { return n.group === "memory"; });

      categories.forEach(function (cat, i) {
        var a = (Math.PI * 2 * i) / Math.max(1, categories.length);
        cat.x = cx + Math.cos(a) * 190;
        cat.y = cy + Math.sin(a) * 190;
      });

      var memoriesByCategory = {};
      (graph.links || []).forEach(function (l) {
        var src = nodesById[l.source];
        var tgt = nodesById[l.target];
        if (!src || !tgt) return;
        if (src.group === "category" && tgt.group === "memory") {
          if (!memoriesByCategory[src.id]) memoriesByCategory[src.id] = [];
          memoriesByCategory[src.id].push(tgt);
        }
      });

      categories.forEach(function (cat) {
        var arr = memoriesByCategory[cat.id] || [];
        arr.forEach(function (mem, i) {
          var a = (Math.PI * 2 * i) / Math.max(1, arr.length);
          mem.x = cat.x + Math.cos(a) * 95;
          mem.y = cat.y + Math.sin(a) * 95;
        });
      });

      function drawLink(a, b) {
        var line = document.createElementNS(ns, "line");
        line.setAttribute("x1", a.x);
        line.setAttribute("y1", a.y);
        line.setAttribute("x2", b.x);
        line.setAttribute("y2", b.y);
        line.setAttribute("stroke", "#38507f");
        line.setAttribute("stroke-width", "1.6");
        line.setAttribute("opacity", "0.9");
        svg.appendChild(line);
      }

      (graph.links || []).forEach(function (l) {
        var src = nodesById[l.source];
        var tgt = nodesById[l.target];
        if (!src || !tgt || typeof src.x !== "number" || typeof tgt.x !== "number") return;
        drawLink(src, tgt);
      });

      function drawNode(n) {
        var g = document.createElementNS(ns, "g");
        var c = document.createElementNS(ns, "circle");
        var t = document.createElementNS(ns, "text");

        c.setAttribute("cx", n.x);
        c.setAttribute("cy", n.y);
        c.setAttribute("r", nodeRadius(n.group));
        c.setAttribute("fill", colorFor(n.group));
        c.setAttribute("stroke", "#10203d");
        c.setAttribute("stroke-width", "2");

        t.setAttribute("x", n.x);
        t.setAttribute("y", n.y + nodeRadius(n.group) + 14);
        t.setAttribute("text-anchor", "middle");
        t.setAttribute("font-size", n.group === "core" ? "13" : "11");
        t.setAttribute("fill", "#dce7ff");
        t.textContent = n.label;

        var tt = document.createElementNS(ns, "title");
        tt.textContent = n.label;
        c.appendChild(tt);

        g.appendChild(c);
        g.appendChild(t);
        svg.appendChild(g);
      }

      [core].concat(categories).concat(memories).forEach(function (n) {
        if (typeof n.x === "number" && typeof n.y === "number") {
          drawNode(n);
        }
      });
    }());
  </script>
</body>
</html>
"@

$Html | Set-Content -LiteralPath $HtmlPath -Encoding UTF8

Write-Host ""
Write-Host "AVA SYMBOLIC MEMORY PORTAL erstellt." -ForegroundColor Green
Write-Host "Ordner: $Root" -ForegroundColor Cyan
Write-Host "JSON:   $JsonPath" -ForegroundColor Cyan
Write-Host "CSV:    $CsvPath" -ForegroundColor Cyan
Write-Host "Portal: $HtmlPath" -ForegroundColor Cyan
Write-Host ""

Start-Process $HtmlPath
