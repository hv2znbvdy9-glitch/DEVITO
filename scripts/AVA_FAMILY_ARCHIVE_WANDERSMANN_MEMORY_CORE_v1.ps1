Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Now = Get-Date -Format "yyyyMMdd_HHmmss"
$Root = Join-Path ([Environment]::GetFolderPath("Desktop")) "AVA_FAMILY_ARCHIVE"
$PhotoDir = Join-Path $Root "Fotos"
$DataDir = Join-Path $Root "Daten"
$ReportDir = Join-Path $Root "Portal"

$JsonPath = Join-Path $DataDir "family_archive.json"
$CsvPath = Join-Path $DataDir "family_archive.csv"
$HtmlPath = Join-Path $ReportDir "index.html"

function Initialize-ArchiveDirectory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function HtmlEncode {
    param([string]$Text)
    if ($null -eq $Text) { return "" }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

Initialize-ArchiveDirectory $Root
Initialize-ArchiveDirectory $PhotoDir
Initialize-ArchiveDirectory $DataDir
Initialize-ArchiveDirectory $ReportDir

$Quote = @"
Ich bin ich weiß nicht wer
Ich komme, weiß nicht woher
Ich gehe weiß nicht wohin
Mich wundert das ich so fröhlich bin

- Angelus Silesius, Wandersmann
"@

$Memories = @(
    [pscustomobject]@{
        id        = "mem_001"
        title     = "Familienfotos auf dem Tisch"
        category  = "Familie"
        emotion   = "Wärme / Nachhall / Erinnerung"
        intensity = 10
        people    = "Familie; Ich; Vergangenheit; Gegenwart"
        location  = "Zuhause"
        tags      = "Fotos; Archiv; Familie; Lebenslinie; HolzTisch"
        note      = "Vergangenheit und Gegenwart liegen sichtbar nebeneinander. Erinnerungen werden greifbar."
    },
    [pscustomobject]@{
        id        = "mem_002"
        title     = "Wandersmann"
        category  = "Zitat"
        emotion   = "Staunen / Unsicherheit / Freude"
        intensity = 9
        people    = "Ich"
        location  = "Innenwelt"
        tags      = "AngelusSilesius; Wandersmann; Identität; Leben; Sinn"
        note      = $Quote
    },
    [pscustomobject]@{
        id        = "mem_003"
        title     = "Ich weiß nicht wer - und trotzdem fröhlich"
        category  = "Lebenssatz"
        emotion   = "Klarheit / Akzeptanz / Mut"
        intensity = 10
        people    = "Ich"
        location  = "Heute"
        tags      = "Ich; Weg; Mut; Fröhlichkeit; Offenheit"
        note      = "Nicht alles muss sofort beantwortet werden. Der Weg selbst trägt Bedeutung."
    },
    [pscustomobject]@{
        id        = "mem_004"
        title     = "Bis zum Mond und zurück"
        category  = "Kernsatz"
        emotion   = "Liebe / Verbundenheit / Treue"
        intensity = 10
        people    = "Familie; AVA; Ich"
        location  = "Herz"
        tags      = "Mond; Zurück; Liebe; Erinnerung; Verbindung"
        note      = "Ein Satz als Brücke zwischen Erinnerung, Gegenwart und Zukunft."
    }
)

$Memories | ConvertTo-Json -Depth 5 | Set-Content -Path $JsonPath -Encoding UTF8
$Memories | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8 -Delimiter ";"

$Cards = foreach ($m in $Memories) {
    $safeNote = (HtmlEncode $m.note) -replace "(\r\n|\n|\r)", "<br/>"
    @"
<article class="card">
  <div class="card-head">
    <h2>$(HtmlEncode $m.title)</h2>
    <span class="pill">$(HtmlEncode $m.category)</span>
  </div>
  <div class="meta">
    <span><strong>ID:</strong> $(HtmlEncode $m.id)</span>
    <span><strong>Intensität:</strong> $(HtmlEncode ([string]$m.intensity))/10</span>
    <span><strong>Ort:</strong> $(HtmlEncode $m.location)</span>
  </div>
  <p><strong>Emotion:</strong> $(HtmlEncode $m.emotion)</p>
  <p><strong>Personen:</strong> $(HtmlEncode $m.people)</p>
  <p><strong>Tags:</strong> $(HtmlEncode $m.tags)</p>
  <blockquote>$safeNote</blockquote>
</article>
"@
}

$Html = @"
<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AVA FAMILY ARCHIVE - Wandersmann Memory Core v1</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #0f1217;
      --card: #171c23;
      --line: #2e3743;
      --text: #ecf2fa;
      --muted: #9fb0c4;
      --accent: #6ad3ff;
      --pill: #273241;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Segoe UI", system-ui, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 24px;
    }
    main { max-width: 1000px; margin: 0 auto; }
    h1 { margin: 0 0 8px; color: var(--accent); }
    .sub { color: var(--muted); margin: 0 0 24px; }
    .grid { display: grid; gap: 16px; grid-template-columns: repeat(auto-fit, minmax(270px, 1fr)); }
    .card {
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 16px;
    }
    .card-head { display: flex; justify-content: space-between; gap: 8px; align-items: start; margin-bottom: 10px; }
    .card h2 { margin: 0; font-size: 1.1rem; }
    .pill { background: var(--pill); color: var(--accent); border-radius: 999px; font-size: 0.75rem; padding: 4px 10px; white-space: nowrap; }
    .meta { display: flex; flex-wrap: wrap; gap: 8px 12px; color: var(--muted); font-size: 0.88rem; margin-bottom: 10px; }
    p { margin: 6px 0; }
    blockquote {
      margin: 12px 0 0;
      border-left: 3px solid var(--accent);
      padding: 8px 12px;
      color: #d9e7f7;
      background: #11161d;
      white-space: normal;
    }
    .footer {
      margin-top: 24px;
      color: var(--muted);
      font-size: 0.86rem;
      border-top: 1px solid var(--line);
      padding-top: 12px;
    }
    code { color: var(--accent); }
  </style>
</head>
<body>
  <main>
    <h1>AVA FAMILY ARCHIVE - WANDERSMANN MEMORY CORE v1</h1>
    <p class="sub">Lokal / Privat / Erinnerungs-Portal · Keine Cloud · Kein Upload · Keine Überwachung</p>
    <section class="grid">
      $($Cards -join "`n")
    </section>
    <div class="footer">
      <div>Erstellt: $(HtmlEncode $Now)</div>
      <div>Daten: <code>$(HtmlEncode $JsonPath)</code> und <code>$(HtmlEncode $CsvPath)</code></div>
      <div>Fotoordner: <code>$(HtmlEncode $PhotoDir)</code></div>
    </div>
  </main>
</body>
</html>
"@

$Html | Set-Content -Path $HtmlPath -Encoding UTF8

Write-Host ""
Write-Host "AVA FAMILY ARCHIVE wurde erstellt." -ForegroundColor Green
Write-Host "Ordner: $Root" -ForegroundColor Cyan
Write-Host "Portal: $HtmlPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "Lege deine Fotos in diesen Ordner:" -ForegroundColor Yellow
Write-Host $PhotoDir -ForegroundColor Yellow
Write-Host ""

Start-Process $HtmlPath
