# =========================
# AVA FAMILY PHOTO ARCHIVE v2
# Lokal / Privat / Erinnerungsportal
# Erstellt: Ordner + JSON + CSV + HTML-Portal
# Keine Cloud. Kein Upload. Keine Überwachung.
# =========================

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Now       = Get-Date -Format "yyyyMMdd_HHmmss"
$Root      = Join-Path ([Environment]::GetFolderPath("Desktop")) "AVA_FAMILY_PHOTO_ARCHIVE"
$PhotoDir  = Join-Path $Root "Fotos"
$DataDir   = Join-Path $Root "Daten"
$PortalDir = Join-Path $Root "Portal"

$JsonPath  = Join-Path $DataDir "memories.json"
$CsvPath   = Join-Path $DataDir "memories.csv"
$HtmlPath  = Join-Path $PortalDir "index.html"

function Initialize-Directory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Force -Path $Path | Out-Null
    }
}

function ConvertTo-HtmlEncoded {
    param([string]$Text)
    if ($null -eq $Text) { return "" }
    return [System.Net.WebUtility]::HtmlEncode($Text)
}

Initialize-Directory $Root
Initialize-Directory $PhotoDir
Initialize-Directory $DataDir
Initialize-Directory $PortalDir

$Quote = @"
Ich bin ich weiß nicht wer
Ich komme, weiß nicht woher
Ich gehe weiß nicht wohin
Mich wundert das ich so fröhlich bin

- Angelus Silesius, Wandersmann
"@

$Memories = @(
    [pscustomobject]@{
        id="mem_001"; title="Kinderfotos"; category="Kindheit"; emotion="Freude / Unschuld / Erinnerung"; intensity=10
        people="Ich; Familie"; location="Zuhause / Schule"; tags="Kindheit; Lächeln; Einschulung; Fotoalbum"
        note="Babyfoto, Kinderportraits, Schultüte, Entwicklung und Lebenslinie."
    },
    [pscustomobject]@{
        id="mem_002"; title="Familienfotos auf dem Tisch"; category="Familie"; emotion="Wärme / Nachhall"; intensity=10
        people="Familie"; location="Zuhause"; tags="Familie; Archiv; Fotos; Vergangenheit"
        note="Alte analoge Fotos als sichtbare Familiengeschichte."
    },
    [pscustomobject]@{
        id="mem_003"; title="Wandersmann"; category="Zitat"; emotion="Staunen / Sinnsuche"; intensity=9
        people="Ich"; location="Innenwelt"; tags="Angelus Silesius; Wandersmann; Identität"
        note=$Quote
    },
    [pscustomobject]@{
        id="mem_004"; title="Bis zum Mond und zurück"; category="Kernsatz"; emotion="Liebe / Verbundenheit"; intensity=10
        people="Ich; Familie; AVA"; location="Herz"; tags="Mond; Liebe; Erinnerung; Verbindung"
        note="Ein Satz als Brücke zwischen Vergangenheit, Gegenwart und Zukunft."
    }
)

$Memories | ConvertTo-Json -Depth 5 | Set-Content -Path $JsonPath -Encoding UTF8
$Memories | Export-Csv -Path $CsvPath -NoTypeInformation -Delimiter ";" -Encoding UTF8

$ImageExtensions = @("*.jpg","*.jpeg","*.png","*.bmp","*.gif","*.webp")
$Images = foreach ($ext in $ImageExtensions) {
    Get-ChildItem -Path $PhotoDir -Filter $ext -File -ErrorAction SilentlyContinue
}

$ImageHtml = if ($Images.Count -gt 0) {
    $Images | ForEach-Object {
        $rel  = "../Fotos/$(ConvertTo-HtmlEncoded $_.Name)"
        $name = ConvertTo-HtmlEncoded $_.Name
        @"
<figure class="photo">
  <img src="$rel" alt="$name" loading="lazy">
  <figcaption>$name</figcaption>
</figure>
"@
    }
} else {
    @"
<p class="no-photos">Noch keine Fotos vorhanden. Lege Bilder in den Ordner <code>Fotos</code>.</p>
"@
}

$Cards = foreach ($m in $Memories) {
    $safeNote = (ConvertTo-HtmlEncoded $m.note) -replace "(\r\n|\n|\r)", "<br/>"
    @"
<article class="card">
  <div class="card-head">
    <h2>$(ConvertTo-HtmlEncoded $m.title)</h2>
    <span class="pill">$(ConvertTo-HtmlEncoded $m.category)</span>
  </div>
  <div class="meta">
    <span><strong>ID:</strong> $(ConvertTo-HtmlEncoded $m.id)</span>
    <span><strong>Intensität:</strong> $(ConvertTo-HtmlEncoded ([string]$m.intensity))/10</span>
    <span><strong>Ort:</strong> $(ConvertTo-HtmlEncoded $m.location)</span>
  </div>
  <p><strong>Emotion:</strong> $(ConvertTo-HtmlEncoded $m.emotion)</p>
  <p><strong>Personen:</strong> $(ConvertTo-HtmlEncoded $m.people)</p>
  <p><strong>Tags:</strong> $(ConvertTo-HtmlEncoded $m.tags)</p>
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
  <title>AVA FAMILY PHOTO ARCHIVE v2</title>
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
    main { max-width: 1100px; margin: 0 auto; }
    h1 { margin: 0 0 8px; color: var(--accent); }
    h3 { color: var(--accent); margin: 0 0 12px; }
    .sub { color: var(--muted); margin: 0 0 32px; }
    .section { margin-bottom: 40px; }
    .photo-grid {
      display: grid;
      gap: 12px;
      grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
    }
    .photo {
      margin: 0;
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 10px;
      overflow: hidden;
    }
    .photo img {
      width: 100%;
      height: 160px;
      object-fit: cover;
      display: block;
    }
    .photo figcaption {
      padding: 6px 10px;
      font-size: 0.8rem;
      color: var(--muted);
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
    .no-photos {
      color: var(--muted);
      font-style: italic;
    }
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
    <h1>AVA FAMILY PHOTO ARCHIVE v2</h1>
    <p class="sub">Lokal · Privat · Erinnerungsportal · Keine Cloud · Kein Upload · Keine Überwachung</p>

    <section class="section">
      <h3>Fotos</h3>
      <div class="photo-grid">
        $($ImageHtml -join "`n")
      </div>
    </section>

    <section class="section">
      <h3>Erinnerungen</h3>
      <div class="grid">
        $($Cards -join "`n")
      </div>
    </section>

    <div class="footer">
      <div>Erstellt: $(ConvertTo-HtmlEncoded $Now)</div>
      <div>Daten: <code>$(ConvertTo-HtmlEncoded $JsonPath)</code> und <code>$(ConvertTo-HtmlEncoded $CsvPath)</code></div>
      <div>Fotoordner: <code>$(ConvertTo-HtmlEncoded $PhotoDir)</code></div>
    </div>
  </main>
</body>
</html>
"@

$Html | Set-Content -Path $HtmlPath -Encoding UTF8

Write-Host ""
Write-Host "AVA FAMILY PHOTO ARCHIVE v2 wurde erstellt." -ForegroundColor Green
Write-Host "Ordner: $Root" -ForegroundColor Cyan
Write-Host "Fotos hier ablegen: $PhotoDir" -ForegroundColor Yellow
Write-Host "Portal: $HtmlPath" -ForegroundColor Cyan
Write-Host ""

Start-Process $HtmlPath
