#requires -Version 5.1
<#
AVA COMMUNITY SECURITY CHECK v3
Ehrenamtlich / Respektvoll / Gesellschaftlich wertvoll
Lokal / Read-Only / Keine Angriffe / Keine Änderungen
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$Now = Get-Date -Format 'yyyyMMdd_HHmmss'
$OutDir = Join-Path ([Environment]::GetFolderPath('Desktop')) "AVA_COMMUNITY_SECURITY_CHECK_v3_$Now"
$ReportHtml = Join-Path $OutDir 'ava_community_security_portal_v3.html'
$ReportTxt = Join-Path $OutDir 'ava_community_security_report_v3.txt'
$ReportJson = Join-Path $OutDir 'ava_community_security_report_v3.json'

$CriticalPenalty = 25
$WarnPenalty = 7
$MaxHotfixesToDisplay = 5
$MaxRowsPerSection = 12
$SuspiciousPowerShellPatterns = @(
    '(?<!\S)-enc(?!\S)',
    '(?<!\S)-encodedcommand(?!\S)',
    '(?<!\S)-executionpolicy\s+bypass(?=\s|$)',
    '(?<!\S)-ep\s+bypass(?=\s|$)',
    '(?<!\S)-nop(?!\S)',
    '(?<!\S)-windowstyle\s+hidden(?=\s|$)',
    '\binvoke-expression\b',
    '\biex\b',
    '\bdownloadstring\b'
)
$RiskyRemotePorts = @(21, 23, 135, 139, 445, 3389, 5985, 5986)

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$Results = New-Object System.Collections.Generic.List[object]

function Add-Result {
    param(
        [string]$Category,
        [string]$Status,
        [string]$Title,
        [string]$Message,
        [string]$Recommendation
    )

    $Results.Add([pscustomobject]@{
            Time = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            Category = $Category
            Status = $Status
            Title = $Title
            Message = $Message
            Recommendation = $Recommendation
        }) | Out-Null
}

function ConvertTo-HtmlEncoded {
    param([AllowNull()][object]$Text)

    if ($null -eq $Text) {
        return ''
    }

    return [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

function Get-StatusColor {
    param([string]$Status)

    switch ($Status) {
        'OK' { return '#1f8f4d' }
        'INFO' { return '#2f6fed' }
        'WARN' { return '#d68a00' }
        'CRITICAL' { return '#c62828' }
        default { return '#64748b' }
    }
}

function ConvertTo-ResultTableMarkup {
    param(
        [object[]]$Entries
    )

    if (-not $Entries -or $Entries.Count -eq 0) {
        return @'
<tr>
  <td colspan="5">Keine Einträge vorhanden.</td>
</tr>
'@
    }

    return ($Entries | ForEach-Object {
            $color = Get-StatusColor -Status $_.Status
            @"
<tr>
  <td><span class="badge" style="background:$color;">$(ConvertTo-HtmlEncoded $_.Status)</span></td>
  <td>$(ConvertTo-HtmlEncoded $_.Category)</td>
  <td>$(ConvertTo-HtmlEncoded $_.Title)</td>
  <td>$(ConvertTo-HtmlEncoded $_.Message)</td>
  <td>$(ConvertTo-HtmlEncoded $_.Recommendation)</td>
</tr>
"@
        }) -join "`n"
}

function ConvertTo-SectionCardMarkup {
    param(
        [object[]]$Entries
    )

    if (-not $Entries -or $Entries.Count -eq 0) {
        return @'
<div class="mini-card">
  <div class="mini-value">0</div>
  <div class="mini-label">Einträge</div>
</div>
'@
    }

    $criticalCount = @($Entries | Where-Object Status -eq 'CRITICAL').Count
    $warnCount = @($Entries | Where-Object Status -eq 'WARN').Count
    $okCount = @($Entries | Where-Object Status -eq 'OK').Count

    return @"
<div class="mini-card">
  <div class="mini-value">$($Entries.Count)</div>
  <div class="mini-label">Einträge</div>
</div>
<div class="mini-card">
  <div class="mini-value">$okCount</div>
  <div class="mini-label">OK</div>
</div>
<div class="mini-card">
  <div class="mini-value">$warnCount</div>
  <div class="mini-label">Warn</div>
</div>
<div class="mini-card">
  <div class="mini-value">$criticalCount</div>
  <div class="mini-label">Critical</div>
</div>
"@
}

function ConvertTo-DetailListMarkup {
    param(
        [string[]]$Items
    )

    if (-not $Items -or $Items.Count -eq 0) {
        return '<li>Keine zusätzlichen Details vorhanden.</li>'
    }

    return ($Items | ForEach-Object { "<li>$(ConvertTo-HtmlEncoded $_)</li>" }) -join "`n"
}

# =========================
# SYSTEMBASIS
# =========================
$os = $null
try {
    $os = Get-CimInstance Win32_OperatingSystem
    Add-Result -Category 'System' -Status 'INFO' -Title 'Betriebssystem' `
        -Message "$($os.Caption) | Version: $($os.Version) | Build: $($os.BuildNumber)" `
        -Recommendation 'System regelmäßig aktualisieren und dokumentieren.'
}
catch {
    Add-Result -Category 'System' -Status 'WARN' -Title 'Betriebssystem konnte nicht gelesen werden' `
        -Message $_.Exception.Message `
        -Recommendation 'PowerShell als normaler Benutzer reicht meist, Admin erhöht die Details.'
}

try {
    if ($null -ne $os) {
        $uptime = (Get-Date) - $os.LastBootUpTime
        Add-Result -Category 'System' -Status 'INFO' -Title 'Laufzeit seit Neustart' `
            -Message ('{0} Tage, {1} Stunden' -f [int]$uptime.TotalDays, $uptime.Hours) `
            -Recommendation 'Gelegentlich sauber neu starten, damit Updates greifen.'
    }
}
catch {
    Write-Debug "Uptime not available: $($_.Exception.Message)"
}

# =========================
# DEFENDER / FIREWALL
# =========================
try {
    $mp = Get-MpComputerStatus

    if ($mp.RealTimeProtectionEnabled) {
        Add-Result -Category 'Schutz' -Status 'OK' -Title 'Microsoft Defender Echtzeitschutz' `
            -Message 'Aktiv' `
            -Recommendation 'Sehr gut. Echtzeitschutz aktiviert lassen.'
    }
    else {
        Add-Result -Category 'Schutz' -Status 'CRITICAL' -Title 'Microsoft Defender Echtzeitschutz' `
            -Message 'Nicht aktiv' `
            -Recommendation 'Defender prüfen und Echtzeitschutz aktivieren.'
    }

    if ($mp.AntivirusSignatureLastUpdated) {
        Add-Result -Category 'Schutz' -Status 'INFO' -Title 'Defender Signaturen' `
            -Message "Letztes Update: $($mp.AntivirusSignatureLastUpdated)" `
            -Recommendation 'Signaturen regelmäßig aktualisieren.'
    }
}
catch {
    Add-Result -Category 'Schutz' -Status 'WARN' -Title 'Defender Status nicht verfügbar' `
        -Message $_.Exception.Message `
        -Recommendation 'Falls ein anderes Antivirus aktiv ist, dort den Schutzstatus prüfen.'
}

try {
    $profiles = Get-NetFirewallProfile
    foreach ($firewallProfile in $profiles) {
        if ($firewallProfile.Enabled) {
            Add-Result -Category 'Firewall' -Status 'OK' -Title "Firewall Profil: $($firewallProfile.Name)" `
                -Message 'Aktiv' `
                -Recommendation 'Firewall aktiv lassen.'
        }
        else {
            Add-Result -Category 'Firewall' -Status 'CRITICAL' -Title "Firewall Profil: $($firewallProfile.Name)" `
                -Message 'Nicht aktiv' `
                -Recommendation 'Firewall-Profil prüfen und aktivieren.'
        }
    }
}
catch {
    Add-Result -Category 'Firewall' -Status 'WARN' -Title 'Firewall Status nicht lesbar' `
        -Message $_.Exception.Message `
        -Recommendation 'Mit Adminrechten erneut prüfen.'
}

# =========================
# REMOTE / KONTEN
# =========================
try {
    $rdp = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction Stop
    if ($rdp.fDenyTSConnections -eq 1) {
        Add-Result -Category 'Remote Zugriff' -Status 'OK' -Title 'Remote Desktop' `
            -Message 'RDP ist deaktiviert' `
            -Recommendation 'Gut für normale Vereins- und Familien-PCs.'
    }
    else {
        Add-Result -Category 'Remote Zugriff' -Status 'WARN' -Title 'Remote Desktop' `
            -Message 'RDP ist aktiviert' `
            -Recommendation 'Nur aktiv lassen, wenn wirklich benötigt. VPN und starke Passwörter verwenden.'
    }
}
catch {
    Add-Result -Category 'Remote Zugriff' -Status 'INFO' -Title 'Remote Desktop' `
        -Message 'Status konnte nicht gelesen werden' `
        -Recommendation 'Bei Bedarf manuell prüfen.'
}

try {
    $admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop
    foreach ($admin in $admins) {
        Add-Result -Category 'Konten' -Status 'INFO' -Title 'Lokaler Administrator' `
            -Message "$($admin.Name) | $($admin.ObjectClass)" `
            -Recommendation 'Adminrechte sparsam vergeben und regelmäßig prüfen.'
    }
}
catch {
    Add-Result -Category 'Konten' -Status 'WARN' -Title 'Administratoren konnten nicht gelesen werden' `
        -Message $_.Exception.Message `
        -Recommendation 'Mit Adminrechten erneut ausführen.'
}

# =========================
# POWERSHELL PROZESSE
# =========================
$powerShellProcessCount = 0
$suspiciousPowerShellCount = 0
try {
    $powerShellProcesses = @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'")
    $powerShellProcessCount = @($powerShellProcesses | Where-Object { $_.ProcessId -ne $PID }).Count

    foreach ($process in $powerShellProcesses) {
        if ($null -eq $process.CommandLine) {
            continue
        }

        $commandLine = [string]$process.CommandLine
        $lowerCommandLine = $commandLine.ToLowerInvariant()
        $hits = @()

        foreach ($pattern in $SuspiciousPowerShellPatterns) {
            if ($lowerCommandLine -match $pattern) {
                $hits += $pattern
            }
        }

        if ($hits.Count -gt 0) {
            $suspiciousPowerShellCount++
            Add-Result -Category 'Prozesse' -Status 'WARN' -Title 'Auffälliger PowerShell Prozess' `
                -Message "PID $($process.ProcessId) | Treffer: $($hits -join ', ') | $commandLine" `
                -Recommendation 'Prüfen, ob dieser Prozess zu einem legitimen Admin- oder Updatevorgang gehört.'
        }
    }

    if ($powerShellProcessCount -eq 0) {
        Add-Result -Category 'Prozesse' -Status 'OK' -Title 'PowerShell Prozesse' `
            -Message 'Keine zusätzlichen laufenden PowerShell-Prozesse erkannt' `
            -Recommendation 'Gut.'
    }
    elseif ($suspiciousPowerShellCount -eq 0) {
        Add-Result -Category 'Prozesse' -Status 'OK' -Title 'PowerShell Prozesse' `
            -Message 'Keine auffälligen PowerShell-Argumente erkannt' `
            -Recommendation 'Gut.'
    }
}
catch {
    Add-Result -Category 'Prozesse' -Status 'WARN' -Title 'Prozessprüfung fehlgeschlagen' `
        -Message $_.Exception.Message `
        -Recommendation 'Später erneut prüfen.'
}

# =========================
# NETZWERK - NUR LOKAL
# =========================
$networkDetails = New-Object System.Collections.Generic.List[string]
$connections = @()
try {
    $ipConfigurations = @(Get-NetIPConfiguration | Where-Object { $_.IPv4Address -or $_.IPv6Address })
    foreach ($configuration in $ipConfigurations) {
        $ipv4 = @($configuration.IPv4Address | ForEach-Object { $_.IPAddress }) -join ', '
        $gateway = @($configuration.IPv4DefaultGateway | ForEach-Object { $_.NextHop }) -join ', '
        $networkDetails.Add("$($configuration.InterfaceAlias): IPv4=$ipv4 | Gateway=$gateway") | Out-Null
    }

    if ($networkDetails.Count -gt 0) {
        Add-Result -Category 'Netzwerk' -Status 'INFO' -Title 'Netzwerkadapter Übersicht' `
            -Message "$($networkDetails.Count) aktive Adapter erkannt" `
            -Recommendation 'Lokale Adapter regelmäßig prüfen.'
    }
}
catch {
    Add-Result -Category 'Netzwerk' -Status 'INFO' -Title 'Netzwerkadapter' `
        -Message 'Adapterübersicht konnte nicht vollständig gelesen werden' `
        -Recommendation 'Bei Bedarf ipconfig oder Adapteransicht lokal prüfen.'
}

try {
    $connections = @(Get-NetTCPConnection -State Established -ErrorAction Stop)

    foreach ($connection in $connections) {
        if ($RiskyRemotePorts -contains $connection.RemotePort) {
            Add-Result -Category 'Netzwerk' -Status 'WARN' -Title 'Verbindung zu sensiblem Port' `
                -Message "Local: $($connection.LocalAddress):$($connection.LocalPort) -> Remote: $($connection.RemoteAddress):$($connection.RemotePort)" `
                -Recommendation 'Nur prüfen. Nicht jede Verbindung ist gefährlich, aber sensible Ports verdienen Aufmerksamkeit.'
        }
    }

    Add-Result -Category 'Netzwerk' -Status 'INFO' -Title 'Aktive TCP-Verbindungen' `
        -Message "$($connections.Count) etablierte Verbindungen gefunden" `
        -Recommendation 'Nur lokale Sicht. Kein Fremdscan wurde durchgeführt.'
}
catch {
    Add-Result -Category 'Netzwerk' -Status 'WARN' -Title 'Netzwerkverbindungen konnten nicht gelesen werden' `
        -Message $_.Exception.Message `
        -Recommendation 'Mit Adminrechten erneut prüfen.'
}

# =========================
# UPDATES
# =========================
try {
    $hotfixes = @(Get-HotFix |
            Where-Object { $null -ne $_.InstalledOn } |
            Sort-Object InstalledOn -Descending |
            Select-Object -First $MaxHotfixesToDisplay)

    foreach ($hotfix in $hotfixes) {
        Add-Result -Category 'Updates' -Status 'INFO' -Title 'Installiertes Update' `
            -Message "$($hotfix.HotFixID) | Installiert am: $($hotfix.InstalledOn)" `
            -Recommendation 'Windows Update regelmäßig prüfen.'
    }
}
catch {
    Add-Result -Category 'Updates' -Status 'INFO' -Title 'Updates' `
        -Message 'Hotfix-Liste konnte nicht gelesen werden' `
        -Recommendation 'Windows Update manuell prüfen.'
}

# =========================
# SCORE / EXPORTS
# =========================
$critical = @($Results | Where-Object Status -eq 'CRITICAL').Count
$warn = @($Results | Where-Object Status -eq 'WARN').Count
$ok = @($Results | Where-Object Status -eq 'OK').Count
$info = @($Results | Where-Object Status -eq 'INFO').Count

$Score = 100 - ($critical * $CriticalPenalty) - ($warn * $WarnPenalty)
if ($Score -lt 0) {
    $Score = 0
}

$ScoreText = if ($Score -ge 85) {
    'Sehr stabil'
}
elseif ($Score -ge 65) {
    'Solide, aber prüfenswert'
}
elseif ($Score -ge 40) {
    'Verbesserungsbedarf'
}
else {
    'Dringend prüfen'
}

$ProtectionEntries = @($Results | Where-Object { $_.Category -in @('Schutz', 'Firewall') })
$NetworkEntries = @($Results | Where-Object Category -eq 'Netzwerk')
$ProcessEntries = @($Results | Where-Object Category -eq 'Prozesse')

$RiskyConnectionCount = @($NetworkEntries | Where-Object Title -eq 'Verbindung zu sensiblem Port').Count
$TopConnectionDetails = @(
    $connections |
        Select-Object -First 5 |
        ForEach-Object { "$($_.LocalAddress):$($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort)" }
)

$reportPayload = [pscustomobject]@{
    generatedAt = (Get-Date).ToString('s')
    computerName = $env:COMPUTERNAME
    userName = $env:USERNAME
    score = $Score
    scoreText = $ScoreText
    summary = [pscustomobject]@{
        critical = $critical
        warn = $warn
        ok = $ok
        info = $info
        powerShellProcesses = $powerShellProcessCount
        suspiciousPowerShellProcesses = $suspiciousPowerShellCount
        establishedConnections = @($connections).Count
        riskyConnections = $RiskyConnectionCount
    }
    results = $Results
}
$reportPayload | ConvertTo-Json -Depth 6 | Set-Content -Path $ReportJson -Encoding UTF8

$textReport = @()
$textReport += 'AVA COMMUNITY SECURITY CHECK v3'
$textReport += "Zeit: $(Get-Date)"
$textReport += "Computer: $env:COMPUTERNAME"
$textReport += "Benutzer: $env:USERNAME"
$textReport += "Security Score: $Score / 100 - $ScoreText"
$textReport += ''
$textReport += 'Ehrenamtlicher Read-Only Report:'
$textReport += '- Lokal ausgeführt'
$textReport += '- Keine Cloud'
$textReport += '- Kein Upload'
$textReport += '- Kein Fremdscan'
$textReport += ''
$textReport += '🌀 CHECKAAR VOM NECKAR MODE AKTIVIERT 😂👍'
$textReport += ''
foreach ($entry in $Results) {
    $textReport += "[$($entry.Status)] $($entry.Category) - $($entry.Title)"
    $textReport += "  $($entry.Message)"
    $textReport += "  Empfehlung: $($entry.Recommendation)"
    $textReport += ''
}
$textReport -join "`r`n" | Set-Content -Path $ReportTxt -Encoding UTF8

$ProtectionRows = ConvertTo-ResultTableMarkup -Entries ($ProtectionEntries | Select-Object -First $MaxRowsPerSection)
$NetworkRows = ConvertTo-ResultTableMarkup -Entries ($NetworkEntries | Select-Object -First $MaxRowsPerSection)
$ProcessRows = ConvertTo-ResultTableMarkup -Entries ($ProcessEntries | Select-Object -First $MaxRowsPerSection)
$AllRows = ConvertTo-ResultTableMarkup -Entries $Results

$Html = @"
<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AVA COMMUNITY SECURITY CHECK v3</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #0f172a;
      --card: #172033;
      --line: #22314c;
      --text: #e2e8f0;
      --muted: #9fb0c4;
      --accent: #67e8f9;
      --good: #1f8f4d;
      --warn: #d68a00;
      --bad: #c62828;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Segoe UI", system-ui, sans-serif;
      background: radial-gradient(circle at top, #12213f 0%, var(--bg) 45%);
      color: var(--text);
      line-height: 1.5;
      padding: 24px;
    }
    .wrap { max-width: 1250px; margin: 0 auto; }
    h1, h2 { margin-top: 0; }
    h1 { color: var(--accent); margin-bottom: 8px; }
    h2 { color: var(--accent); font-size: 1.1rem; }
    .sub { color: var(--muted); margin-bottom: 18px; }
    .banner {
      margin: 20px 0;
      padding: 14px 18px;
      border: 1px solid var(--line);
      border-radius: 14px;
      background: rgba(23, 32, 51, 0.75);
      color: #dbeafe;
      font-weight: 600;
    }
    .hero, .mini-grid, .section-grid {
      display: grid;
      gap: 14px;
    }
    .hero {
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      margin-bottom: 20px;
    }
    .card, .section, .mini-card {
      background: rgba(23, 32, 51, 0.9);
      border: 1px solid var(--line);
      border-radius: 14px;
    }
    .card {
      padding: 16px;
      min-height: 118px;
    }
    .value { font-size: 2rem; font-weight: 700; }
    .label { color: var(--muted); font-size: 0.88rem; }
    .section-grid { grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); }
    .section {
      padding: 18px;
      margin-bottom: 18px;
    }
    .mini-grid {
      grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
      margin: 12px 0 16px;
    }
    .mini-card {
      padding: 12px;
      text-align: center;
    }
    .mini-value { font-size: 1.3rem; font-weight: 700; }
    .mini-label { color: var(--muted); font-size: 0.8rem; }
    ul { padding-left: 18px; }
    table {
      width: 100%;
      border-collapse: collapse;
      overflow: hidden;
      border-radius: 12px;
    }
    th, td {
      padding: 10px 12px;
      border-bottom: 1px solid var(--line);
      vertical-align: top;
      text-align: left;
      font-size: 0.92rem;
    }
    th { color: #cbd5e1; background: rgba(15, 23, 42, 0.85); }
    tr:hover td { background: rgba(15, 23, 42, 0.65); }
    .badge {
      color: white;
      padding: 4px 8px;
      border-radius: 999px;
      display: inline-block;
      font-size: 0.75rem;
      font-weight: 700;
    }
    .footer {
      margin-top: 24px;
      color: var(--muted);
      font-size: 0.86rem;
      border-top: 1px solid var(--line);
      padding-top: 14px;
    }
    code { color: var(--accent); word-break: break-all; }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>AVA COMMUNITY SECURITY CHECK v3</h1>
    <div class="sub">Ehrenamtlich / Respektvoll / Gesellschaftlich wertvoll &middot; Lokal / Read-Only / Keine Angriffe / Keine Änderungen</div>

    <div class="banner">Wenn alles passt, öffnet sich automatisch dein lokales HTML-Portal mit Security Score, Defender-/Firewall-Check, Netzwerkübersicht, PowerShell-Prozessanalyse und ehrenamtlichem Read-Only Report.</div>

    <section class="hero">
      <div class="card"><div class="value">$Score</div><div class="label">Security Score / 100</div><div>$(ConvertTo-HtmlEncoded $ScoreText)</div></div>
      <div class="card"><div class="value">$critical</div><div class="label">Critical Findings</div><div>Hohe Priorität</div></div>
      <div class="card"><div class="value">$warn</div><div class="label">Warn Findings</div><div>Prüfen empfohlen</div></div>
      <div class="card"><div class="value">$(@($connections).Count)</div><div class="label">Netzwerk-Verbindungen</div><div>$RiskyConnectionCount sensible Ports</div></div>
      <div class="card"><div class="value">$powerShellProcessCount</div><div class="label">PowerShell-Prozesse</div><div>$suspiciousPowerShellCount auffällig</div></div>
      <div class="card"><div class="value">Read-Only</div><div class="label">Report-Modus</div><div>Keine Änderungen am Zielsystem</div></div>
    </section>

    <section class="section">
      <h2>Defender- / Firewall-Check</h2>
      <div class="mini-grid">
        $(ConvertTo-SectionCardMarkup -Entries $ProtectionEntries)
      </div>
      <table>
        <thead>
          <tr>
            <th>Status</th>
            <th>Kategorie</th>
            <th>Titel</th>
            <th>Nachricht</th>
            <th>Empfehlung</th>
          </tr>
        </thead>
        <tbody>
          $ProtectionRows
        </tbody>
      </table>
    </section>

    <section class="section-grid">
      <section class="section">
        <h2>Netzwerkübersicht</h2>
        <div class="mini-grid">
          $(ConvertTo-SectionCardMarkup -Entries $NetworkEntries)
        </div>
        <ul>
          $(ConvertTo-DetailListMarkup -Items ([string[]]$networkDetails.ToArray()))
          $(ConvertTo-DetailListMarkup -Items $TopConnectionDetails)
        </ul>
        <table>
          <thead>
            <tr>
              <th>Status</th>
              <th>Kategorie</th>
              <th>Titel</th>
              <th>Nachricht</th>
              <th>Empfehlung</th>
            </tr>
          </thead>
          <tbody>
            $NetworkRows
          </tbody>
        </table>
      </section>

      <section class="section">
        <h2>PowerShell-Prozessanalyse</h2>
        <div class="mini-grid">
          $(ConvertTo-SectionCardMarkup -Entries $ProcessEntries)
        </div>
        <ul>
          <li>Zusätzliche laufende PowerShell-Prozesse: $(ConvertTo-HtmlEncoded $powerShellProcessCount)</li>
          <li>Auffällige Treffer anhand lokaler Musterprüfung: $(ConvertTo-HtmlEncoded $suspiciousPowerShellCount)</li>
          <li>Erkennung basiert nur auf lokalen Befehlszeilenmustern, ohne Eingriffe.</li>
        </ul>
        <table>
          <thead>
            <tr>
              <th>Status</th>
              <th>Kategorie</th>
              <th>Titel</th>
              <th>Nachricht</th>
              <th>Empfehlung</th>
            </tr>
          </thead>
          <tbody>
            $ProcessRows
          </tbody>
        </table>
      </section>
    </section>

    <section class="section">
      <h2>Ehrenamtlicher Read-Only Report</h2>
      <ul>
        <li>Lokal / Privat / defensiv: keine Cloud, kein Upload, kein Fremdscan.</li>
        <li>Computer: $(ConvertTo-HtmlEncoded $env:COMPUTERNAME) &middot; Benutzer: $(ConvertTo-HtmlEncoded $env:USERNAME)</li>
        <li>HTML Portal: <code>$(ConvertTo-HtmlEncoded $ReportHtml)</code></li>
        <li>TXT Report: <code>$(ConvertTo-HtmlEncoded $ReportTxt)</code></li>
        <li>JSON Report: <code>$(ConvertTo-HtmlEncoded $ReportJson)</code></li>
      </ul>
      <div class="banner">🌀 CHECKAAR VOM NECKAR MODE AKTIVIERT 😂👍</div>
    </section>

    <section class="section">
      <h2>Vollständige Ergebnisliste</h2>
      <table>
        <thead>
          <tr>
            <th>Status</th>
            <th>Kategorie</th>
            <th>Titel</th>
            <th>Nachricht</th>
            <th>Empfehlung</th>
          </tr>
        </thead>
        <tbody>
          $AllRows
        </tbody>
      </table>
    </section>

    <div class="footer">
      <div>Export: $(ConvertTo-HtmlEncoded (Get-Date))</div>
      <div>Leitsatz: Fakten vor Angst. Baseline vor Chaos. Sichtbarkeit vor Kontrolle.</div>
    </div>
  </div>
</body>
</html>
"@

$Html | Set-Content -Path $ReportHtml -Encoding UTF8

Write-Host ''
Write-Host 'AVA COMMUNITY SECURITY CHECK v3 abgeschlossen.' -ForegroundColor Green
Write-Host "Security Score: $Score / 100 - $ScoreText" -ForegroundColor Yellow
Write-Host ''
Write-Host 'HTML Portal:' -ForegroundColor Cyan
Write-Host $ReportHtml
Write-Host ''
Write-Host 'TXT Report:' -ForegroundColor Cyan
Write-Host $ReportTxt
Write-Host ''
Write-Host 'JSON Report:' -ForegroundColor Cyan
Write-Host $ReportJson
Write-Host ''
Write-Host '🌀 CHECKAAR VOM NECKAR MODE AKTIVIERT 😂👍' -ForegroundColor Green

Start-Process $ReportHtml
