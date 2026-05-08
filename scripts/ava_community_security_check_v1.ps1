#requires -Version 5.1
<#
AVA COMMUNITY SECURITY CHECK v1
Ehrenamtlich / Respektvoll / Gesellschaftlich wertvoll
Lokal / Read-Only / Keine Angriffe / Keine Änderungen

Ziel:
- Kleine Vereine, Familien, Ehrenamt, Kleinbetriebe unterstützen
- Sicherheitsbasis sichtbar machen
- Verständlicher HTML-Report
- Keine Daten an Dritte
- Keine fremden Systeme scannen
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$Now = Get-Date -Format 'yyyyMMdd_HHmmss'
$OutDir = Join-Path ([Environment]::GetFolderPath('Desktop')) "AVA_COMMUNITY_SECURITY_CHECK_$Now"
$ReportHtml = Join-Path $OutDir 'ava_community_security_report.html'
$ReportTxt  = Join-Path $OutDir 'ava_community_security_report.txt'
$ReportJson = Join-Path $OutDir 'ava_community_security_report.json'

$MaxAdminsThreshold = 3
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
$RiskyRemotePorts = @(
    21,   # FTP
    23,   # Telnet
    135,  # RPC
    139,  # NetBIOS
    445,  # SMB
    3389, # RDP
    5985, # WinRM HTTP
    5986  # WinRM HTTPS
)
$CriticalPenalty = 25
$WarnPenalty = 7
$MaxHotfixesToDisplay = 5

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
        Time           = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Category       = $Category
        Status         = $Status
        Title          = $Title
        Message        = $Message
        Recommendation = $Recommendation
    }) | Out-Null
}

function HtmlEncode {
    param([object]$Text)
    if ($null -eq $Text) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Text)
}

# =========================
# SYSTEMBASIS
# =========================
$os = $null
try {
    $os = Get-CimInstance Win32_OperatingSystem
    Add-Result 'System' 'INFO' 'Betriebssystem' `
        "$($os.Caption) | Version: $($os.Version) | Build: $($os.BuildNumber)" `
        'System regelmäßig aktualisieren und alte Geräte dokumentieren.'
}
catch {
    Add-Result 'System' 'WARN' 'Betriebssystem konnte nicht gelesen werden' "$($_.Exception.Message)" 'PowerShell als normaler Benutzer reicht meist, Admin erhöht die Details.'
}

try {
    if ($null -ne $os) {
        $uptime = (Get-Date) - $os.LastBootUpTime
        Add-Result 'System' 'INFO' 'Laufzeit seit Neustart' `
            ('{0} Tage, {1} Stunden' -f [int]$uptime.TotalDays, $uptime.Hours) `
            'Sehr lange Laufzeiten können Updates blockieren. Gelegentlich sauber neu starten.'
    }
}
catch {
    Write-Debug "Uptime not available: $($_.Exception.Message)"
}

# =========================
# DEFENDER / ANTIVIRUS
# =========================
try {
    $mp = Get-MpComputerStatus

    if ($mp.RealTimeProtectionEnabled) {
        Add-Result 'Schutz' 'OK' 'Microsoft Defender Echtzeitschutz' 'Aktiv' 'Sehr gut. Echtzeitschutz aktiviert lassen.'
    }
    else {
        Add-Result 'Schutz' 'CRITICAL' 'Microsoft Defender Echtzeitschutz' 'Nicht aktiv' 'Echtzeitschutz prüfen und aktivieren.'
    }

    if ($mp.AntivirusSignatureLastUpdated) {
        Add-Result 'Schutz' 'INFO' 'Defender Signaturen' `
            "Letztes Update: $($mp.AntivirusSignatureLastUpdated)" `
            'Signaturen sollten regelmäßig aktualisiert werden.'
    }
}
catch {
    Add-Result 'Schutz' 'WARN' 'Defender Status nicht verfügbar' `
        "$($_.Exception.Message)" `
        'Falls ein anderes Antivirus aktiv ist, dort Schutzstatus prüfen.'
}

# =========================
# FIREWALL
# =========================
try {
    $profiles = Get-NetFirewallProfile
    foreach ($p in $profiles) {
        if ($p.Enabled) {
            Add-Result 'Firewall' 'OK' "Firewall Profil: $($p.Name)" 'Aktiv' 'Firewall aktiv lassen.'
        }
        else {
            Add-Result 'Firewall' 'CRITICAL' "Firewall Profil: $($p.Name)" 'Nicht aktiv' 'Firewall-Profil prüfen und aktivieren.'
        }
    }
}
catch {
    Add-Result 'Firewall' 'WARN' 'Firewall Status nicht lesbar' "$($_.Exception.Message)" 'Mit Adminrechten erneut prüfen.'
}

# =========================
# REMOTE ZUGRIFFE
# =========================
try {
    $rdp = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction Stop
    if ($rdp.fDenyTSConnections -eq 1) {
        Add-Result 'Remote Zugriff' 'OK' 'Remote Desktop' 'RDP ist deaktiviert' 'Gut für normale Vereins-/Büro-PCs.'
    }
    else {
        Add-Result 'Remote Zugriff' 'WARN' 'Remote Desktop' 'RDP ist aktiviert' 'Nur aktiv lassen, wenn wirklich benötigt. Starke Passwörter und VPN verwenden.'
    }
}
catch {
    Add-Result 'Remote Zugriff' 'INFO' 'Remote Desktop' 'Status konnte nicht gelesen werden' 'Bei Bedarf manuell prüfen.'
}

try {
    $winrm = Get-Service WinRM -ErrorAction Stop
    if ($winrm.Status -eq 'Running') {
        Add-Result 'Remote Zugriff' 'WARN' 'WinRM Dienst' 'WinRM läuft' 'Nur für verwaltete Systeme aktiv lassen.'
    }
    else {
        Add-Result 'Remote Zugriff' 'OK' 'WinRM Dienst' 'WinRM läuft nicht' 'Für normale Clients meist sinnvoll.'
    }
}
catch {
    Write-Debug "WinRM service not available: $($_.Exception.Message)"
}

# =========================
# LOKALE ADMINISTRATOREN
# =========================
    foreach ($a in $admins) {
        Add-Result 'Konten' 'INFO' 'Lokaler Administrator' `
            "$($a.Name) | $($a.ObjectClass)" `
            'Adminrechte regelmäßig prüfen. Nur notwendige Personen sollten Admin sein.'
    }

    if ($admins.Count -gt $MaxAdminsThreshold) {
        Add-Result 'Konten' 'WARN' 'Viele lokale Administratoren' `
            "$($admins.Count) Administrator-Einträge gefunden" `
            'Für Vereine/Kleinbetriebe: Adminrechte sparsam vergeben.'
    }
}
catch {
    Add-Result 'Konten' 'WARN' 'Administratoren konnten nicht gelesen werden' "$($_.Exception.Message)" 'Mit Adminrechten erneut ausführen.'
}

# =========================
# AUTOSTART
# =========================
try {
    $startupPaths = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
    )

    foreach ($path in $startupPaths) {
        if (Test-Path $path) {
            $items = Get-ItemProperty $path
            $props = $items.PSObject.Properties | Where-Object {
                $_.Name -notin @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')
            }

            foreach ($prop in $props) {
                Add-Result 'Autostart' 'INFO' 'Autostart Eintrag' `
                    "$($prop.Name): $($prop.Value)" `
                    'Unbekannte Autostarts prüfen, aber nichts vorschnell löschen.'
            }
        }
    }
}
catch {
    Add-Result 'Autostart' 'WARN' 'Autostart konnte nicht geprüft werden' "$($_.Exception.Message)" 'Manuell im Task-Manager prüfen.'
}

# =========================
# AUFFÄLLIGE POWERSHELL PROZESSE
# =========================
try {
    $procs = Get-CimInstance Win32_Process -Filter "Name='powershell.exe' OR Name='pwsh.exe'"
    $hasSuspiciousPowerShellProcess = $false

    foreach ($p in $procs) {
        if ($null -eq $p.CommandLine) { continue }

        $cmd = "$($p.CommandLine)"
        $lower = $cmd.ToLowerInvariant()
        $hits = @()

        foreach ($pattern in $SuspiciousPowerShellPatterns) {
            if ($lower -match $pattern) { $hits += $pattern }
        }

        if ($hits.Count -gt 0) {
            $hasSuspiciousPowerShellProcess = $true
            Add-Result 'Prozesse' 'WARN' 'Auffälliger PowerShell Prozess' `
                "PID $($p.ProcessId) | Treffer: $($hits -join ', ') | $cmd" `
                'Prüfen, ob dieser Prozess zu einem legitimen Admin-/Updatevorgang gehört.'
        }
    }

    $procCount = @($procs | Where-Object { $_.ProcessId -ne $PID }).Count
    if ($procCount -eq 0) {
        Add-Result 'Prozesse' 'OK' 'PowerShell Prozesse' 'Keine zusätzlichen laufenden PowerShell-Prozesse erkannt' 'Gut.'
    }
    elseif (-not $hasSuspiciousPowerShellProcess) {
        Add-Result 'Prozesse' 'OK' 'PowerShell Prozesse' 'Keine auffälligen PowerShell-Argumente erkannt' 'Gut.'
    }
}
catch {
    Add-Result 'Prozesse' 'WARN' 'Prozessprüfung fehlgeschlagen' "$($_.Exception.Message)" 'Später erneut prüfen.'
}

# =========================
# NETZWERK - NUR LOKAL, KEIN SCAN
# =========================
try {
    $connections = Get-NetTCPConnection -State Established -ErrorAction Stop

    foreach ($c in $connections) {
        if ($RiskyRemotePorts -contains $c.RemotePort) {
            Add-Result 'Netzwerk' 'WARN' 'Verbindung zu sensiblem Port' `
                "Local: $($c.LocalAddress):$($c.LocalPort) -> Remote: $($c.RemoteAddress):$($c.RemotePort)" `
                'Nur prüfen. Nicht jede Verbindung ist gefährlich, aber sensible Ports verdienen Aufmerksamkeit.'
        }
    }

    Add-Result 'Netzwerk' 'INFO' 'Aktive TCP-Verbindungen' `
        "$($connections.Count) etablierte Verbindungen gefunden" `
        'Nur lokale Sicht. Kein Fremdscan wurde durchgeführt.'
}
catch {
    Add-Result 'Netzwerk' 'WARN' 'Netzwerkverbindungen konnten nicht gelesen werden' "$($_.Exception.Message)" 'Mit Adminrechten erneut prüfen.'
}

# =========================
# WINDOWS UPDATE HINWEIS
# =========================
try {
    $hotfixes = Get-HotFix |
        Where-Object { $null -ne $_.InstalledOn } |
        Sort-Object InstalledOn -Descending |
        Select-Object -First $MaxHotfixesToDisplay
    foreach ($h in $hotfixes) {
        Add-Result 'Updates' 'INFO' 'Installiertes Update' `
            "$($h.HotFixID) | Installiert am: $($h.InstalledOn)" `
            'Updates regelmäßig prüfen.'
    }
}
catch {
    Add-Result 'Updates' 'INFO' 'Updates' 'Hotfix-Liste konnte nicht gelesen werden' 'Windows Update manuell prüfen.'
}

# =========================
# RISIKO-SCORE
# =========================
$critical = ($Results | Where-Object Status -eq 'CRITICAL').Count
$warn = ($Results | Where-Object Status -eq 'WARN').Count
$ok = ($Results | Where-Object Status -eq 'OK').Count
$info = ($Results | Where-Object Status -eq 'INFO').Count

$Score = 100 - ($critical * $CriticalPenalty) - ($warn * $WarnPenalty)
if ($Score -lt 0) { $Score = 0 }

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

# =========================
# EXPORT JSON / TXT
# =========================
$Results | ConvertTo-Json -Depth 5 | Out-File -FilePath $ReportJson -Encoding UTF8

$txt = @()
$txt += 'AVA COMMUNITY SECURITY CHECK v1'
$txt += "Zeit: $(Get-Date)"
$txt += "Computer: $env:COMPUTERNAME"
$txt += "Benutzer: $env:USERNAME"
$txt += "Score: $Score / 100 - $ScoreText"
$txt += ''
$txt += 'Leitsatz:'
$txt += 'Fakten vor Angst. Baseline vor Chaos. Sichtbarkeit vor Kontrolle.'
$txt += ''
foreach ($r in $Results) {
    $txt += "[$($r.Status)] $($r.Category) - $($r.Title)"
    $txt += "  $($r.Message)"
    $txt += "  Empfehlung: $($r.Recommendation)"
    $txt += ''
}
$txt -join "`r`n" | Out-File -FilePath $ReportTxt -Encoding UTF8

# =========================
# HTML REPORT
# =========================
$rows = foreach ($r in $Results) {
    $color = switch ($r.Status) {
        'OK' { '#1f8f4d' }
        'INFO' { '#2f6fed' }
        'WARN' { '#d68a00' }
        'CRITICAL' { '#c62828' }
        default { '#777777' }
    }

@"
<tr>
  <td>$(HtmlEncode $r.Time)</td>
  <td><span class="badge" style="background:$color;">$(HtmlEncode $r.Status)</span></td>
  <td>$(HtmlEncode $r.Category)</td>
  <td>$(HtmlEncode $r.Title)</td>
  <td>$(HtmlEncode $r.Message)</td>
  <td>$(HtmlEncode $r.Recommendation)</td>
</tr>
"@
}

$html = @"
<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AVA COMMUNITY SECURITY CHECK v1</title>
  <style>
    body { font-family: 'Segoe UI', Tahoma, Arial, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 24px; }
    .wrap { max-width: 1200px; margin: 0 auto; }
    h1 { margin: 0 0 8px; color: #22d3ee; }
    .sub { color: #94a3b8; margin-bottom: 18px; }
    .summary { display: flex; flex-wrap: wrap; gap: 10px; margin-bottom: 18px; }
    .card { background: #1e293b; border-radius: 8px; padding: 10px 14px; min-width: 120px; border-left: 4px solid #475569; }
    .value { font-size: 1.4rem; font-weight: 600; }
    .label { color: #94a3b8; font-size: .8rem; }
    table { width: 100%; border-collapse: collapse; font-size: .9rem; background: #111827; border-radius: 10px; overflow: hidden; }
    th, td { padding: 10px 12px; border-bottom: 1px solid #1f2937; vertical-align: top; text-align: left; }
    th { background: #1f2937; color: #cbd5e1; font-weight: 600; }
    tr:hover td { background: #0b1220; }
    .badge { color: white; padding: 3px 8px; border-radius: 999px; font-size: .75rem; font-weight: 600; display: inline-block; }
    .motto { margin-top: 20px; color: #93c5fd; }
    .footer { margin-top: 18px; color: #64748b; font-size: .8rem; }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>AVA COMMUNITY SECURITY CHECK v1</h1>
    <div class="sub">Ehrenamtlich / Respektvoll / Gesellschaftlich wertvoll &middot; Lokal / Read-Only / Keine Angriffe / Keine Änderungen</div>

    <div class="summary">
      <div class="card"><div class="value">$Score</div><div class="label">Score / 100</div></div>
      <div class="card"><div class="value">$(HtmlEncode $ScoreText)</div><div class="label">Einordnung</div></div>
      <div class="card"><div class="value">$critical</div><div class="label">Critical</div></div>
      <div class="card"><div class="value">$warn</div><div class="label">Warn</div></div>
      <div class="card"><div class="value">$ok</div><div class="label">OK</div></div>
      <div class="card"><div class="value">$info</div><div class="label">Info</div></div>
    </div>

    <table>
      <thead>
        <tr>
          <th>Zeit</th>
          <th>Status</th>
          <th>Kategorie</th>
          <th>Titel</th>
          <th>Nachricht</th>
          <th>Empfehlung</th>
        </tr>
      </thead>
      <tbody>
$($rows -join "`n")
      </tbody>
    </table>

    <div class="motto">Leitsatz: Fakten vor Angst. Baseline vor Chaos. Sichtbarkeit vor Kontrolle.</div>
    <div class="footer">Computer: $(HtmlEncode $env:COMPUTERNAME) &middot; Benutzer: $(HtmlEncode $env:USERNAME) &middot; Export: $(HtmlEncode (Get-Date))</div>
  </div>
</body>
</html>
"@

$html | Out-File -FilePath $ReportHtml -Encoding UTF8

Write-Host ''
Write-Host 'AVA COMMUNITY SECURITY CHECK abgeschlossen.' -ForegroundColor Green
Write-Host "Score: $Score / 100 - $ScoreText" -ForegroundColor Yellow
Write-Host ''
Write-Host 'HTML Report:' -ForegroundColor Cyan
Write-Host $ReportHtml
Write-Host ''
Write-Host 'TXT Report:' -ForegroundColor Cyan
Write-Host $ReportTxt
Write-Host ''
Write-Host 'JSON Report:' -ForegroundColor Cyan
Write-Host $ReportJson
Write-Host ''
Write-Host 'Leitsatz: Fakten vor Angst. Baseline vor Chaos. Sichtbarkeit vor Kontrolle.' -ForegroundColor Green

Start-Process $ReportHtml
