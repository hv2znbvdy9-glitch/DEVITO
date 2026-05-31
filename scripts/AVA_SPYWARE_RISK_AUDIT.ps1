#requires -Version 5.1
<#
AVA SPYWARE RISK AUDIT
Lokal / Defensiv / Read-Only

Keine Angriffe
Keine Änderungen
Keine Fremdscans
Keine Bereinigung
Nur Sichtbarkeit + Report
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$auditTimestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$root = Join-Path $env:USERPROFILE "Desktop\AVA_SPYWARE_RISK_AUDIT_$auditTimestamp"
$logDir = Join-Path $root 'Logs'
$reportDir = Join-Path $root 'Reports'
$stateDir = Join-Path $root 'State'

$htmlReport = Join-Path $reportDir 'ava_spyware_risk_audit.html'
$jsonReport = Join-Path $reportDir 'ava_spyware_risk_audit.json'
$txtReport = Join-Path $reportDir 'ava_spyware_risk_audit.txt'
$tangleLog = Join-Path $logDir 'ava_tangle.jsonl'
$tangleState = Join-Path $stateDir 'tangle_state.json'

foreach ($dir in @($root, $logDir, $reportDir, $stateDir)) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}

$findings = New-Object System.Collections.Generic.List[object]

function ConvertTo-HtmlSafe {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Get-Sha256Text {
    param([Parameter(Mandatory)][string]$Text)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally {
        $sha.Dispose()
    }
}

function Add-Finding {
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Severity,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][string]$Recommendation
    )

    $findings.Add([pscustomobject]@{
            Time           = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
            Category       = $Category
            Severity       = $Severity
            Title          = $Title
            Message        = $Message
            Recommendation = $Recommendation
        }) | Out-Null
}

function Write-Tangle {
    param(
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][string]$Summary,
        [Parameter(Mandatory)][object]$Data
    )

    $previousHash = $null
    if (Test-Path -LiteralPath $tangleState) {
        try {
            $previousHash = (Get-Content -Path $tangleState -Raw | ConvertFrom-Json).last_hash
        }
        catch {
            $previousHash = $null
        }
    }

    $tangleEvent = [ordered]@{
        time          = (Get-Date).ToString('o')
        computer      = $env:COMPUTERNAME
        user          = $env:USERNAME
        type          = $Type
        summary       = $Summary
        previous_hash = $previousHash
        data          = $Data
    }

    $raw = $tangleEvent | ConvertTo-Json -Depth 20 -Compress
    $hash = Get-Sha256Text -Text $raw
    $tangleEvent.hash = $hash

    $tangleEvent | ConvertTo-Json -Depth 20 -Compress | Add-Content -Path $tangleLog -Encoding UTF8

    [pscustomobject]@{
        updated   = (Get-Date).ToString('o')
        last_hash = $hash
    } | ConvertTo-Json | Set-Content -Path $tangleState -Encoding UTF8
}

Write-Host ''
Write-Host 'AVA SPYWARE RISK AUDIT startet...' -ForegroundColor Cyan
Write-Host 'Read-Only / Lokal / Keine Änderungen' -ForegroundColor Green
Write-Host ''

# SYSTEM
try {
    $os = Get-CimInstance Win32_OperatingSystem
    Add-Finding -Category 'System' -Severity 'INFO' -Title 'Betriebssystem' -Message "$($os.Caption) | Build $($os.BuildNumber)" -Recommendation 'Windows aktuell halten.'
}
catch {
    Add-Finding -Category 'System' -Severity 'WARN' -Title 'Betriebssystem' -Message $_.Exception.Message -Recommendation 'Systeminformationen prüfen.'
}

# DEFENDER
try {
    $mp = Get-MpComputerStatus
    if ($mp.RealTimeProtectionEnabled) {
        Add-Finding -Category 'Defender' -Severity 'OK' -Title 'Echtzeitschutz' -Message 'Aktiv' -Recommendation 'Sehr gut.'
    }
    else {
        Add-Finding -Category 'Defender' -Severity 'CRITICAL' -Title 'Echtzeitschutz' -Message 'Nicht aktiv' -Recommendation 'Windows-Sicherheit sofort prüfen.'
    }

    Add-Finding -Category 'Defender' -Severity 'INFO' -Title 'Signaturen' -Message "Letztes Update: $($mp.AntivirusSignatureLastUpdated)" -Recommendation 'Signaturen aktuell halten.'
}
catch {
    Add-Finding -Category 'Defender' -Severity 'WARN' -Title 'Defender Status' -Message $_.Exception.Message -Recommendation 'Manuell in Windows-Sicherheit prüfen.'
}

# FIREWALL
try {
    Get-NetFirewallProfile | ForEach-Object {
        if ($_.Enabled) {
            Add-Finding -Category 'Firewall' -Severity 'OK' -Title "Firewall $($_.Name)" -Message 'Aktiv' -Recommendation 'Sehr gut.'
        }
        else {
            Add-Finding -Category 'Firewall' -Severity 'CRITICAL' -Title "Firewall $($_.Name)" -Message 'Deaktiviert' -Recommendation 'Firewall aktivieren.'
        }
    }
}
catch {
    Add-Finding -Category 'Firewall' -Severity 'WARN' -Title 'Firewall' -Message $_.Exception.Message -Recommendation 'Firewall prüfen.'
}

# ADMINS
try {
    $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544')
    foreach ($admin in $admins) {
        Add-Finding -Category 'Konten' -Severity 'INFO' -Title 'Lokaler Administrator' -Message $admin.Name -Recommendation 'Nur notwendige Adminrechte behalten.'
    }

    if ($admins.Count -gt 3) {
        Add-Finding -Category 'Konten' -Severity 'WARN' -Title 'Viele Administratoren' -Message "$($admins.Count) Admin-Konten gefunden" -Recommendation 'Adminrechte minimieren.'
    }
}
catch {
    Add-Finding -Category 'Konten' -Severity 'WARN' -Title 'Administratoren' -Message $_.Exception.Message -Recommendation 'Mit Adminrechten erneut prüfen.'
}

# PROCESSES
$suspiciousProcessPatterns = @(
    'powershell -enc',
    'encodedcommand',
    'downloadstring',
    'invoke-expression',
    'iex',
    'mshta',
    'rundll32',
    'regsvr32',
    'certutil',
    'bitsadmin',
    'anydesk',
    'teamviewer',
    'rustdesk',
    'remotedesktop',
    'vnc'
)

try {
    $processes = Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath, CommandLine

    foreach ($process in $processes) {
        $normalizedCommandLine = "$($process.Name) $($process.CommandLine)".ToLowerInvariant()
        $hits = @($suspiciousProcessPatterns | Where-Object { $normalizedCommandLine.Contains($_) })

        if ($hits.Count -gt 0) {
            Add-Finding -Category 'Prozesse' -Severity 'WARN' -Title 'Auffälliger Prozess-Hinweis' -Message "PID $($process.ProcessId) | $($process.Name) | Treffer: $($hits -join ', ')" -Recommendation 'Nicht automatisch löschen. Erst prüfen, ob legitim.'
        }
    }
}
catch {
    Add-Finding -Category 'Prozesse' -Severity 'WARN' -Title 'Prozessanalyse' -Message $_.Exception.Message -Recommendation 'Prozesse manuell prüfen.'
}

# NETWORK CONNECTIONS
$riskPorts = @(21, 23, 135, 139, 445, 3389, 5985, 5986)

try {
    $procMap = @{}
    Get-Process | ForEach-Object { $procMap[$_.Id] = $_.ProcessName }

    $connections = @(Get-NetTCPConnection -State Established)

    Add-Finding -Category 'Netzwerk' -Severity 'INFO' -Title 'Aktive TCP-Verbindungen' -Message "$($connections.Count) Verbindungen" -Recommendation 'Unbekannte Remote-Ziele prüfen.'

    foreach ($connection in $connections) {
        if ($riskPorts -contains $connection.RemotePort) {
            $procName = if ($procMap.ContainsKey($connection.OwningProcess)) { $procMap[$connection.OwningProcess] } else { 'Unknown' }
            Add-Finding -Category 'Netzwerk' -Severity 'WARN' -Title 'Risiko-Port Verbindung' -Message "$($connection.RemoteAddress):$($connection.RemotePort) durch $procName / PID $($connection.OwningProcess)" -Recommendation 'Prüfen, ob diese Verbindung erwartet ist.'
        }
    }
}
catch {
    Add-Finding -Category 'Netzwerk' -Severity 'WARN' -Title 'TCP-Verbindungen' -Message $_.Exception.Message -Recommendation 'Netzwerk manuell prüfen.'
}

# WLAN / LAN NEIGHBORS
try {
    $neighbors = @(Get-NetNeighbor -AddressFamily IPv4 | Where-Object { $_.State -ne 'Unreachable' })
    Add-Finding -Category 'Netzwerk' -Severity 'INFO' -Title 'LAN-Nachbarn / ARP' -Message "$($neighbors.Count) lokale Nachbarn gefunden" -Recommendation 'Unbekannte MAC/IP-Adressen im Router gegenprüfen.'
}
catch {
    Add-Finding -Category 'Netzwerk' -Severity 'WARN' -Title 'LAN-Nachbarn / ARP' -Message $_.Exception.Message -Recommendation 'Nachbarn manuell prüfen.'
}

try {
    $adapters = Get-NetAdapter
    foreach ($adapter in $adapters) {
        Add-Finding -Category 'Adapter' -Severity 'INFO' -Title 'Netzwerkadapter' -Message "$($adapter.Name) | $($adapter.Status) | $($adapter.MacAddress) | $($adapter.LinkSpeed)" -Recommendation 'Unbekannte Adapter prüfen.'
    }
}
catch {
    Add-Finding -Category 'Adapter' -Severity 'WARN' -Title 'Netzwerkadapter' -Message $_.Exception.Message -Recommendation 'Adapterstatus manuell prüfen.'
}

# MOBILE / SPYWARE RELATED FILE CHECKS
$scanDirs = @(
    (Join-Path $env:USERPROFILE 'Downloads'),
    (Join-Path $env:USERPROFILE 'Desktop'),
    (Join-Path $env:USERPROFILE 'Documents')
)

$suspiciousExtensions = @('*.apk', '*.ipa', '*.mobileconfig', '*.cer', '*.p12', '*.pfx')
$suspiciousNames = @('spy', 'tracker', 'monitor', 'mdm', 'pegasus', 'stalker', 'stealth', 'keylog', 'remote', 'rat')
$maxFileFindings = 50

foreach ($scanDir in $scanDirs) {
    if (-not (Test-Path -LiteralPath $scanDir)) { continue }

    foreach ($extension in $suspiciousExtensions) {
        try {
            Get-ChildItem -Path $scanDir -Filter $extension -File -Recurse -ErrorAction SilentlyContinue |
                Select-Object -First $maxFileFindings |
                ForEach-Object {
                    Add-Finding -Category 'Dateien' -Severity 'WARN' -Title 'Mobile/Profil-Datei gefunden' -Message $_.FullName -Recommendation 'Nur installieren/importieren, wenn Herkunft absolut vertrauenswürdig ist.'
                }
        }
        catch {
            Add-Finding -Category 'Dateien' -Severity 'WARN' -Title 'Dateiscanner (Erweiterungen)' -Message $_.Exception.Message -Recommendation "Scan in '$scanDir' manuell prüfen."
        }
    }

    try {
        Get-ChildItem -Path $scanDir -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object {
                $normalizedFileName = $_.Name.ToLowerInvariant()
                foreach ($searchTerm in $suspiciousNames) {
                    if ($normalizedFileName.Contains($searchTerm)) { return $true }
                }
                return $false
            } |
            Select-Object -First $maxFileFindings |
            ForEach-Object {
                Add-Finding -Category 'Dateien' -Severity 'INFO' -Title 'Dateiname mit Sicherheitsbezug' -Message $_.FullName -Recommendation 'Kontext prüfen. Treffer ist nicht automatisch gefährlich.'
            }
    }
    catch {
        Add-Finding -Category 'Dateien' -Severity 'WARN' -Title 'Dateiscanner (Namen)' -Message $_.Exception.Message -Recommendation "Scan in '$scanDir' manuell prüfen."
    }
}

# IPHONE BACKUP PATHS
$iPhoneBackupPaths = @(
    (Join-Path $env:APPDATA 'Apple Computer\MobileSync\Backup'),
    (Join-Path $env:USERPROFILE 'Apple\MobileSync\Backup')
)

foreach ($backupPath in $iPhoneBackupPaths) {
    if (Test-Path -LiteralPath $backupPath) {
        Add-Finding -Category 'Mobile' -Severity 'INFO' -Title 'iPhone Backup Ordner gefunden' -Message $backupPath -Recommendation 'Backups verschlüsseln und sicher aufbewahren.'
    }
}

# HOSTS FILE
try {
    $hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    if (Test-Path -LiteralPath $hostsPath) {
        $hostsContent = @(Get-Content -Path $hostsPath -ErrorAction SilentlyContinue | Where-Object { $_ -notmatch '^\s*(#|$)' })
        if ($hostsContent.Count -gt 0) {
            Add-Finding -Category 'System' -Severity 'WARN' -Title 'Hosts-Datei enthält aktive Einträge' -Message "$($hostsContent.Count) aktive Zeilen" -Recommendation 'Prüfen, ob Umleitungen legitim sind.'
        }
        else {
            Add-Finding -Category 'System' -Severity 'OK' -Title 'Hosts-Datei' -Message 'Keine aktiven Umleitungen gefunden' -Recommendation 'Gut.'
        }
    }
}
catch {
    Add-Finding -Category 'System' -Severity 'WARN' -Title 'Hosts-Datei' -Message $_.Exception.Message -Recommendation 'Hosts-Datei manuell prüfen.'
}

# SCORE
$critical = ($findings | Where-Object Severity -eq 'CRITICAL').Count
$warn = ($findings | Where-Object Severity -eq 'WARN').Count
$ok = ($findings | Where-Object Severity -eq 'OK').Count
$info = ($findings | Where-Object Severity -eq 'INFO').Count

$score = 100 - ($critical * 30) - ($warn * 7)
if ($score -lt 0) { $score = 0 }

$rating = switch ($score) {
    { $_ -ge 90 } { 'Sehr stabil'; break }
    { $_ -ge 70 } { 'Solide'; break }
    { $_ -ge 50 } { 'Verbesserbar'; break }
    default { 'Prüfung empfohlen' }
}

Write-Tangle -Type 'AVA_SPYWARE_RISK_AUDIT' -Summary 'Read-Only Audit abgeschlossen' -Data @{
    score    = $score
    critical = $critical
    warn     = $warn
    info     = $info
    ok       = $ok
}

# EXPORT JSON
[pscustomobject]@{
    Tool     = 'AVA SPYWARE RISK AUDIT'
    Mode     = 'LOCAL / DEFENSIVE / READ-ONLY'
    Time     = (Get-Date).ToString('o')
    Computer = $env:COMPUTERNAME
    User     = $env:USERNAME
    Score    = $score
    Rating   = $rating
    Counts   = @{
        OK       = $ok
        INFO     = $info
        WARN     = $warn
        CRITICAL = $critical
    }
    Findings = $findings
} | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonReport -Encoding UTF8

# EXPORT TXT
$textReportLines = @(
    'AVA SPYWARE RISK AUDIT',
    "Zeit: $(Get-Date)",
    "Computer: $env:COMPUTERNAME",
    "User: $env:USERNAME",
    '',
    "Score: $score / 100",
    "Bewertung: $rating",
    '',
    'Kernsatz: Fakten vor Angst. Baseline vor Chaos. Sichtbarkeit vor Kontrolle.',
    ''
)

foreach ($finding in $findings) {
    $textReportLines += "[$($finding.Severity)] $($finding.Category) - $($finding.Title)"
    $textReportLines += $finding.Message
    $textReportLines += "Empfehlung: $($finding.Recommendation)"
    $textReportLines += ''
}

$textReportLines -join "`r`n" | Set-Content -Path $txtReport -Encoding UTF8

# HTML
$rows = foreach ($finding in $findings) {
    $color = switch ($finding.Severity) {
        'OK' { '#15803d' }
        'INFO' { '#2563eb' }
        'WARN' { '#d97706' }
        'CRITICAL' { '#dc2626' }
        default { '#6b7280' }
    }

    @"
<tr>
  <td>$(ConvertTo-HtmlSafe $finding.Time)</td>
  <td><span class="badge" style="background:$color;">$(ConvertTo-HtmlSafe $finding.Severity)</span></td>
  <td>$(ConvertTo-HtmlSafe $finding.Category)</td>
  <td>$(ConvertTo-HtmlSafe $finding.Title)</td>
  <td>$(ConvertTo-HtmlSafe $finding.Message)</td>
  <td>$(ConvertTo-HtmlSafe $finding.Recommendation)</td>
</tr>
"@
}

$html = @"
<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>AVA Spyware Risk Audit</title>
  <style>
    body { font-family: Segoe UI, Arial, sans-serif; background: #0b1220; color: #e5e7eb; margin: 0; padding: 24px; }
    h1 { margin: 0 0 6px; color: #38bdf8; }
    .sub { color: #9ca3af; margin-bottom: 20px; }
    .cards { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 20px; }
    .card { background: #111827; border: 1px solid #1f2937; border-radius: 10px; padding: 12px 16px; min-width: 150px; }
    .card .value { font-size: 1.4rem; font-weight: 700; }
    .muted { color: #94a3b8; }
    table { width: 100%; border-collapse: collapse; background: #0f172a; border: 1px solid #1f2937; }
    th, td { padding: 10px; text-align: left; border-bottom: 1px solid #1f2937; vertical-align: top; }
    th { background: #111827; color: #93c5fd; }
    tr:hover { background: #111827; }
    .badge { display: inline-block; color: white; padding: 2px 8px; border-radius: 999px; font-size: .8rem; }
    .footer { margin-top: 16px; color: #9ca3af; font-size: .9rem; }
  </style>
</head>
<body>
  <h1>AVA SPYWARE RISK AUDIT</h1>
  <div class="sub">Read-Only / Lokal / Keine Änderungen</div>

  <div class="cards">
    <div class="card"><div class="muted">Score</div><div class="value">$score / 100</div><div>$rating</div></div>
    <div class="card"><div class="muted">CRITICAL</div><div class="value">$critical</div></div>
    <div class="card"><div class="muted">WARN</div><div class="value">$warn</div></div>
    <div class="card"><div class="muted">INFO</div><div class="value">$info</div></div>
    <div class="card"><div class="muted">OK</div><div class="value">$ok</div></div>
  </div>

  <table>
    <thead>
      <tr>
        <th>Zeit</th>
        <th>Severity</th>
        <th>Kategorie</th>
        <th>Titel</th>
        <th>Nachricht</th>
        <th>Empfehlung</th>
      </tr>
    </thead>
    <tbody>
      $($rows -join "`r`n")
    </tbody>
  </table>

  <div class="footer">Kernsatz: Fakten vor Angst. Baseline vor Chaos. Sichtbarkeit vor Kontrolle.</div>
</body>
</html>
"@

$html | Set-Content -Path $htmlReport -Encoding UTF8

Write-Host ''
Write-Host 'AVA SPYWARE RISK AUDIT abgeschlossen.' -ForegroundColor Green
Write-Host "Score: $score / 100 - $rating" -ForegroundColor Yellow
Write-Host "HTML: $htmlReport" -ForegroundColor Cyan
Write-Host "JSON: $jsonReport" -ForegroundColor Cyan
Write-Host "TXT:  $txtReport" -ForegroundColor Cyan
Write-Host ''

Start-Process -FilePath $htmlReport
