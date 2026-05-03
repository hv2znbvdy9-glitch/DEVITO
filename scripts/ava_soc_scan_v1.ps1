#requires -RunAsAdministrator
<#
AVA DEFENSE LAB + SOC SCAN INTEGRATION v1
Lokal / Defensiv / Read-Only
Erkennt auffällige Netzwerk-Muster, PowerShell-Prozesse, offene Ports
und erstellt JSON + TXT + HTML Report.

Keine Angriffe. Keine fremden Scans. Keine Änderungen am System.

Output paths:
  C:\Windows\SecurityGuardian\Reports\ava_soc_scan_report_<timestamp>.json
  C:\Windows\SecurityGuardian\Reports\ava_soc_scan_report_<timestamp>.txt
  C:\Windows\SecurityGuardian\Reports\ava_soc_scan_report_<timestamp>.html
  C:\Windows\SecurityGuardian\Logs\scan_alerts.jsonl

Usage:
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\ava_soc_scan_v1.ps1

Tested on Windows 10/11, PowerShell 5.1+
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# =========================
# CONFIG
# =========================
$Now = Get-Date -Format 'yyyyMMdd_HHmmss'

$Root      = 'C:\Windows\SecurityGuardian'
$LogDir    = Join-Path $Root 'Logs'
$ReportDir = Join-Path $Root 'Reports'
$StateDir  = Join-Path $Root 'State'

$JsonReport = Join-Path $ReportDir "ava_soc_scan_report_$Now.json"
$TxtReport  = Join-Path $ReportDir "ava_soc_scan_report_$Now.txt"
$HtmlReport = Join-Path $ReportDir "ava_soc_scan_report_$Now.html"
$AlertLog   = Join-Path $LogDir 'scan_alerts.jsonl'

$HighRiskPorts = @(21, 23, 135, 139, 445, 3389, 4444, 5555, 5900, 5985, 5986, 8080, 8443, 9001, 1337)

$SuspiciousPSFlags = @(
    '-enc',
    'encodedcommand',
    '-nop',
    '-w hidden',
    'windowstyle hidden',
    '-executionpolicy bypass',
    '-ep bypass',
    'iex ',
    'invoke-expression'
)

# =========================
# INIT
# =========================
foreach ($d in @($Root, $LogDir, $ReportDir, $StateDir)) {
    if (-not (Test-Path -LiteralPath $d)) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
    }
}

$Findings = New-Object System.Collections.Generic.List[object]
$Alerts   = New-Object System.Collections.Generic.List[object]

function Add-Finding {
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Severity,
        [Parameter(Mandatory)][int]$Score,
        [Parameter(Mandatory)][AllowNull()][object]$Details
    )

    $item = [PSCustomObject]@{
        Time     = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        Title    = $Title
        Severity = $Severity
        Score    = $Score
        Details  = $Details
    }

    $Findings.Add($item) | Out-Null

    if ($Severity -in @('MEDIUM', 'HIGH', 'CRITICAL')) {
        $Alerts.Add($item) | Out-Null
        $item | ConvertTo-Json -Depth 8 -Compress | Out-File -FilePath $AlertLog -Append -Encoding UTF8
    }
}

function HtmlEncode {
    param([object]$Value)
    return [System.Net.WebUtility]::HtmlEncode(($Value | Out-String).Trim())
}

# =========================
# SYSTEM INFO
# =========================
$SystemInfo = [PSCustomObject]@{
    ComputerName = $env:COMPUTERNAME
    User         = $env:USERNAME
    Time         = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    Mode         = 'Read-Only / Defensive'
    Root         = $Root
}

Add-Finding -Title 'AVA SOC gestartet' -Severity 'INFO' -Score 0 -Details $SystemInfo

# =========================
# FIREWALL PROFILE
# =========================
try {
    $FwProfiles = Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
    Add-Finding -Title 'Firewall Profile Status' -Severity 'INFO' -Score 0 -Details $FwProfiles
}
catch {
    Add-Finding -Title 'Firewall Profil konnte nicht gelesen werden' -Severity 'MEDIUM' -Score 30 -Details $_.Exception.Message
}

# =========================
# TCP CONNECTIONS
# =========================
try {
    $Connections = Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess

    $Established = $Connections | Where-Object { $_.State -eq 'Established' }
    $Listening   = $Connections | Where-Object { $_.State -eq 'Listen' }

    Add-Finding -Title 'Aktive TCP Verbindungen' -Severity 'INFO' -Score 0 -Details $Established
    Add-Finding -Title 'Lauschende lokale Ports'  -Severity 'INFO' -Score 0 -Details $Listening

    $RiskPorts = $Listening | Where-Object { $HighRiskPorts -contains $_.LocalPort }
    if ($RiskPorts) {
        Add-Finding -Title 'Auffällige offene Ports erkannt' -Severity 'HIGH' -Score 75 -Details $RiskPorts
    }

    $GroupedRemote = $Connections |
        Where-Object { $_.RemoteAddress -and $_.RemoteAddress -notin @('0.0.0.0', '::', '127.0.0.1') } |
        Group-Object RemoteAddress |
        Sort-Object Count -Descending

    $TopRemote = $GroupedRemote | Select-Object -First 10 Name, Count
    Add-Finding -Title 'Top Remote-Adressen nach Verbindungsanzahl' -Severity 'INFO' -Score 0 -Details $TopRemote

    foreach ($g in $GroupedRemote) {
        if ($g.Count -ge 30) {
            Add-Finding -Title 'Mögliches Scan-/Flood-Muster erkannt' -Severity 'HIGH' -Score 80 -Details @{
                RemoteAddress   = $g.Name
                ConnectionCount = $g.Count
                Reason          = 'Viele Verbindungen von einer Remote-Adresse'
            }
        }
    }
}
catch {
    Add-Finding -Title 'TCP Verbindungen konnten nicht gelesen werden' -Severity 'MEDIUM' -Score 30 -Details $_.Exception.Message
}

# =========================
# PROCESS MAPPING
# =========================
try {
    $ProcMap = @{}
    Get-Process | ForEach-Object { $ProcMap[$_.Id] = $_.ProcessName }

    $ConnWithProcess = Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess,
            @{Name = 'ProcessName'; Expression = {
                if ($ProcMap.ContainsKey($_.OwningProcess)) { $ProcMap[$_.OwningProcess] } else { 'Unknown' }
            }}

    Add-Finding -Title 'Netzwerkverbindungen mit Prozess-Zuordnung' -Severity 'INFO' -Score 0 -Details $ConnWithProcess
}
catch {
    Add-Finding -Title 'Prozess-Zuordnung fehlgeschlagen' -Severity 'MEDIUM' -Score 30 -Details $_.Exception.Message
}

# =========================
# POWERSHELL PROCESS AUDIT
# =========================
try {
    $PsProcesses = Get-CimInstance Win32_Process |
        Where-Object { $_.Name -in @('powershell.exe', 'pwsh.exe') } |
        Select-Object ProcessId, Name, CommandLine, CreationDate

    Add-Finding -Title 'PowerShell Prozesse' -Severity 'INFO' -Score 0 -Details $PsProcesses

    foreach ($p in $PsProcesses) {
        $cmd = if ($p.CommandLine) { $p.CommandLine.ToLowerInvariant() } else { '' }

        $hits = @(foreach ($flag in $SuspiciousPSFlags) {
            if ($cmd.Contains($flag)) { $flag }
        })

        if ($hits.Count -gt 0) {
            Add-Finding -Title 'Auffälliger PowerShell Prozess erkannt' -Severity 'CRITICAL' -Score 95 -Details @{
                PID         = $p.ProcessId
                Name        = $p.Name
                Flags       = $hits
                CommandLine = $p.CommandLine
            }
        }
    }
}
catch {
    Add-Finding -Title 'PowerShell Audit fehlgeschlagen' -Severity 'MEDIUM' -Score 30 -Details $_.Exception.Message
}

# =========================
# LOCAL ADMIN AUDIT
# =========================
try {
    $Admins = Get-LocalGroupMember -Group 'Administrators' |
        Select-Object Name, ObjectClass, PrincipalSource, SID

    Add-Finding -Title 'Lokale Administratoren' -Severity 'INFO' -Score 0 -Details $Admins
}
catch {
    Add-Finding -Title 'Lokale Administratoren konnten nicht gelesen werden' -Severity 'MEDIUM' -Score 30 -Details $_.Exception.Message
}

# =========================
# NON MICROSOFT TASKS
# =========================
try {
    $Tasks = Get-ScheduledTask |
        Where-Object { $_.TaskPath -notlike '\Microsoft*' } |
        Select-Object TaskName, TaskPath, State

    Add-Finding -Title 'Nicht-Microsoft Scheduled Tasks' -Severity 'INFO' -Score 0 -Details $Tasks
}
catch {
    Add-Finding -Title 'Scheduled Tasks konnten nicht gelesen werden' -Severity 'MEDIUM' -Score 30 -Details $_.Exception.Message
}

# =========================
# DEFENDER STATUS
# =========================
try {
    $Defender = Get-MpComputerStatus |
        Select-Object AMServiceEnabled, AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled,
                      IoavProtectionEnabled, AntispywareEnabled, IsTamperProtected,
                      AntivirusSignatureLastUpdated

    Add-Finding -Title 'Microsoft Defender Status' -Severity 'INFO' -Score 0 -Details $Defender

    if (-not $Defender.RealTimeProtectionEnabled) {
        Add-Finding -Title 'Defender Echtzeitschutz ist aus' -Severity 'CRITICAL' -Score 100 -Details $Defender
    }
}
catch {
    Add-Finding -Title 'Defender Status konnte nicht gelesen werden' -Severity 'MEDIUM' -Score 30 -Details $_.Exception.Message
}

# =========================
# RISK SUMMARY
# =========================
$MaxScore = 0
if ($Findings.Count -gt 0) {
    $MaxScore = ($Findings | Measure-Object Score -Maximum).Maximum
}

$Critical = @($Findings | Where-Object Severity -eq 'CRITICAL').Count
$High     = @($Findings | Where-Object Severity -eq 'HIGH').Count
$Medium   = @($Findings | Where-Object Severity -eq 'MEDIUM').Count
$Info     = @($Findings | Where-Object Severity -eq 'INFO').Count

$Summary = [PSCustomObject]@{
    Time       = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    Computer   = $env:COMPUTERNAME
    User       = $env:USERNAME
    MaxRisk    = $MaxScore
    Critical   = $Critical
    High       = $High
    Medium     = $Medium
    Info       = $Info
    ReportJson = $JsonReport
    ReportTxt  = $TxtReport
    ReportHtml = $HtmlReport
}

$Output = [PSCustomObject]@{
    Summary  = $Summary
    Findings = $Findings
}

# =========================
# EXPORT JSON
# =========================
$Output | ConvertTo-Json -Depth 12 | Out-File -FilePath $JsonReport -Encoding UTF8

# =========================
# EXPORT TXT
# =========================
$Txt = New-Object System.Collections.Generic.List[string]
$Txt.Add('AVA DEFENSE LAB + SOC SCAN INTEGRATION v1')
$Txt.Add('================================================')
$Txt.Add("Zeit: $($Summary.Time)")
$Txt.Add("Computer: $($Summary.Computer)")
$Txt.Add("User: $($Summary.User)")
$Txt.Add("MaxRisk: $($Summary.MaxRisk)")
$Txt.Add("Critical: $Critical | High: $High | Medium: $Medium | Info: $Info")
$Txt.Add('')
$Txt.Add('Kernsatz: Fakten vor Angst. Baseline vor Chaos. Sichtbarkeit vor Kontrolle.')
$Txt.Add('')

foreach ($f in $Findings) {
    $Txt.Add('------------------------------------------------')
    $Txt.Add("[$($f.Severity)] $($f.Title) | Score: $($f.Score)")
    $Txt.Add("Zeit: $($f.Time)")
    $Txt.Add(($f.Details | Out-String))
    $Txt.Add('')
}

$Txt -join "`r`n" | Out-File -FilePath $TxtReport -Encoding UTF8

# =========================
# EXPORT HTML
# =========================
$Rows = foreach ($f in $Findings) {
    $sevClass = $f.Severity.ToLowerInvariant()
    "<tr class='sev-$sevClass'><td>$(HtmlEncode $f.Time)</td><td>$(HtmlEncode $f.Severity)</td><td>$(HtmlEncode $f.Score)</td><td>$(HtmlEncode $f.Title)</td><td><pre>$(HtmlEncode $f.Details)</pre></td></tr>"
}

$Html = @"
<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AVA DEFENSE LAB + SOC SCAN INTEGRATION v1</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', Tahoma, Arial, sans-serif; background: #111827; color: #e5e7eb; padding: 24px; }
    h1 { color: #00ffcc; border-bottom: 2px solid #00ffcc; padding-bottom: 10px; margin-bottom: 8px; font-size: 1.6rem; letter-spacing: 1px; }
    .subtitle { color: #9ca3af; font-size: 0.85rem; margin-bottom: 24px; }
    .stats { display: flex; gap: 16px; margin-bottom: 28px; flex-wrap: wrap; }
    .stat-card { background: #1f2937; border-radius: 8px; padding: 16px 24px; min-width: 140px; text-align: center; border-top: 3px solid #374151; }
    .stat-card.critical { border-top-color: #ef4444; }
    .stat-card.high     { border-top-color: #f97316; }
    .stat-card.medium   { border-top-color: #eab308; }
    .stat-card.total    { border-top-color: #3b82f6; }
    .stat-number { font-size: 2rem; font-weight: bold; }
    .stat-label  { font-size: 0.8rem; color: #9ca3af; margin-top: 4px; }
    table { width: 100%; border-collapse: collapse; font-size: 0.85rem; margin-top: 16px; }
    thead tr { background: #1f2937; }
    th { padding: 10px 12px; text-align: left; color: #9ca3af; font-weight: 600; border-bottom: 1px solid #374151; }
    td { padding: 8px 12px; border-bottom: 1px solid #1f2937; word-break: break-all; vertical-align: top; }
    tbody tr:hover { background: #1f2937; }
    .sev-critical td { background: #2d1515; color: #fca5a5; }
    .sev-high     td { background: #2d1f0f; color: #fdba74; }
    .sev-medium   td { background: #2d2a0a; color: #fde68a; }
    .sev-info     td { color: #e5e7eb; }
    pre { white-space: pre-wrap; font-size: 0.78rem; font-family: 'Cascadia Code', Consolas, monospace; }
    footer { margin-top: 40px; font-size: 0.75rem; color: #4b5563; border-top: 1px solid #374151; padding-top: 12px; }
  </style>
</head>
<body>

<h1>&#x1F6E1; AVA DEFENSE LAB + SOC SCAN INTEGRATION v1</h1>
<div class="subtitle">
  Zeit: $($Summary.Time) &nbsp;|&nbsp;
  Computer: $($Summary.Computer) &nbsp;|&nbsp;
  User: $($Summary.User) &nbsp;|&nbsp;
  MaxRisk: $($Summary.MaxRisk)
</div>

<div class="stats">
  <div class="stat-card critical">
    <div class="stat-number">$Critical</div>
    <div class="stat-label">Critical</div>
  </div>
  <div class="stat-card high">
    <div class="stat-number">$High</div>
    <div class="stat-label">High</div>
  </div>
  <div class="stat-card medium">
    <div class="stat-number">$Medium</div>
    <div class="stat-label">Medium</div>
  </div>
  <div class="stat-card total">
    <div class="stat-number">$Info</div>
    <div class="stat-label">Info</div>
  </div>
</div>

<table>
  <thead>
    <tr>
      <th>Zeit</th>
      <th>Severity</th>
      <th>Score</th>
      <th>Titel</th>
      <th>Details</th>
    </tr>
  </thead>
  <tbody>
$($Rows -join "`n")
  </tbody>
</table>

<footer>
  AVA DEFENSE LAB + SOC SCAN INTEGRATION v1 &mdash; Defensiv / Lokal / Read-Only &mdash;
  Kernsatz: Fakten vor Angst. Baseline vor Chaos. Sichtbarkeit vor Kontrolle.
</footer>

</body>
</html>
"@

$Html | Out-File -FilePath $HtmlReport -Encoding UTF8

# =========================
# DONE
# =========================
Write-Host ''
Write-Host 'AVA SOC SCAN INTEGRATION fertig.' -ForegroundColor Green
Write-Host "JSON: $JsonReport" -ForegroundColor Cyan
Write-Host "TXT : $TxtReport"  -ForegroundColor Cyan
Write-Host "HTML: $HtmlReport" -ForegroundColor Cyan
Write-Host ''
Write-Host 'Öffne HTML Report...' -ForegroundColor Green

Start-Process $HtmlReport
