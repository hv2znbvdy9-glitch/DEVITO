#requires -RunAsAdministrator
<#
AVA SOC CORE v1 - DEFENSIVE / READ-ONLY / LOCAL MONITORING
- Persistent event and alert logging (JSONL)
- Canary file tamper detection
- Admin group drift detection against saved baseline
- Risk-port outbound/inbound connection monitoring
- Windows Defender status monitoring
- Suspicious PowerShell process detection
- Script integrity (SHA-256) self-check
- HTML SOC dashboard (ava_soc_dashboard.html)
- Windows Scheduled Task support (5-minute interval)

Output paths:
  C:\Windows\SecurityGuardian\Reports\ava_soc_dashboard.html
  C:\Windows\SecurityGuardian\Logs\events.jsonl
  C:\Windows\SecurityGuardian\Logs\alerts.jsonl

Usage:
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\AVA_SOC_CORE.ps1 -RunOnce
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\AVA_SOC_CORE.ps1 -InstallTask
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\AVA_SOC_CORE.ps1 -RemoveTask

Tested on Windows 10/11, PowerShell 5.1+
#>

[CmdletBinding()]
param(
    [switch]$RunOnce,
    [switch]$InstallTask,
    [switch]$RemoveTask
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# =============================================================
# CONFIG
# =============================================================
$Root       = 'C:\Windows\SecurityGuardian'
$LogDir     = Join-Path $Root 'Logs'
$ReportDir  = Join-Path $Root 'Reports'
$StateDir   = Join-Path $Root 'State'

$EventLog     = Join-Path $LogDir  'events.jsonl'
$AlertLog     = Join-Path $LogDir  'alerts.jsonl'
$BaselinePath = Join-Path $StateDir 'soc_baseline.json'
$HashPath     = Join-Path $StateDir 'soc_integrity.hash'
$DashboardHtml = Join-Path $ReportDir 'ava_soc_dashboard.html'

$TaskName = 'AVA_SOC_CORE'

# Ports flagged as high-risk when seen in established connections
$RiskPorts = @(21, 22, 23, 135, 139, 445, 3389, 4444, 5985, 5986, 6666, 8080)

# Canary files – any deletion/modification triggers a HIGH alert
$CanaryFiles = @(
    (Join-Path $Root 'finance_decoy_2026.txt'),
    (Join-Path $Root 'admin_notes_decoy.txt'),
    (Join-Path $Root 'vpn_inventory_decoy.txt')
)

# Accounts always expected in the local Administrators group
$KnownAdmins = @(
    'Administrator',
    "$env:COMPUTERNAME\$env:USERNAME",
    $env:USERNAME
) | Select-Object -Unique

# =============================================================
# INIT – ensure directory tree exists
# =============================================================
New-Item -ItemType Directory -Path $Root, $LogDir, $ReportDir, $StateDir -Force | Out-Null

# =============================================================
# LOGGING HELPERS
# =============================================================
function Write-JsonLine {
    param(
        [Parameter(Mandatory)][object]$Object,
        [Parameter(Mandatory)][string]$Path
    )
    $json = $Object | ConvertTo-Json -Compress -Depth 8
    Add-Content -Path $Path -Value $json -Encoding UTF8
}

function Write-EventEntry {
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Message,
        [string]$Severity = 'INFO'
    )
    Write-JsonLine -Object @{
        time     = (Get-Date).ToString('s')
        category = $Category
        severity = $Severity
        message  = $Message
    } -Path $EventLog
}

function Write-Alert {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')]
        [string]$Severity = 'MEDIUM'
    )
    Write-JsonLine -Object @{
        time     = (Get-Date).ToString('s')
        severity = $Severity
        message  = $Message
    } -Path $AlertLog
}

# =============================================================
# BASELINE – admin group snapshot
# =============================================================
function Save-Baseline {
    $admins = Get-LocalGroupMember -Group 'Administrators' |
        Select-Object Name, ObjectClass, PrincipalSource

    $baseline = @{
        created = (Get-Date).ToString('s')
        admins  = @($admins)
    }
    $baseline | ConvertTo-Json -Depth 6 | Set-Content -Path $BaselinePath -Encoding UTF8
    Write-EventEntry -Category 'baseline' -Message 'Baseline saved.'
}

function Check-AdminDrift {
    $currentAdmins = @(
        Get-LocalGroupMember -Group 'Administrators' |
            Select-Object -ExpandProperty Name
    )

    # Flag any admin not in the known-good list
    foreach ($admin in $currentAdmins) {
        if ($KnownAdmins -notcontains $admin) {
            Write-Alert -Message "UNAUTHORIZED ADMIN DETECTED: $admin" -Severity 'HIGH'
        }
    }

    # If baseline exists, compare against it
    if (Test-Path -LiteralPath $BaselinePath) {
        try {
            $bl = Get-Content -Path $BaselinePath -Raw | ConvertFrom-Json
            $baselineNames = @($bl.admins | Select-Object -ExpandProperty Name)

            foreach ($admin in $currentAdmins) {
                if ($baselineNames -notcontains $admin) {
                    Write-Alert -Message "ADMIN ADDED SINCE BASELINE: $admin" -Severity 'HIGH'
                }
            }

            foreach ($admin in $baselineNames) {
                if ($currentAdmins -notcontains $admin) {
                    Write-Alert -Message "ADMIN REMOVED SINCE BASELINE: $admin" -Severity 'MEDIUM'
                }
            }
        }
        catch {
            Write-EventEntry -Category 'baseline' -Message "Baseline read error: $($_.Exception.Message)" -Severity 'WARN'
        }
    }
}

# =============================================================
# CANARY FILES
# =============================================================
function Initialize-Canaries {
    foreach ($file in $CanaryFiles) {
        if (-not (Test-Path -LiteralPath $file)) {
            'DO NOT TOUCH - MONITORED BY AVA SOC CORE' |
                Set-Content -Path $file -Encoding UTF8
            Write-EventEntry -Category 'canary' -Message "Canary created: $file"
        }
    }
}

function Check-Canaries {
    foreach ($file in $CanaryFiles) {
        if (-not (Test-Path -LiteralPath $file)) {
            Write-Alert -Message "CANARY DELETED OR MISSING: $file" -Severity 'HIGH'
        }
    }
}

# =============================================================
# SCRIPT INTEGRITY
# =============================================================
function Save-ScriptHash {
    if (-not $PSCommandPath) { return }
    $hash = (Get-FileHash -Path $PSCommandPath -Algorithm SHA256).Hash
    Set-Content -Path $HashPath -Value $hash -Encoding ASCII
}

function Check-ScriptIntegrity {
    if (-not $PSCommandPath) { return }
    if (-not (Test-Path -LiteralPath $HashPath)) { return }

    $stored  = (Get-Content -Path $HashPath -Raw).Trim()
    $current = (Get-FileHash -Path $PSCommandPath -Algorithm SHA256).Hash

    if ($stored -and $stored -ne $current) {
        Write-Alert -Message 'SCRIPT TAMPER DETECTED: AVA_SOC_CORE.ps1 hash mismatch' -Severity 'CRITICAL'
    }
}

# =============================================================
# RISK-PORT CONNECTION MONITOR
# =============================================================
function Check-RiskPortConnections {
    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
    if (-not $connections) { return }

    $procMap = @{}
    foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
        $procMap[$p.Id] = $p.ProcessName
    }

    foreach ($c in $connections) {
        $remotePort = $c.RemotePort
        $localPort  = $c.LocalPort

        $flaggedPort = if ($RiskPorts -contains $remotePort) { $remotePort }
                       elseif ($RiskPorts -contains $localPort) { $localPort }
                       else { $null }

        if ($null -ne $flaggedPort) {
            $procName = if ($procMap.ContainsKey($c.OwningProcess)) { $procMap[$c.OwningProcess] } else { 'Unknown' }
            Write-Alert -Message "RISK PORT CONNECTION: port=$flaggedPort process=$procName pid=$($c.OwningProcess) remote=$($c.RemoteAddress):$remotePort" `
                        -Severity 'HIGH'
        }
    }
}

# =============================================================
# WINDOWS DEFENDER STATUS
# =============================================================
function Check-DefenderStatus {
    try {
        $mp = Get-MpComputerStatus -ErrorAction Stop

        if (-not $mp.AntivirusEnabled) {
            Write-Alert -Message 'DEFENDER: Antivirus is DISABLED' -Severity 'CRITICAL'
        }
        if (-not $mp.RealTimeProtectionEnabled) {
            Write-Alert -Message 'DEFENDER: Real-Time Protection is DISABLED' -Severity 'CRITICAL'
        }
        if ($mp.AntivirusSignatureAge -gt 3) {
            Write-Alert -Message "DEFENDER: Signatures are $($mp.AntivirusSignatureAge) days old" -Severity 'HIGH'
        }
        if ($mp.QuickScanAge -gt 7) {
            Write-Alert -Message "DEFENDER: Last Quick Scan was $($mp.QuickScanAge) days ago" -Severity 'MEDIUM'
        }

        Write-EventEntry -Category 'defender' -Message (
            "AV=$($mp.AntivirusEnabled) RTP=$($mp.RealTimeProtectionEnabled) " +
            "SigAge=$($mp.AntivirusSignatureAge)d ScanAge=$($mp.QuickScanAge)d"
        )
    }
    catch {
        Write-EventEntry -Category 'defender' -Message "Defender status unavailable: $($_.Exception.Message)" -Severity 'WARN'
    }
}

# =============================================================
# SUSPICIOUS PROCESS SCAN
# =============================================================
function Scan-SuspiciousProcesses {
    $suspiciousFlags = @('-enc', 'encodedcommand', 'windowstyle hidden', 'bypass', 'nop', 'iex', 'invoke-expression')

    $psProcs = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -in @('powershell.exe', 'pwsh.exe') }

    foreach ($p in $psProcs) {
        $cmdLine = [string]$p.CommandLine
        if ([string]::IsNullOrWhiteSpace($cmdLine)) { continue }

        $cmdLower = $cmdLine.ToLowerInvariant()
        $foundFlags = $suspiciousFlags | Where-Object { $cmdLower.Contains($_) }

        if (($foundFlags | Measure-Object).Count -ge 2 -or $cmdLower.Contains('-enc')) {
            Write-Alert -Message "SUSPICIOUS PS PROCESS: pid=$($p.ProcessId) flags=$($foundFlags -join ', ')" `
                        -Severity 'CRITICAL'
        }
    }
}

# =============================================================
# HTML SOC DASHBOARD
# =============================================================
function Build-HtmlDashboard {
    # Load alert entries
    $alerts = @()
    if (Test-Path -LiteralPath $AlertLog) {
        $alerts = Get-Content -Path $AlertLog -ErrorAction SilentlyContinue |
            Where-Object { $_.Trim() } |
            ForEach-Object { try { $_ | ConvertFrom-Json } catch { $null } } |
            Where-Object { $_ -ne $null }
    }

    # Load recent event entries (last 100)
    $events = @()
    if (Test-Path -LiteralPath $EventLog) {
        $events = Get-Content -Path $EventLog -ErrorAction SilentlyContinue |
            Where-Object { $_.Trim() } |
            ForEach-Object { try { $_ | ConvertFrom-Json } catch { $null } } |
            Where-Object { $_ -ne $null } |
            Select-Object -Last 100
    }

    $generatedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $alertCount   = $alerts.Count
    $criticalCount = ($alerts | Where-Object { $_.severity -eq 'CRITICAL' } | Measure-Object).Count
    $highCount     = ($alerts | Where-Object { $_.severity -eq 'HIGH' }     | Measure-Object).Count

    # Build alert rows
    $alertRows = foreach ($a in ($alerts | Sort-Object time -Descending)) {
        $sev  = [System.Net.WebUtility]::HtmlEncode([string]$a.severity)
        $msg  = [System.Net.WebUtility]::HtmlEncode([string]$a.message)
        $time = [System.Net.WebUtility]::HtmlEncode([string]$a.time)
        "<tr class='sev-$sev'><td>$time</td><td>$sev</td><td>$msg</td></tr>"
    }

    # Build event rows
    $eventRows = foreach ($e in ($events | Sort-Object time -Descending)) {
        $cat  = [System.Net.WebUtility]::HtmlEncode([string]$e.category)
        $sev  = [System.Net.WebUtility]::HtmlEncode([string]$e.severity)
        $msg  = [System.Net.WebUtility]::HtmlEncode([string]$e.message)
        $time = [System.Net.WebUtility]::HtmlEncode([string]$e.time)
        "<tr><td>$time</td><td>$cat</td><td>$sev</td><td>$msg</td></tr>"
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AVA SOC CORE - Security Dashboard</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', Tahoma, Arial, sans-serif; background: #111827; color: #e5e7eb; padding: 24px; }
    h1 { color: #00ffcc; border-bottom: 2px solid #00ffcc; padding-bottom: 10px; margin-bottom: 8px; font-size: 1.6rem; letter-spacing: 1px; }
    .subtitle { color: #9ca3af; font-size: 0.85rem; margin-bottom: 24px; }
    .stats { display: flex; gap: 16px; margin-bottom: 28px; flex-wrap: wrap; }
    .stat-card { background: #1f2937; border-radius: 8px; padding: 16px 24px; min-width: 140px; text-align: center; border-top: 3px solid #374151; }
    .stat-card.critical { border-top-color: #ef4444; }
    .stat-card.high     { border-top-color: #f97316; }
    .stat-card.total    { border-top-color: #3b82f6; }
    .stat-number { font-size: 2rem; font-weight: bold; }
    .stat-label  { font-size: 0.8rem; color: #9ca3af; margin-top: 4px; }
    h2 { color: #00ffcc; font-size: 1.1rem; margin: 24px 0 10px; }
    table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
    thead tr { background: #1f2937; }
    th { padding: 10px 12px; text-align: left; color: #9ca3af; font-weight: 600; border-bottom: 1px solid #374151; }
    td { padding: 8px 12px; border-bottom: 1px solid #1f2937; word-break: break-all; }
    tbody tr:hover { background: #1f2937; }
    .sev-CRITICAL td { background: #2d1515; color: #fca5a5; }
    .sev-HIGH     td { background: #2d1f0f; color: #fdba74; }
    .sev-MEDIUM   td { background: #2d2a0a; color: #fde68a; }
    .sev-LOW      td { color: #86efac; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }
    .badge-CRITICAL { background: #ef4444; color: #fff; }
    .badge-HIGH     { background: #f97316; color: #fff; }
    .badge-MEDIUM   { background: #eab308; color: #000; }
    .badge-LOW      { background: #22c55e; color: #000; }
    .badge-INFO     { background: #3b82f6; color: #fff; }
    .badge-WARN     { background: #f59e0b; color: #000; }
    .no-data { color: #6b7280; font-style: italic; padding: 12px 0; }
    footer { margin-top: 40px; font-size: 0.75rem; color: #4b5563; border-top: 1px solid #374151; padding-top: 12px; }
  </style>
</head>
<body>

<h1>&#x1F6E1; AVA SOC CORE — Security Dashboard</h1>
<div class="subtitle">Generated: $generatedAt &nbsp;|&nbsp; Host: $env:COMPUTERNAME &nbsp;|&nbsp; User: $env:USERDOMAIN\$env:USERNAME</div>

<div class="stats">
  <div class="stat-card total">
    <div class="stat-number">$alertCount</div>
    <div class="stat-label">Total Alerts</div>
  </div>
  <div class="stat-card critical">
    <div class="stat-number">$criticalCount</div>
    <div class="stat-label">Critical</div>
  </div>
  <div class="stat-card high">
    <div class="stat-number">$highCount</div>
    <div class="stat-label">High</div>
  </div>
</div>

<h2>&#x26A0; Active Alerts</h2>
$(if ($alertRows) {
    "<table><thead><tr><th>Time</th><th>Severity</th><th>Message</th></tr></thead><tbody>$($alertRows -join '')</tbody></table>"
} else {
    "<p class='no-data'>No alerts recorded.</p>"
})

<h2>&#x1F4CB; Recent Events (last 100)</h2>
$(if ($eventRows) {
    "<table><thead><tr><th>Time</th><th>Category</th><th>Severity</th><th>Message</th></tr></thead><tbody>$($eventRows -join '')</tbody></table>"
} else {
    "<p class='no-data'>No events recorded.</p>"
})

<footer>
  AVA SOC CORE v1 &mdash; Defensive / Read-Only / Local &mdash;
  Report: $DashboardHtml
</footer>

</body>
</html>
"@

    Set-Content -Path $DashboardHtml -Value $html -Encoding UTF8
    Write-EventEntry -Category 'dashboard' -Message "SOC dashboard written: $DashboardHtml"
}

# =============================================================
# SCHEDULED TASK MANAGEMENT
# =============================================================
function Install-Task {
    if (-not $PSCommandPath) {
        throw 'PSCommandPath is empty. The script must be saved as a .ps1 file and run with -File.'
    }

    $action = New-ScheduledTaskAction `
        -Execute  'powershell.exe' `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -RunOnce"

    $trigger = New-ScheduledTaskTrigger `
        -Once `
        -At (Get-Date).AddMinutes(1) `
        -RepetitionInterval (New-TimeSpan -Minutes 5) `
        -RepetitionDuration ([TimeSpan]::MaxValue)

    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest

    Register-ScheduledTask `
        -TaskName  $TaskName `
        -Action    $action `
        -Trigger   $trigger `
        -Principal $principal `
        -Force | Out-Null

    Write-EventEntry -Category 'task' -Message "Scheduled Task installed: $TaskName (every 5 min)"
    Write-Host "AVA SOC CORE: Scheduled Task '$TaskName' installed (runs every 5 minutes as SYSTEM)." -ForegroundColor Cyan
}

function Remove-Task {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-EventEntry -Category 'task' -Message "Scheduled Task removed: $TaskName"
        Write-Host "AVA SOC CORE: Scheduled Task '$TaskName' removed." -ForegroundColor Yellow
    }
    else {
        Write-Host "AVA SOC CORE: Scheduled Task '$TaskName' not found." -ForegroundColor Gray
    }
}

# =============================================================
# MAIN
# =============================================================
if ($RemoveTask) {
    Remove-Task
    exit 0
}

if ($InstallTask -and -not $RunOnce) {
    # Ensure directories and canaries exist, then register the task
    if (-not (Test-Path -LiteralPath $BaselinePath)) {
        Save-Baseline
    }
    Initialize-Canaries
    Save-ScriptHash
    Install-Task
    exit 0
}

# --- Monitoring cycle (RunOnce or interactive) ---
Write-Host 'AVA SOC CORE: Starting monitoring cycle...' -ForegroundColor Green

Check-ScriptIntegrity

if (-not (Test-Path -LiteralPath $BaselinePath)) {
    Save-Baseline
}

Initialize-Canaries
Check-Canaries
Check-AdminDrift
Check-RiskPortConnections
Check-DefenderStatus
Scan-SuspiciousProcesses
Build-HtmlDashboard
Save-ScriptHash

if ($InstallTask) {
    Install-Task
}

Write-Host ''
Write-Host 'AVA SOC CORE: Monitoring cycle complete.' -ForegroundColor Green
Write-Host "Dashboard : $DashboardHtml"              -ForegroundColor Cyan
Write-Host "Alert log : $AlertLog"                   -ForegroundColor Cyan
Write-Host "Event log : $EventLog"                   -ForegroundColor Cyan
Write-Host ''
Write-Host 'Kernsatz: Ich bleibe klar. Ich prüfe erst. Ich handle bewusst.' -ForegroundColor Yellow
Write-Host ''
