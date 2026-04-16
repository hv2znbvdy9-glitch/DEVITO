#requires -RunAsAdministrator

<#
AVA Security Guardian - Defensive Monitoring & Hardening
- Monitors local admin accounts against a baseline
- Deploys canary (decoy) files and watches for tampering
- Verifies script integrity via file hashes
- Applies inbound firewall rules for risky ports
- Scans network connections for suspicious processes
- Detects PowerShell processes with obfuscation flags
- Generates an HTML security dashboard
- Can install a recurring scheduled task

Rein lokal / defensiv / nur auf autorisierten Systemen nutzen
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

param(
    [switch]$RunOnce,
    [switch]$InstallTask,
    [switch]$RemoveTask,
    [switch]$RollbackFirewall,
    [switch]$HardenRemoteServices
)

# =========================
# CONFIG
# =========================
$Root = 'C:\Windows\SecurityGuardian'
$LogDir = Join-Path $Root 'Logs'
$ReportDir = Join-Path $Root 'Reports'
$StateDir = Join-Path $Root 'State'
$TaskName = 'WindowsSecurityGuardian'

$EventLog = Join-Path $LogDir 'events.jsonl'
$AlertLog = Join-Path $LogDir 'alerts.jsonl'
$BaselinePath = Join-Path $StateDir 'baseline.json'
$HashPath = Join-Path $StateDir 'integrity.hash'

$RulePrefix = 'AVA_Block_'

# Allowed local administrator accounts (adjust to your environment)
$AllowedAdmins = @(
    'Administrator',
    $env:USERNAME
)

# Canary (decoy) files – deletion or modification triggers an alert
$CanaryFiles = @(
    (Join-Path $Root 'finance_decoy_2026.txt'),
    (Join-Path $Root 'admin_notes_decoy.txt'),
    (Join-Path $Root 'vpn_inventory_decoy.txt')
)

# =========================
# INIT
# =========================
New-Item -ItemType Directory -Path $Root, $LogDir, $ReportDir, $StateDir -Force | Out-Null

function Write-LogEntry {
    param(
        [Parameter(Mandatory)]
        [object]$LogObject,

        [Parameter(Mandatory)]
        [string]$Path
    )

    $json = $LogObject | ConvertTo-Json -Compress -Depth 5
    Add-Content -Path $Path -Value $json
}

function Write-Alert {
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')]
        [string]$Severity = 'MEDIUM'
    )

    Write-LogEntry -LogObject @{
        time     = (Get-Date).ToString('o')
        severity = $Severity
        message  = $Message
    } -Path $AlertLog
}

# =========================
# BASELINE
# =========================
function Save-Baseline {
    $admins = Get-LocalGroupMember Administrators | Select-Object Name
    $baseline = @{
        created = (Get-Date).ToString('o')
        admins  = $admins
    }
    $baseline | ConvertTo-Json | Set-Content $BaselinePath
}

function Test-Admins {
    $admins = Get-LocalGroupMember Administrators | Select-Object Name
    foreach ($a in $admins) {
        if ($AllowedAdmins -notcontains $a.Name) {
            Write-Alert -Message "UNAUTHORIZED ADMIN: $($a.Name)" -Severity 'HIGH'
        }
    }
}

# =========================
# CANARY SYSTEM
# =========================
function Initialize-Canaries {
    foreach ($file in $CanaryFiles) {
        if (-not (Test-Path $file)) {
            'DO NOT TOUCH - MONITORED' | Set-Content $file
        }
    }
}

function Test-Canaries {
    foreach ($file in $CanaryFiles) {
        if (-not (Test-Path $file)) {
            Write-Alert -Message "CANARY DELETED: $file" -Severity 'HIGH'
        }
    }
}

# =========================
# INTEGRITY CHECK
# =========================
function Save-ScriptHash {
    $hash = Get-FileHash $PSCommandPath
    $hash.Hash | Set-Content $HashPath
}

function Test-ScriptHash {
    if (Test-Path $HashPath) {
        $old = Get-Content $HashPath
        $new = (Get-FileHash $PSCommandPath).Hash
        if ($old -ne $new) {
            Write-Alert -Message 'SCRIPT TAMPER DETECTED!' -Severity 'HIGH'
        }
    }
}

# =========================
# FIREWALL
# =========================
$BlockedPorts = @(21, 23, 135, 139, 445, 3389, 5985, 5986)

function Set-FirewallBlocks {
    foreach ($p in $BlockedPorts) {
        $ruleName = "$RulePrefix$p"
        if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $ruleName `
                -Direction Inbound `
                -Action Block `
                -Protocol TCP `
                -LocalPort $p | Out-Null
        }
    }
}

function Remove-FirewallBlocks {
    foreach ($p in $BlockedPorts) {
        $ruleName = "$RulePrefix$p"
        $existing = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        if ($existing) {
            Remove-NetFirewallRule -DisplayName $ruleName
            Write-Host "Removed firewall rule: $ruleName" -ForegroundColor Yellow
        }
    }
    Write-Host 'Firewall rollback complete.' -ForegroundColor Green
}

# =========================
# HARDEN REMOTE SERVICES
# =========================
function Set-RemoteServiceHardening {
    $servicesToDisable = @('RemoteRegistry', 'WinRM')
    foreach ($svcName in $servicesToDisable) {
        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq 'Running') {
            Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
            Set-Service -Name $svcName -StartupType Disabled -ErrorAction SilentlyContinue
            Write-Alert -Message "Disabled remote service: $svcName" -Severity 'MEDIUM'
            Write-Host "Disabled service: $svcName" -ForegroundColor Yellow
        }
    }
    Write-Host 'Remote service hardening complete.' -ForegroundColor Green
}

# =========================
# NETWORK MONITOR
# =========================
function Test-NetworkConnections {
    $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
    foreach ($c in $conns) {
        # Skip private / loopback addresses
        if ($c.RemoteAddress -match '^127\.|^192\.168\.|^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.') {
            continue
        }

        $proc = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
        if ($proc) {
            $path = $proc.Path
            $riskyTools = @('powershell', 'cmd', 'python', 'certutil', 'bitsadmin')

            if ($proc.Name -in $riskyTools -or ($path -and $path -like '*\AppData\Local\Temp\*')) {
                Write-Alert -Message ("NETWORK ALERT: {0} -> {1}:{2} (Path: {3})" -f `
                    $proc.Name, $c.RemoteAddress, $c.RemotePort, $path) -Severity 'CRITICAL'
            }
        }
    }
}

# =========================
# SUSPICIOUS PROCESS SCAN
# =========================
function Find-SuspiciousProcesses {
    $suspiciousArgs = @('-enc', 'encodedcommand', 'windowstyle hidden', 'bypass', 'nop')

    $psProcs = Get-WmiObject Win32_Process -Filter "name='powershell.exe' OR name='pwsh.exe'" -ErrorAction SilentlyContinue

    foreach ($p in $psProcs) {
        if (-not $p.CommandLine) { continue }

        $cmdLine = $p.CommandLine.ToLower()
        $foundFlags = @()

        foreach ($flag in $suspiciousArgs) {
            if ($cmdLine.Contains($flag)) {
                $foundFlags += $flag
            }
        }

        # Alert when two or more suspicious flags are present, or Base64-encoded command is used
        if ($foundFlags.Count -ge 2 -or $cmdLine.Contains('-enc')) {
            Write-Alert -Message ("SUSPICIOUS PS PROCESS: PID {0} | Args: {1}" -f `
                $p.ProcessId, ($foundFlags -join ', ')) -Severity 'CRITICAL'
        }
    }
}

# =========================
# CANARY WATCHDOG (live filesystem watcher)
# =========================
function Start-CanaryWatchdog {
    foreach ($file in $CanaryFiles) {
        $dir = Split-Path $file
        $filter = Split-Path $file -Leaf

        $watcher = New-Object System.IO.FileSystemWatcher
        $watcher.Path = $dir
        $watcher.Filter = $filter
        $watcher.IncludeSubdirectories = $false
        $watcher.EnableRaisingEvents = $true

        $action = {
            $changedPath = $Event.SourceEventArgs.FullPath
            $changeType = $Event.SourceEventArgs.ChangeType
            Write-Host "[!] ALERT: Canary File $changeType - $changedPath" -ForegroundColor Red
        }

        Register-ObjectEvent $watcher 'Changed' -Action $action | Out-Null
        Register-ObjectEvent $watcher 'Deleted' -Action $action | Out-Null
        Register-ObjectEvent $watcher 'Renamed' -Action $action | Out-Null
    }
}

# =========================
# HTML REPORT
# =========================
function Build-HTMLReport {
    $alerts = @()
    if (Test-Path $AlertLog) {
        $alerts = Get-Content $AlertLog -ErrorAction SilentlyContinue |
            Where-Object { $_ -match '\S' } |
            ForEach-Object {
                try { $_ | ConvertFrom-Json } catch { $null }
            } |
            Where-Object { $_ -ne $null }
    }

    $style = @'
<style>
    body { font-family: Segoe UI, Arial, sans-serif; background: #1e1e2e; color: #cdd6f4; margin: 2em; }
    h1 { color: #89b4fa; }
    table { border-collapse: collapse; width: 100%; margin-top: 1em; }
    th, td { border: 1px solid #45475a; padding: 8px 12px; text-align: left; }
    th { background: #313244; color: #cba6f7; }
    tr:nth-child(even) { background: #181825; }
    .HIGH, .CRITICAL { color: #f38ba8; font-weight: bold; }
    .MEDIUM { color: #fab387; }
    .LOW { color: #a6e3a1; }
</style>
'@

    $rows = foreach ($a in $alerts) {
        $severityClass = $a.severity
        "<tr><td>$($a.time)</td><td class='$severityClass'>$($a.severity)</td><td>$($a.message)</td></tr>"
    }

    $html = @"
<!DOCTYPE html>
<html>
<head><title>AVA Security Dashboard</title>$style</head>
<body>
<h1>AVA Security Dashboard</h1>
<p>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
<table>
<tr><th>Time</th><th>Severity</th><th>Message</th></tr>
$($rows -join "`n")
</table>
</body>
</html>
"@

    $html | Set-Content (Join-Path $ReportDir 'report.html')
}

# =========================
# SCHEDULED TASK
# =========================
function Install-GuardianTask {
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-File `"$PSCommandPath`" -RunOnce"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)
    $trigger.RepetitionInterval = New-TimeSpan -Minutes 5
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest

    Register-ScheduledTask -TaskName $TaskName `
        -Action $action `
        -Trigger $trigger `
        -Principal $principal `
        -Force | Out-Null
}

# =========================
# MAIN
# =========================
if ($RemoveTask) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Scheduled task '$TaskName' removed." -ForegroundColor Green
    exit
}

if ($RollbackFirewall) {
    Remove-FirewallBlocks
    exit
}

if ($HardenRemoteServices) {
    Set-RemoteServiceHardening
    exit
}

if (-not (Test-Path $BaselinePath)) {
    Save-Baseline
}

Initialize-Canaries
Test-ScriptHash
Test-Admins
Test-Canaries
Set-FirewallBlocks
Test-NetworkConnections
Find-SuspiciousProcesses
Build-HTMLReport
Save-ScriptHash

if ($InstallTask) {
    Install-GuardianTask
}

Write-Host 'AVA Security Guardian complete.' -ForegroundColor Green
