#requires -RunAsAdministrator
<#
AVA IMMUNE SYSTEM v3 – SOC FUSION
Basierend auf:
- Linux SOC Commands (uptime/top/ss/systemctl/journalctl/id/df/iptables)
- Windows Defender / Netzwerk / Prozesse
- AVA Baseline + Risk Engine

Defensiv / Lokal / Read-Only

Usage:
  powershell -ExecutionPolicy Bypass -File .\AVA_Immune_System_v3.ps1

Output:
  C:\Windows\SecurityGuardian\Reports\ava_immune_v3_<timestamp>.txt
  C:\Windows\SecurityGuardian\Logs\immune_v3_events.jsonl
  C:\Windows\SecurityGuardian\Logs\immune_v3_alerts.jsonl

Tested on Windows 10/11, PowerShell 5.1+
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# =========================
# CONFIG
# =========================
$Root      = 'C:\Windows\SecurityGuardian'
$LogDir    = Join-Path $Root 'Logs'
$ReportDir = Join-Path $Root 'Reports'

$Now        = Get-Date -Format 'yyyyMMdd_HHmmss'
$EventLog   = Join-Path $LogDir    'immune_v3_events.jsonl'
$AlertLog   = Join-Path $LogDir    'immune_v3_alerts.jsonl'
$TxtReport  = Join-Path $ReportDir "ava_immune_v3_$Now.txt"

foreach ($d in @($Root, $LogDir, $ReportDir)) {
    if (-not (Test-Path -LiteralPath $d)) {
        New-Item -ItemType Directory -Path $d -Force | Out-Null
    }
}

$Out = New-Object System.Collections.Generic.List[string]

# =========================
# LOGGING HELPERS
# =========================
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

function Add-OutputLine {
    param([string]$txt)
    $Out.Add($txt)
    Write-Host $txt
}

# =========================
# HEADER
# =========================
Add-OutputLine '===== AVA IMMUNE SYSTEM v3 – SOC FUSION ====='
Add-OutputLine "Time: $(Get-Date)"
Add-OutputLine ''

Write-EventEntry -Category 'startup' -Message "AVA Immune System v3 started on $env:COMPUTERNAME by $env:USERNAME"

# =========================
# SYSTEM HEALTH (Linux: uptime/top)
# =========================
Add-OutputLine '=== SYSTEM HEALTH ==='
$script:cpuLoad = $null
try {
    $script:cpuLoad = Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty LoadPercentage
    $ram = Get-CimInstance Win32_OperatingSystem

    $ramUsedGB = [math]::Round(($ram.TotalVisibleMemorySize - $ram.FreePhysicalMemory) / 1MB, 2)

    Add-OutputLine "CPU Load: $($script:cpuLoad)%"
    Add-OutputLine "RAM Used: $ramUsedGB GB"

    Write-EventEntry -Category 'system_health' -Message "CPU=$($script:cpuLoad)% RAM_Used=${ramUsedGB}GB"
}
catch {
    Add-OutputLine "System Health unavailable: $($_.Exception.Message)"
    Write-EventEntry -Category 'system_health' -Message $_.Exception.Message -Severity 'WARN'
}

# =========================
# PROCESSES (Linux: ps/top)
# =========================
Add-OutputLine "`n=== TOP PROCESSES ==="
try {
    $topProcs = Get-Process |
        Sort-Object CPU -Descending |
        Select-Object -First 10 Name, CPU

    foreach ($p in $topProcs) {
        Add-OutputLine "$($p.Name) | CPU: $($p.CPU)"
    }

    Write-EventEntry -Category 'processes' -Message "Top process: $($topProcs[0].Name) CPU=$($topProcs[0].CPU)"
}
catch {
    Add-OutputLine "Process list unavailable: $($_.Exception.Message)"
    Write-EventEntry -Category 'processes' -Message $_.Exception.Message -Severity 'WARN'
}

# =========================
# NETWORK (Linux: ss/netstat)
# =========================
Add-OutputLine "`n=== NETWORK CONNECTIONS ==="
try {
    $conns = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
        Select-Object LocalAddress, RemoteAddress, RemotePort, OwningProcess

    foreach ($c in $conns) {
        Add-OutputLine "$($c.RemoteAddress):$($c.RemotePort)"
    }

    Write-EventEntry -Category 'network' -Message "Established TCP connections: $($conns.Count)"
}
catch {
    Add-OutputLine "Network connections unavailable: $($_.Exception.Message)"
    Write-EventEntry -Category 'network' -Message $_.Exception.Message -Severity 'WARN'
}

# =========================
# SERVICES (Linux: systemctl)
# =========================
Add-OutputLine "`n=== SERVICES ==="
try {
    Get-Service |
        Where-Object { $_.Status -eq 'Running' } |
        Select-Object -First 10 Name, Status |
        ForEach-Object { Add "$($_.Name) running" }

    Write-EventEntry -Category 'services' -Message 'Running services snapshot taken'
}
catch {
    Add-OutputLine "Services unavailable: $($_.Exception.Message)"
    Write-EventEntry -Category 'services' -Message $_.Exception.Message -Severity 'WARN'
}

# =========================
# LOGS (Linux: journalctl)
# =========================
Add-OutputLine "`n=== EVENT LOG ERRORS ==="
try {
    Get-EventLog -LogName System -EntryType Error -Newest 10 |
        ForEach-Object { Add "$($_.TimeGenerated) | $($_.Source)" }

    Write-EventEntry -Category 'event_log' -Message 'System event log errors snapshot taken'
}
catch {
    Add-OutputLine "Event log unavailable: $($_.Exception.Message)"
    Write-EventEntry -Category 'event_log' -Message $_.Exception.Message -Severity 'WARN'
}

# =========================
# USERS (Linux: id/groups)
# =========================
Add-OutputLine "`n=== ADMIN USERS ==="
try {
    $adminMembers = Get-LocalGroupMember -Group 'Administrators'
    foreach ($member in $adminMembers) {
        Add-OutputLine $member.Name
    }

    Write-EventEntry -Category 'users' -Message "Admin group members: $($adminMembers.Count)"
}
catch {
    Add-OutputLine "Admin users unavailable: $($_.Exception.Message)"
    Write-EventEntry -Category 'users' -Message $_.Exception.Message -Severity 'WARN'
}

# =========================
# DISK (Linux: df/du)
# =========================
Add-OutputLine "`n=== DISK ==="
try {
    Get-PSDrive -PSProvider FileSystem |
        ForEach-Object {
            Add-OutputLine "$($_.Name): Free $([math]::Round($_.Free / 1GB, 2)) GB"
        }

    Write-EventEntry -Category 'disk' -Message 'Disk usage snapshot taken'
}
catch {
    Add-OutputLine "Disk info unavailable: $($_.Exception.Message)"
    Write-EventEntry -Category 'disk' -Message $_.Exception.Message -Severity 'WARN'
}

# =========================
# FIREWALL (Linux: iptables/ufw)
# =========================
Add-OutputLine "`n=== FIREWALL STATUS ==="
try {
    $fwProfiles = Get-NetFirewallProfile
    foreach ($p in $fwProfiles) {
        Add-OutputLine "$($p.Name): Enabled=$($p.Enabled)"
    }

    $disabledProfiles = @($fwProfiles | Where-Object { -not $_.Enabled })
    if ($disabledProfiles.Count -gt 0) {
        foreach ($dp in $disabledProfiles) {
            Write-Alert -Message "FIREWALL PROFILE DISABLED: $($dp.Name)" -Severity 'CRITICAL'
        }
    }

    Write-EventEntry -Category 'firewall' -Message 'Firewall profile snapshot taken'
}
catch {
    Add-OutputLine "Firewall status unavailable: $($_.Exception.Message)"
    Write-EventEntry -Category 'firewall' -Message $_.Exception.Message -Severity 'WARN'
}

# =========================
# DEFENDER
# =========================
Add-OutputLine "`n=== DEFENDER ==="
$def = $null
try {
    $def = Get-MpComputerStatus
    Add-OutputLine "Realtime: $($def.RealTimeProtectionEnabled)"
    Add-OutputLine "AV Enabled: $($def.AntivirusEnabled)"

    Write-EventEntry -Category 'defender' -Message "AV=$($def.AntivirusEnabled) RTP=$($def.RealTimeProtectionEnabled) SigAge=$($def.AntivirusSignatureAge)d"
}
catch {
    Add-OutputLine "Defender status unavailable: $($_.Exception.Message)"
    Write-EventEntry -Category 'defender' -Message $_.Exception.Message -Severity 'WARN'
}

# =========================
# RISK ENGINE
# =========================
Add-OutputLine "`n=== RISK ENGINE ==="

$Risk = 0

if ($null -ne $def) {
    if (-not $def.RealTimeProtectionEnabled) {
        Add-OutputLine 'CRITICAL: Defender Realtime Protection OFF'
        Write-Alert -Message 'DEFENDER: Real-Time Protection is DISABLED' -Severity 'CRITICAL'
        $Risk += 100
    }

    if (-not $def.AntivirusEnabled) {
        Add-OutputLine 'CRITICAL: Defender Antivirus DISABLED'
        Write-Alert -Message 'DEFENDER: Antivirus is DISABLED' -Severity 'CRITICAL'
        $Risk += 100
    }
}

try {
    $rdp = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -ErrorAction Stop
    if ($rdp.fDenyTSConnections -eq 0) {
        Add-OutputLine 'WARNING: RDP ENABLED'
        Write-Alert -Message 'RDP is enabled (fDenyTSConnections=0)' -Severity 'HIGH'
        $Risk += 40
    }
}
catch {
    Write-EventEntry -Category 'risk_engine' -Message "RDP registry check failed: $($_.Exception.Message)" -Severity 'WARN'
}

if ($null -ne $def -and $null -ne $def.AntivirusSignatureAge -and $def.AntivirusSignatureAge -gt 3) {
    Add-OutputLine "WARNING: AV signatures $($def.AntivirusSignatureAge) days old"
    Write-Alert -Message "DEFENDER: Signatures are $($def.AntivirusSignatureAge) days old" -Severity 'HIGH'
    $Risk += 30
}

if ($null -ne $script:cpuLoad -and $script:cpuLoad -gt 80) {
    Add-OutputLine "HIGH CPU LOAD: $($script:cpuLoad)%"
    Write-Alert -Message "HIGH CPU LOAD: $($script:cpuLoad)%" -Severity 'HIGH'
    $Risk += 30
}

Add-OutputLine "TOTAL RISK SCORE: $Risk"

Write-EventEntry -Category 'risk_engine' -Message "Risk score: $Risk"

if ($Risk -ge 100) {
    Write-Alert -Message "RISK SCORE CRITICAL: $Risk" -Severity 'CRITICAL'
}
elseif ($Risk -ge 40) {
    Write-Alert -Message "RISK SCORE HIGH: $Risk" -Severity 'HIGH'
}
elseif ($Risk -gt 0) {
    Write-Alert -Message "RISK SCORE MEDIUM: $Risk" -Severity 'MEDIUM'
}

# =========================
# SAVE REPORT
# =========================
$Out -join "`r`n" | Out-File -FilePath $TxtReport -Encoding UTF8

Add-OutputLine "`nReport saved: $TxtReport"
Write-Host ''
Write-Host 'AVA IMMUNE SYSTEM v3 fertig.' -ForegroundColor Green
Write-Host "TXT : $TxtReport"  -ForegroundColor Cyan
Write-Host "Logs: $LogDir"     -ForegroundColor Cyan
Write-Host ''
Write-Host 'Kernsatz: Fakten vor Angst. Baseline vor Chaos. Sichtbarkeit vor Kontrolle.' -ForegroundColor Yellow
Write-Host ''
