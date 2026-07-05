<#
AVA SAFE STANDARD (V6)
Lokal / Defensiv / Read-Only
Keine Angriffe / Keine Exploits / Keine Fremdscans / Keine automatische Ausbreitung / Keine Änderungen am System
#>

#requires -RunAsAdministrator
<#
AVA WLAN TANGLE SENSOR v1.1 SAFE
- Defensiv / Lokal / Read-Only
- Visible WLANs via netsh wlan show networks mode=bssid
- Eigene Adapterdaten via Get-NetAdapter / Get-NetIPConfiguration
- Eigene LAN-Nachbarn via Get-NetNeighbor
- JSONL event log  : C:\Windows\SecurityGuardian\Logs\wlan_events.jsonl
- JSONL tangle log : C:\Windows\SecurityGuardian\Logs\wlan_tangle.jsonl
- HTML portal      : C:\Windows\SecurityGuardian\Reports\ava_wlan_portal.html
- Admin-Policy JSON: C:\Windows\SecurityGuardian\State\ava_admin_policy.json

No attacks. No monitor mode. No deauth. No cracking.

Usage:
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\AVA_WLAN_TANGLE_SENSOR.ps1 -RunOnce
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\AVA_WLAN_TANGLE_SENSOR.ps1 -Loop -IntervalSeconds 60
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\AVA_WLAN_TANGLE_SENSOR.ps1 -InstallTask
  powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\AVA_WLAN_TANGLE_SENSOR.ps1 -RemoveTask

Tested on Windows 10/11, PowerShell 5.1+
#>

[CmdletBinding()]
param(
    [switch]$RunOnce,
    [switch]$Loop,
    [switch]$InstallTask,
    [switch]$RemoveTask,
    [ValidateRange(10, 86400)]
    [int]$IntervalSeconds = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# =============================================================
# CONFIG
# =============================================================
$Root       = 'C:\Windows\SecurityGuardian'
$LogDir     = Join-Path $Root   'Logs'
$StateDir   = Join-Path $Root   'State'
$ReportDir  = Join-Path $Root   'Reports'
$ScriptPath = $PSCommandPath

$EventLog    = Join-Path $LogDir  'wlan_events.jsonl'
$TangleLog   = Join-Path $LogDir  'wlan_tangle.jsonl'
$TangleState = Join-Path $StateDir 'wlan_tangle_state.json'
$PolicyJson  = Join-Path $StateDir 'ava_admin_policy.json'
$PortalHtml  = Join-Path $ReportDir 'ava_wlan_portal.html'

$TaskName = 'AVA_WLAN_TANGLE_SENSOR_V1'

$AvaAdminPolicy = [ordered]@{
    ava_admin = [ordered]@{
        role        = 'CHEF_CONTROLLER_OWNER_ADMIN'
        rights      = 'FULL_CONTROL_ON_AUTHORIZED_SYSTEMS_ONLY'
        purpose     = @(
            'Schutz',
            'Sicherheit',
            'Beweissicherung',
            'Defensive Analyse',
            'Attacke-Abwehr',
            'Recovery',
            'Safe Mode'
        )
        hard_limits = @(
            'keine fremden Systeme angreifen',
            'keine Accounts missbrauchen',
            'keine WLANs stören',
            'keine Panikreaktionen',
            'keine Gewalt',
            'keine Gegenattacke'
        )
        core_rule   = 'Schutzregeln stehen über Vollzugriff.'
    }
}

# =============================================================
# DIRECTORY INIT
# =============================================================
function Ensure-Dirs {
    foreach ($d in @($Root, $LogDir, $StateDir, $ReportDir)) {
        if (-not (Test-Path -LiteralPath $d)) {
            New-Item -ItemType Directory -Path $d -Force | Out-Null
        }
    }

    $AvaAdminPolicy |
        ConvertTo-Json -Depth 10 |
        Set-Content -LiteralPath $PolicyJson -Encoding UTF8
}

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
        time     = (Get-Date).ToString('o')
        category = $Category
        severity = $Severity
        message  = $Message
    } -Path $EventLog
}

function HtmlEncode {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Format-EmptyRow {
    param(
        [int]$Cols,
        [string]$Text
    )
    return "<tr><td colspan='$Cols' style='color:#9ca3af;font-style:italic'>$(HtmlEncode $Text)</td></tr>"
}

# =============================================================
# TANGLE HASH CHAIN
# =============================================================
function Get-Sha256Text {
    param([Parameter(Mandatory)][string]$Text)
    $sha   = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join ''
}

function Write-Tangle {
    param(
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][string]$Summary,
        [Parameter(Mandatory)][AllowNull()][object]$Data
    )

    $prevHash = $null
    if (Test-Path -LiteralPath $TangleState) {
        try {
            $state    = Get-Content -Path $TangleState -Raw -Encoding UTF8 | ConvertFrom-Json
            $prevHash = $state.last_hash
        }
        catch { $prevHash = $null }
    }

    # Build entry without hash field first, hash it, then append hash
    $entryContent = [ordered]@{
        time          = (Get-Date).ToString('o')
        host          = $env:COMPUTERNAME
        user          = $env:USERNAME
        type          = $Type
        summary       = $Summary
        previous_hash = $prevHash
        data          = $Data
    }

    $raw  = $entryContent | ConvertTo-Json -Compress -Depth 8
    $hash = Get-Sha256Text -Text $raw

    # Compose the final logged entry with the computed hash appended
    $entry = [ordered]@{}
    foreach ($k in $entryContent.Keys) { $entry[$k] = $entryContent[$k] }
    $entry['hash'] = $hash

    Write-JsonLine -Object $entry -Path $TangleLog

    @{
        updated   = (Get-Date).ToString('o')
        last_hash = $hash
    } | ConvertTo-Json | Set-Content -Path $TangleState -Encoding UTF8
}

# =============================================================
# WLAN SCAN  (read-only via netsh)
# =============================================================
function Get-WlanNetworksSafe {
    $raw = ''
    try {
        $raw = netsh wlan show networks mode=bssid 2>&1 | Out-String
    }
    catch {
        return @([pscustomobject]@{ Error = $_.Exception.Message })
    }

    $items        = [System.Collections.Generic.List[pscustomobject]]::new()
    $currentSsid  = $null
    $currentAuth  = $null
    $currentEncr  = $null

    foreach ($line in ($raw -split '\r?\n')) {
        $l = $line.Trim()

        if ($l -match '^SSID\s+\d+\s*:\s*(.*)$') {
            $currentSsid = $Matches[1]
            $currentAuth = $null
            $currentEncr = $null
        }
        elseif ($l -match '^(Authentication|Authentifizierung)\s*:\s*(.*)$') {
            $currentAuth = $Matches[2]
        }
        elseif ($l -match '^(Encryption|Verschlüsselung)\s*:\s*(.*)$') {
            $currentEncr = $Matches[2]
        }
        elseif ($l -match '^BSSID\s+\d+\s*:\s*(.*)$') {
            $items.Add([pscustomobject]@{
                SSID           = $currentSsid
                BSSID          = $Matches[1]
                Authentication = $currentAuth
                Encryption     = $currentEncr
                Signal         = $null
                RadioType      = $null
                Channel        = $null
            }) | Out-Null
        }
        elseif ($l -match '^Signal\s*:\s*(.*)$') {
            if ($items.Count -gt 0) {
                $items[$items.Count - 1].Signal = $Matches[1]
            }
        }
        elseif ($l -match '^(Radio type|Funktyp)\s*:\s*(.*)$') {
            if ($items.Count -gt 0) {
                $items[$items.Count - 1].RadioType = $Matches[2]
            }
        }
        elseif ($l -match '^(Channel|Kanal)\s*:\s*(.*)$') {
            if ($items.Count -gt 0) {
                $items[$items.Count - 1].Channel = $Matches[2]
            }
        }
    }

    if ($items.Count -eq 0) {
        return @([pscustomobject]@{ Info = 'No networks found or WLAN adapter unavailable.' })
    }
    return $items.ToArray()
}

# =============================================================
# LOCAL NETWORK SNAPSHOT  (adapters + ARP neighbours)
# =============================================================
function Get-LocalNetworkSnapshot {
    $adapters = @()
    try {
        $adapters = @(
            Get-NetAdapter -ErrorAction Stop |
                Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed
        )
    }
    catch {
        $adapters = @([pscustomobject]@{ Error = $_.Exception.Message })
    }

    $ipConfig = @()
    try {
        $ipConfig = @(
            Get-NetIPConfiguration -ErrorAction Stop | ForEach-Object {
                [pscustomobject]@{
                    InterfaceAlias     = $_.InterfaceAlias
                    IPv4Address        = @($_.IPv4Address | ForEach-Object { $_.IPAddress })
                    IPv6Address        = @($_.IPv6Address | ForEach-Object { $_.IPAddress })
                    IPv4DefaultGateway = @($_.IPv4DefaultGateway | ForEach-Object { $_.NextHop })
                    DNSServer          = if ($_.DNSServer) { @($_.DNSServer.ServerAddresses) } else { @() }
                }
            }
        )
    }
    catch {
        $ipConfig = @([pscustomobject]@{ Error = $_.Exception.Message })
    }

    $neighbors = @()
    try {
        $neighbors = @(Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.State -ne 'Unreachable' } |
            Select-Object InterfaceAlias, IPAddress, LinkLayerAddress, State)
    }
    catch {
        $neighbors = @(@{ Error = $_.Exception.Message })
    }

    [ordered]@{
        time       = (Get-Date).ToString('o')
        computer   = $env:COMPUTERNAME
        user       = $env:USERNAME
        adapters   = $adapters
        ipconfig   = $ipConfig
        neighbors  = $neighbors
        wlan       = Get-WlanNetworksSafe
        policy     = $AvaAdminPolicy.ava_admin
    }
}

# =============================================================
# HTML PORTAL
# =============================================================
function New-Portal {
    param([Parameter(Mandatory)][object]$Snapshot)

    $wlanCount     = @($Snapshot.wlan).Count
    $neighborCount = @($Snapshot.neighbors).Count
    $adapterCount  = @($Snapshot.adapters).Count
    $generatedAt   = if ($Snapshot.generated_at -and ([string]$Snapshot.generated_at).Trim()) {
        [string]$Snapshot.generated_at
    }
    else {
        (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    }

    $lastHash = 'N/A'
    if (Test-Path -LiteralPath $TangleState) {
        try {
            $stateObj = Get-Content -LiteralPath $TangleState -Raw -Encoding UTF8 | ConvertFrom-Json
            $lastHash = if ($stateObj.last_hash) { [string]$stateObj.last_hash } else { 'N/A' }
        }
        catch {
            $lastHash = 'N/A'
            Write-EventEntry -Category 'portal' -Severity 'WARN' -Message "Could not parse tangle state: $($_.Exception.Message)"
        }
    }

    $wlanRows = foreach ($w in @($Snapshot.wlan)) {
        if ($w.PSObject.Properties.Name -contains 'Error' -or
            $w.PSObject.Properties.Name -contains 'Info') {
            $msg = if ($w.Error) { $w.Error } else { $w.Info }
            Format-EmptyRow -Cols 7 -Text $msg
            continue
        }
        $wlanCells = @(
            "<td>$(HtmlEncode $w.SSID)</td>"
            "<td>$(HtmlEncode $w.BSSID)</td>"
            "<td>$(HtmlEncode $w.Authentication)</td>"
            "<td>$(HtmlEncode $w.Encryption)</td>"
            "<td>$(HtmlEncode $w.Signal)</td>"
            "<td>$(HtmlEncode $w.RadioType)</td>"
            "<td>$(HtmlEncode $w.Channel)</td>"
        ) -join ''
        "<tr>$wlanCells</tr>"
    }
    if (-not $wlanRows) {
        $wlanRows = @(Format-EmptyRow -Cols 7 -Text 'No WLAN data available.')
    }

    $neighborRows = foreach ($n in @($Snapshot.neighbors)) {
        if ($n.PSObject.Properties.Name -contains 'Error') {
            Format-EmptyRow -Cols 4 -Text $n.Error
            continue
        }
        $neighborCells = @(
            "<td>$(HtmlEncode $n.IPAddress)</td>"
            "<td>$(HtmlEncode $n.LinkLayerAddress)</td>"
            "<td>$(HtmlEncode $n.State)</td>"
            "<td>$(HtmlEncode $n.InterfaceAlias)</td>"
        ) -join ''
        "<tr>$neighborCells</tr>"
    }
    if (-not $neighborRows) {
        $neighborRows = @(Format-EmptyRow -Cols 4 -Text 'No neighbor entries found.')
    }

    $adapterRows = foreach ($a in @($Snapshot.adapters)) {
        if ($a.PSObject.Properties.Name -contains 'Error') {
            Format-EmptyRow -Cols 5 -Text $a.Error
            continue
        }
        $adapterCells = @(
            "<td>$(HtmlEncode $a.Name)</td>"
            "<td>$(HtmlEncode $a.InterfaceDescription)</td>"
            "<td>$(HtmlEncode $a.Status)</td>"
            "<td>$(HtmlEncode $a.MacAddress)</td>"
            "<td>$(HtmlEncode $a.LinkSpeed)</td>"
        ) -join ''
        "<tr>$adapterCells</tr>"
    }
    if (-not $adapterRows) {
        $adapterRows = @(Format-EmptyRow -Cols 5 -Text 'Keine Adapterdaten gefunden.')
    }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AVA WLAN TANGLE SENSOR</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', Tahoma, Arial, sans-serif; background: #111827; color: #e5e7eb; padding: 24px; }
    h1 { color: #00ffcc; border-bottom: 2px solid #00ffcc; padding-bottom: 10px; margin-bottom: 8px; font-size: 1.6rem; letter-spacing: 1px; }
    .subtitle { color: #9ca3af; font-size: 0.85rem; margin-bottom: 24px; }
    .stats { display: flex; gap: 16px; margin-bottom: 28px; flex-wrap: wrap; }
    .stat-card { background: #1f2937; border-radius: 8px; padding: 16px 24px; min-width: 140px; text-align: center; border-top: 3px solid #00ffcc; }
    .stat-number { font-size: 2rem; font-weight: bold; color: #00ffcc; }
    .stat-label  { font-size: 0.8rem; color: #9ca3af; margin-top: 4px; }
    h2 { color: #00ffcc; font-size: 1.1rem; margin: 28px 0 10px; }
    table { width: 100%; border-collapse: collapse; font-size: 0.85rem; margin-bottom: 8px; }
    thead tr { background: #1f2937; }
    th { padding: 10px 12px; text-align: left; color: #9ca3af; font-weight: 600; border-bottom: 1px solid #374151; }
    td { padding: 8px 12px; border-bottom: 1px solid #1f2937; word-break: break-all; }
    tbody tr:hover { background: #1f2937; }
    footer { margin-top: 40px; font-size: 0.75rem; color: #4b5563; border-top: 1px solid #374151; padding-top: 12px; }
  </style>
</head>
<body>

<h1>&#x1F4F6; AVA WLAN TANGLE SENSOR &#x1F6E1;</h1>
<div class="subtitle">
  Generated: $generatedAt &nbsp;|&nbsp;
  Host: $(HtmlEncode $env:COMPUTERNAME) &nbsp;|&nbsp;
  User: $(HtmlEncode $env:USERNAME) &nbsp;|&nbsp;
  Last Hash: $(HtmlEncode $lastHash)
</div>

<div class="stats">
  <div class="stat-card">
    <div class="stat-number">$wlanCount</div>
    <div class="stat-label">Visible WLANs</div>
  </div>
  <div class="stat-card">
    <div class="stat-number">$adapterCount</div>
    <div class="stat-label">Active Adapters</div>
  </div>
  <div class="stat-card">
    <div class="stat-number">$neighborCount</div>
    <div class="stat-label">ARP Neighbors</div>
  </div>
</div>

<h2>&#x1F4E1; Visible WLAN Networks</h2>
<table><thead><tr><th>SSID</th><th>BSSID</th><th>Authentication</th><th>Encryption</th><th>Signal</th><th>Radio Type</th><th>Channel</th></tr></thead><tbody>$($wlanRows -join '')</tbody></table>

<h2>&#x1F5A7; Local Adapters</h2>
<table><thead><tr><th>Name</th><th>Interface Description</th><th>Status</th><th>MAC</th><th>Speed</th></tr></thead><tbody>$($adapterRows -join '')</tbody></table>

<h2>&#x1F4CB; LAN Neighbors (ARP Cache)</h2>
<table><thead><tr><th>IP Address</th><th>MAC / Link-Layer</th><th>State</th><th>Interface</th></tr></thead><tbody>$($neighborRows -join '')</tbody></table>

<footer>
  AVA WLAN TANGLE SENSOR v1 &mdash; Defensive / Read-Only / Local &mdash;
  Tangle log: $(HtmlEncode $TangleLog) &mdash;
  Events: $(HtmlEncode $EventLog)
</footer>

</body>
</html>
"@

    Set-Content -LiteralPath $PortalHtml -Value $html -Encoding UTF8
    Write-EventEntry -Category 'portal' -Message "HTML portal written: $PortalHtml"
}

function Build-HtmlPortal {
    param(
        [Parameter(Mandatory)][object[]]$WlanNetworks,
        [Parameter(Mandatory)][object]$LocalSnapshot
    )

    New-Portal -Snapshot @{
        wlan        = $WlanNetworks
        neighbors   = $LocalSnapshot.neighbors
        adapters    = $LocalSnapshot.adapters
        generated_at = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    }
}

# =============================================================
# SCHEDULED TASK MANAGEMENT
# =============================================================
function Install-SensorTask {
    if (-not $ScriptPath) {
        throw 'ScriptPath is empty. The script must be saved as a .ps1 file and run with -File.'
    }

    $action = New-ScheduledTaskAction `
        -Execute  'powershell.exe' `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -RunOnce"

    $trigger = New-ScheduledTaskTrigger `
        -Once `
        -At (Get-Date).AddMinutes(1) `
        -RepetitionInterval (New-TimeSpan -Seconds $IntervalSeconds) `
        -RepetitionDuration ([TimeSpan]::MaxValue)

    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest

    Register-ScheduledTask `
        -TaskName  $TaskName `
        -Action    $action `
        -Trigger   $trigger `
        -Principal $principal `
        -Force | Out-Null

    Write-EventEntry -Category 'task' -Message "Scheduled Task installed: $TaskName (every ${IntervalSeconds}s)"
    Write-Host "AVA WLAN TANGLE SENSOR: Task '$TaskName' installed (every ${IntervalSeconds}s as SYSTEM)." -ForegroundColor Cyan
}

function Remove-SensorTask {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-EventEntry -Category 'task' -Message "Scheduled Task removed: $TaskName"
        Write-Host "AVA WLAN TANGLE SENSOR: Task '$TaskName' removed." -ForegroundColor Yellow
    }
    else {
        Write-Host "AVA WLAN TANGLE SENSOR: Task '$TaskName' not found." -ForegroundColor Gray
    }
}

# =============================================================
# SINGLE SENSOR CYCLE
# =============================================================
function Invoke-SensorCycle {
    Write-Host 'AVA WLAN TANGLE SENSOR: Running sensor cycle...' -ForegroundColor Green

    $wlanNetworks  = Get-WlanNetworksSafe
    $localSnapshot = Get-LocalNetworkSnapshot

    $wlanCount     = $wlanNetworks.Count
    $summary       = "WLANs=$wlanCount adapters=$($localSnapshot.adapters.Count) neighbors=$($localSnapshot.neighbors.Count)"

    Write-EventEntry -Category 'wlan_scan' -Message $summary

    Write-Tangle -Type 'wlan_scan' -Summary $summary -Data @{
        wlan_networks  = $wlanNetworks
        local_snapshot = $localSnapshot
    }

    Build-HtmlPortal -WlanNetworks $wlanNetworks -LocalSnapshot $localSnapshot

    Write-Host "  WLANs found  : $wlanCount"              -ForegroundColor Cyan
    Write-Host "  Portal       : $PortalHtml"             -ForegroundColor Cyan
    Write-Host "  Tangle log   : $TangleLog"              -ForegroundColor Cyan
}

# =============================================================
# MAIN
# =============================================================
Ensure-Dirs

if ($RemoveTask) {
    Remove-SensorTask
    exit 0
}

if ($InstallTask -and -not $RunOnce -and -not $Loop) {
    Install-SensorTask
    exit 0
}

if ($Loop) {
    Write-Host "AVA WLAN TANGLE SENSOR: Loop mode — interval ${IntervalSeconds}s. Press Ctrl+C to stop." -ForegroundColor Green
    while ($true) {
        Invoke-SensorCycle
        Start-Sleep -Seconds $IntervalSeconds
    }
}
else {
    # -RunOnce or plain interactive run
    Invoke-SensorCycle

    if ($InstallTask) {
        Install-SensorTask
    }

    Write-Host ''
    Write-Host 'AVA WLAN TANGLE SENSOR: Cycle complete.' -ForegroundColor Green
    Write-Host ''
    Write-Host 'Kernsatz: Ich beobachte. Ich protokolliere. Ich greife nicht ein.' -ForegroundColor Yellow
    Write-Host ''
}
