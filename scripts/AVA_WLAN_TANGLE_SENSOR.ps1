#requires -RunAsAdministrator
<#
AVA WLAN TANGLE SENSOR v1 - DEFENSIVE / LOCAL / READ-ONLY
- Visible WLANs via netsh wlan show networks mode=bssid
- Local adapter data via Get-NetAdapter / Get-NetIPAddress
- LAN neighbours via Get-NetNeighbor (ARP cache)
- JSONL event log  : C:\Windows\SecurityGuardian\Logs\wlan_events.jsonl
- JSONL tangle log : C:\Windows\SecurityGuardian\Logs\wlan_tangle.jsonl
- HTML portal      : C:\Windows\SecurityGuardian\Reports\ava_wlan.html

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
    [int]$IntervalSeconds = 60,
    [switch]$InstallTask,
    [switch]$RemoveTask
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

$EventLog    = Join-Path $LogDir  'wlan_events.jsonl'
$TangleLog   = Join-Path $LogDir  'wlan_tangle.jsonl'
$TangleState = Join-Path $StateDir 'wlan_tangle_state.json'
$PortalHtml  = Join-Path $ReportDir 'ava_wlan.html'

$TaskName = 'AVA_WLAN_TANGLE_SENSOR_V1'

# =============================================================
# DIRECTORY INIT
# =============================================================
function Ensure-Dirs {
    foreach ($d in @($Root, $LogDir, $StateDir, $ReportDir)) {
        if (-not (Test-Path -LiteralPath $d)) {
            New-Item -ItemType Directory -Path $d -Force | Out-Null
        }
    }
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
        time     = (Get-Date).ToString('s')
        category = $Category
        severity = $Severity
        message  = $Message
    } -Path $EventLog
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

    $entry = [ordered]@{
        time          = (Get-Date).ToString('o')
        host          = $env:COMPUTERNAME
        user          = $env:USERNAME
        type          = $Type
        summary       = $Summary
        previous_hash = $prevHash
        data          = $Data
        hash          = ''
    }

    $raw         = $entry | ConvertTo-Json -Compress -Depth 8
    $hash        = Get-Sha256Text -Text $raw
    $entry.hash  = $hash

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
        $raw = netsh wlan show networks mode=bssid 2>&1
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

        if ($l -match '^SSID\s+\d+\s*:\s+(.+)$') {
            $currentSsid = $Matches[1]
            $currentAuth = $null
            $currentEncr = $null
        }
        elseif ($l -match '^Authentication\s*:\s+(.+)$') {
            $currentAuth = $Matches[1]
        }
        elseif ($l -match '^Encryption\s*:\s+(.+)$') {
            $currentEncr = $Matches[1]
        }
        elseif ($l -match '^BSSID\s+\d+\s*:\s+(.+)$') {
            $items.Add([pscustomobject]@{
                SSID           = $currentSsid
                BSSID          = $Matches[1]
                Authentication = $currentAuth
                Encryption     = $currentEncr
                Signal         = $null
                RadioType      = $null
            }) | Out-Null
        }
        elseif ($l -match '^Signal\s*:\s+(.+)$') {
            if ($items.Count -gt 0) {
                $items[$items.Count - 1] |
                    Add-Member -NotePropertyName Signal -NotePropertyValue $Matches[1] -Force
            }
        }
        elseif ($l -match '^Radio type\s*:\s+(.+)$') {
            if ($items.Count -gt 0) {
                $items[$items.Count - 1] |
                    Add-Member -NotePropertyName RadioType -NotePropertyValue $Matches[1] -Force
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
        $adapters = Get-NetAdapter -ErrorAction SilentlyContinue |
            Where-Object { $_.Status -eq 'Up' } |
            ForEach-Object {
                $adp = $_
                $ips = @(Get-NetIPAddress -InterfaceIndex $adp.ifIndex -ErrorAction SilentlyContinue |
                    Select-Object -ExpandProperty IPAddress)
                [ordered]@{
                    Name        = $adp.Name
                    Description = $adp.InterfaceDescription
                    MacAddress  = $adp.MacAddress
                    LinkSpeed   = $adp.LinkSpeed
                    IPAddresses = $ips
                }
            }
    }
    catch {
        $adapters = @(@{ Error = $_.Exception.Message })
    }

    $neighbours = @()
    try {
        $neighbours = @(Get-NetNeighbor -ErrorAction SilentlyContinue |
            Where-Object { $_.State -ne 'Unreachable' } |
            Select-Object -Property IPAddress, LinkLayerAddress, State, InterfaceAlias)
    }
    catch {
        $neighbours = @(@{ Error = $_.Exception.Message })
    }

    [ordered]@{
        time       = (Get-Date).ToString('o')
        computer   = $env:COMPUTERNAME
        user       = $env:USERNAME
        adapters   = $adapters
        neighbours = $neighbours
    }
}

# =============================================================
# HTML PORTAL
# =============================================================
function Build-HtmlPortal {
    param(
        [Parameter(Mandatory)][object[]]$WlanNetworks,
        [Parameter(Mandatory)][object]$LocalSnapshot
    )

    $generatedAt  = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $networkCount = $WlanNetworks.Count

    # WLAN table rows
    $wlanRows = foreach ($n in $WlanNetworks) {
        if ($n.PSObject.Properties.Name -contains 'Error' -or
            $n.PSObject.Properties.Name -contains 'Info') {
            $msg = if ($n.Error) { $n.Error } else { $n.Info }
            "<tr><td colspan='6' style='color:#9ca3af;font-style:italic'>$([System.Net.WebUtility]::HtmlEncode($msg))</td></tr>"
            continue
        }
        $ssid   = [System.Net.WebUtility]::HtmlEncode([string]$n.SSID)
        $bssid  = [System.Net.WebUtility]::HtmlEncode([string]$n.BSSID)
        $auth   = [System.Net.WebUtility]::HtmlEncode([string]$n.Authentication)
        $encr   = [System.Net.WebUtility]::HtmlEncode([string]$n.Encryption)
        $sig    = [System.Net.WebUtility]::HtmlEncode([string]$n.Signal)
        $radio  = [System.Net.WebUtility]::HtmlEncode([string]$n.RadioType)
        "<tr><td>$ssid</td><td>$bssid</td><td>$auth</td><td>$encr</td><td>$sig</td><td>$radio</td></tr>"
    }

    # Adapter rows
    $adapterRows = foreach ($a in $LocalSnapshot.adapters) {
        if ($a.ContainsKey('Error')) {
            "<tr><td colspan='5' style='color:#9ca3af;font-style:italic'>$([System.Net.WebUtility]::HtmlEncode($a.Error))</td></tr>"
            continue
        }
        $name  = [System.Net.WebUtility]::HtmlEncode([string]$a.Name)
        $desc  = [System.Net.WebUtility]::HtmlEncode([string]$a.Description)
        $mac   = [System.Net.WebUtility]::HtmlEncode([string]$a.MacAddress)
        $speed = [System.Net.WebUtility]::HtmlEncode([string]$a.LinkSpeed)
        $ips   = [System.Net.WebUtility]::HtmlEncode(($a.IPAddresses -join ', '))
        "<tr><td>$name</td><td>$desc</td><td>$mac</td><td>$speed</td><td>$ips</td></tr>"
    }

    # Neighbour rows
    $neighbourRows = foreach ($nb in $LocalSnapshot.neighbours) {
        if ($nb -is [hashtable] -and $nb.ContainsKey('Error')) {
            "<tr><td colspan='4' style='color:#9ca3af;font-style:italic'>$([System.Net.WebUtility]::HtmlEncode($nb.Error))</td></tr>"
            continue
        }
        $ip    = [System.Net.WebUtility]::HtmlEncode([string]$nb.IPAddress)
        $mac   = [System.Net.WebUtility]::HtmlEncode([string]$nb.LinkLayerAddress)
        $state = [System.Net.WebUtility]::HtmlEncode([string]$nb.State)
        $iface = [System.Net.WebUtility]::HtmlEncode([string]$nb.InterfaceAlias)
        "<tr><td>$ip</td><td>$mac</td><td>$state</td><td>$iface</td></tr>"
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
    .no-data { color: #6b7280; font-style: italic; padding: 12px 0; }
    footer { margin-top: 40px; font-size: 0.75rem; color: #4b5563; border-top: 1px solid #374151; padding-top: 12px; }
  </style>
</head>
<body>

<h1>&#x1F4F6; AVA WLAN TANGLE SENSOR &#x1F6E1;</h1>
<div class="subtitle">
  Generated: $generatedAt &nbsp;|&nbsp;
  Host: $([System.Net.WebUtility]::HtmlEncode($env:COMPUTERNAME)) &nbsp;|&nbsp;
  User: $([System.Net.WebUtility]::HtmlEncode($env:USERNAME))
</div>

<div class="stats">
  <div class="stat-card">
    <div class="stat-number">$networkCount</div>
    <div class="stat-label">Visible WLANs</div>
  </div>
  <div class="stat-card">
    <div class="stat-number">$($LocalSnapshot.adapters.Count)</div>
    <div class="stat-label">Active Adapters</div>
  </div>
  <div class="stat-card">
    <div class="stat-number">$($LocalSnapshot.neighbours.Count)</div>
    <div class="stat-label">ARP Neighbours</div>
  </div>
</div>

<h2>&#x1F4E1; Visible WLAN Networks</h2>
$(if ($wlanRows) {
    "<table><thead><tr><th>SSID</th><th>BSSID</th><th>Authentication</th><th>Encryption</th><th>Signal</th><th>Radio Type</th></tr></thead><tbody>$($wlanRows -join '')</tbody></table>"
} else {
    "<p class='no-data'>No WLAN data available.</p>"
})

<h2>&#x1F5A7; Local Adapters</h2>
$(if ($adapterRows) {
    "<table><thead><tr><th>Name</th><th>Description</th><th>MAC</th><th>Speed</th><th>IP Addresses</th></tr></thead><tbody>$($adapterRows -join '')</tbody></table>"
} else {
    "<p class='no-data'>No active adapters found.</p>"
})

<h2>&#x1F4CB; LAN Neighbours (ARP Cache)</h2>
$(if ($neighbourRows) {
    "<table><thead><tr><th>IP Address</th><th>MAC / Link-Layer</th><th>State</th><th>Interface</th></tr></thead><tbody>$($neighbourRows -join '')</tbody></table>"
} else {
    "<p class='no-data'>No neighbour entries found.</p>"
})

<footer>
  AVA WLAN TANGLE SENSOR v1 &mdash; Defensive / Read-Only / Local &mdash;
  Tangle log: $([System.Net.WebUtility]::HtmlEncode($TangleLog)) &mdash;
  Events: $([System.Net.WebUtility]::HtmlEncode($EventLog))
</footer>

</body>
</html>
"@

    Set-Content -Path $PortalHtml -Value $html -Encoding UTF8
    Write-EventEntry -Category 'portal' -Message "HTML portal written: $PortalHtml"
}

# =============================================================
# SCHEDULED TASK MANAGEMENT
# =============================================================
function Install-SensorTask {
    if (-not $PSCommandPath) {
        throw 'PSCommandPath is empty. The script must be saved as a .ps1 file and run with -File.'
    }

    $action = New-ScheduledTaskAction `
        -Execute  'powershell.exe' `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -RunOnce"

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
    $summary       = "WLANs=$wlanCount adapters=$($localSnapshot.adapters.Count) neighbours=$($localSnapshot.neighbours.Count)"

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
