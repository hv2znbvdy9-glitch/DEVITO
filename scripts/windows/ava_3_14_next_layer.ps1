#requires -RunAsAdministrator
<#
AVA 3.14 NEXT LAYER — ALL
LOCAL DEFENSIVE VISIBILITY SYSTEM

Defensiv / Lokal / Read-Only
- Angriff
- Exploit
- Fremdscan
- Deauth
- Cracken
- Payload
- offensive Automatisierung

Funktionen:
- SOC Snapshot
- Defender / Firewall / Prozesse / Dienste / Admins / Tasks
- Netzwerk TCP / WLAN / LAN Nachbarn
- Baseline + Delta
- Risk Score
- Alert JSONL
- Tangle Hash Chain
- HTML HUD Portal
- Optional Scheduled Task
#>

[CmdletBinding()]
param(
    [switch]$RunOnce,
    [switch]$Loop,
    [switch]$InstallTask,
    [switch]$RemoveTask,
    [switch]$ResetBaseline,
    [int]$IntervalSeconds = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# =========================
# CONFIG
# =========================

$Root       = "C:\Windows\SecurityGuardian"
$LogDir     = Join-Path $Root "Logs"
$StateDir   = Join-Path $Root "State"
$ReportDir  = Join-Path $Root "Reports"
$PortalDir  = Join-Path $Root "Portal"

$TaskName   = "AVA_3_14_NEXT_LAYER_ALL"
$ScriptPath = $PSCommandPath

$EventLog     = Join-Path $LogDir "ava_3_14_events.jsonl"
$AlertLog     = Join-Path $LogDir "ava_3_14_alerts.jsonl"
$TangleLog    = Join-Path $LogDir "ava_3_14_tangle.jsonl"
$TangleState  = Join-Path $StateDir "ava_3_14_tangle_state.json"
$BaselinePath = Join-Path $StateDir "ava_3_14_baseline.json"
$PortalHtml   = Join-Path $PortalDir "index.html"
$SnapshotJson = Join-Path $ReportDir "ava_3_14_latest_snapshot.json"
$AnalysisJson = Join-Path $ReportDir "ava_3_14_latest_analysis.json"

$RiskPorts = @(21,23,135,139,445,3389,5985,5986)

$SuspiciousCmdPatterns = @(
    "-enc",
    "encodedcommand",
    "downloadstring",
    "invoke-expression",
    "iex ",
    "-nop",
    "noprofile",
    "-w hidden",
    "windowstyle hidden",
    "executionpolicy bypass",
    "-ep bypass",
    "frombase64string",
    "bitsadmin",
    "certutil",
    "mshta"
)

# =========================
# HELPERS
# =========================

function Ensure-Dirs {
    foreach ($d in @($Root, $LogDir, $StateDir, $ReportDir, $PortalDir)) {
        if (-not (Test-Path -LiteralPath $d)) {
            New-Item -ItemType Directory -Path $d -Force | Out-Null
        }
    }
}

function HtmlEncode {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return "" }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Sha256Text {
    param([Parameter(Mandatory)][string]$Text)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") }) -join "")
}

function Write-JsonLine {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][object]$Object
    )

    $Object | ConvertTo-Json -Depth 40 -Compress |
        Add-Content -LiteralPath $Path -Encoding UTF8
}

function Rotate-LogIfLarge {
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$MaxMB = 25
    )

    if (Test-Path -LiteralPath $Path) {
        $file = Get-Item -LiteralPath $Path
        if ($file.Length -gt ($MaxMB * 1MB)) {
            $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
            Rename-Item -LiteralPath $Path -NewName "$($file.BaseName)_$stamp$($file.Extension)" -Force
        }
    }
}

function Write-Tangle {
    param(
        [Parameter(Mandatory)][string]$Type,
        [Parameter(Mandatory)][string]$Summary,
        [Parameter(Mandatory)][object]$Data
    )

    $prev = $null

    if (Test-Path -LiteralPath $TangleState) {
        try {
            $prev = (Get-Content -LiteralPath $TangleState -Raw | ConvertFrom-Json).last_hash
        } catch {
            $prev = $null
        }
    }

    $tangleEvent = [ordered]@{
        time          = (Get-Date).ToString("o")
        host          = $env:COMPUTERNAME
        user          = $env:USERNAME
        type          = $Type
        summary       = $Summary
        previous_hash = $prev
        data          = $Data
    }

    $raw = $tangleEvent | ConvertTo-Json -Depth 40 -Compress
    $hash = Sha256Text -Text $raw
    $tangleEvent["hash"] = $hash

    Write-JsonLine -Path $TangleLog -Object $tangleEvent

    [ordered]@{
        updated   = (Get-Date).ToString("o")
        last_hash = $hash
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $TangleState -Encoding UTF8
}

function Add-Alert {
    param(
        [Parameter(Mandatory)][string]$Severity,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Message,
        [Parameter(Mandatory)][int]$Score,
        [AllowNull()][object]$Data
    )

    [ordered]@{
        time     = (Get-Date).ToString("o")
        severity = $Severity
        title    = $Title
        message  = $Message
        score    = $Score
        data     = $Data
    }
}

# =========================
# COLLECTORS
# =========================

function Get-DefenderSafe {
    try {
        Get-MpComputerStatus | Select-Object `
            AMServiceEnabled,
            AntivirusEnabled,
            AntispywareEnabled,
            BehaviorMonitorEnabled,
            RealTimeProtectionEnabled,
            IoavProtectionEnabled,
            NISEnabled,
            OnAccessProtectionEnabled,
            AntivirusSignatureLastUpdated,
            QuickScanEndTime,
            FullScanEndTime
    } catch {
        [pscustomobject]@{ Error = $_.Exception.Message }
    }
}

function Get-FirewallSafe {
    try {
        Get-NetFirewallProfile |
            Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
    } catch {
        @([pscustomobject]@{ Error = $_.Exception.Message })
    }
}

function Get-AdminsSafe {
    try {
        Get-LocalGroupMember -Group "Administrators" |
            Select-Object Name, ObjectClass, PrincipalSource
    } catch {
        @([pscustomobject]@{ Error = $_.Exception.Message })
    }
}

function Get-TasksSafe {
    try {
        Get-ScheduledTask |
            Where-Object { $_.TaskPath -notlike "\Microsoft*" } |
            Select-Object TaskName, TaskPath, State
    } catch {
        @([pscustomobject]@{ Error = $_.Exception.Message })
    }
}

function Get-ServicesSafe {
    try {
        Get-CimInstance Win32_Service |
            Where-Object { $_.State -eq "Running" } |
            Select-Object Name, DisplayName, State, StartMode, StartName, PathName
    } catch {
        @([pscustomobject]@{ Error = $_.Exception.Message })
    }
}

function Get-ProcessesSafe {
    try {
        Get-CimInstance Win32_Process |
            Select-Object ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine
    } catch {
        @([pscustomobject]@{ Error = $_.Exception.Message })
    }
}

function Get-ConnectionsSafe {
    try {
        $procMap = @{}
        Get-Process | ForEach-Object {
            $procMap[$_.Id] = $_.ProcessName
        }

        Get-NetTCPConnection -State Established |
            ForEach-Object {
                [pscustomobject]@{
                    LocalAddress  = $_.LocalAddress
                    LocalPort     = $_.LocalPort
                    RemoteAddress = $_.RemoteAddress
                    RemotePort    = $_.RemotePort
                    State         = $_.State
                    PID           = $_.OwningProcess
                    Process       = $procMap[$_.OwningProcess]
                }
            }
    } catch {
        @([pscustomobject]@{ Error = $_.Exception.Message })
    }
}

function Get-WlanNetworksSafe {
    try {
        $raw = netsh wlan show networks mode=bssid 2>&1 | Out-String
    } catch {
        return @([pscustomobject]@{ Error = $_.Exception.Message })
    }

    $items = New-Object System.Collections.Generic.List[object]

    $ssid = $null
    $auth = $null
    $enc  = $null

    foreach ($line in ($raw -split "`r?`n")) {
        $l = $line.Trim()

        if ($l -match "^SSID\s+\d+\s+:\s+(.*)$") {
            $ssid = $Matches[1]
            $auth = $null
            $enc = $null
        }
        elseif ($l -match "^Authentication\s+:\s+(.*)$") {
            $auth = $Matches[1]
        }
        elseif ($l -match "^Encryption\s+:\s+(.*)$") {
            $enc = $Matches[1]
        }
        elseif ($l -match "^BSSID\s+\d+\s+:\s+(.*)$") {
            $items.Add([pscustomobject]@{
                SSID           = $ssid
                BSSID          = $Matches[1]
                Authentication = $auth
                Encryption     = $enc
                Signal         = $null
                RadioType      = $null
                Channel        = $null
            }) | Out-Null
        }
        elseif ($l -match "^Signal\s+:\s+(.*)$") {
            if ($items.Count -gt 0) { $items[$items.Count - 1].Signal = $Matches[1] }
        }
        elseif ($l -match "^Radio type\s+:\s+(.*)$") {
            if ($items.Count -gt 0) { $items[$items.Count - 1].RadioType = $Matches[1] }
        }
        elseif ($l -match "^Channel\s+:\s+(.*)$") {
            if ($items.Count -gt 0) { $items[$items.Count - 1].Channel = $Matches[1] }
        }
    }

    return $items
}

function Get-NetworkLocalSafe {
    $adapters = try {
        Get-NetAdapter |
            Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed
    } catch {
        @([pscustomobject]@{ Error = $_.Exception.Message })
    }

    $ipconfig = try {
        Get-NetIPConfiguration |
            Select-Object InterfaceAlias, IPv4Address, IPv6Address, IPv4DefaultGateway, DNSServer
    } catch {
        @([pscustomobject]@{ Error = $_.Exception.Message })
    }

    $neighbors = try {
        Get-NetNeighbor -AddressFamily IPv4 |
            Where-Object { $_.State -ne "Unreachable" } |
            Select-Object InterfaceAlias, IPAddress, LinkLayerAddress, State
    } catch {
        @([pscustomobject]@{ Error = $_.Exception.Message })
    }

    [ordered]@{
        adapters  = $adapters
        ipconfig  = $ipconfig
        neighbors = $neighbors
    }
}

function New-Snapshot {
    [ordered]@{
        time        = (Get-Date).ToString("o")
        computer    = $env:COMPUTERNAME
        user        = $env:USERNAME
        mode        = "LOCAL_DEFENSIVE_READ_ONLY"
        defender    = Get-DefenderSafe
        firewall    = Get-FirewallSafe
        admins      = Get-AdminsSafe
        tasks       = Get-TasksSafe
        services    = Get-ServicesSafe
        processes   = Get-ProcessesSafe
        connections = Get-ConnectionsSafe
        network     = Get-NetworkLocalSafe
        wlan        = Get-WlanNetworksSafe
    }
}

# =========================
# BASELINE / ANALYSIS
# =========================

function Load-Baseline {
    if (Test-Path -LiteralPath $BaselinePath) {
        try {
            return Get-Content -LiteralPath $BaselinePath -Raw | ConvertFrom-Json
        } catch {
            return $null
        }
    }

    return $null
}

function Save-Baseline {
    param([Parameter(Mandatory)][object]$Snapshot)

    $Snapshot |
        ConvertTo-Json -Depth 40 |
        Set-Content -LiteralPath $BaselinePath -Encoding UTF8
}

function Analyze-Snapshot {
    param([Parameter(Mandatory)][object]$Snapshot)

    $alerts = New-Object System.Collections.Generic.List[object]
    $score = 0

    # Defender
    if ($Snapshot.defender.PSObject.Properties.Name -contains "RealTimeProtectionEnabled") {
        if ($Snapshot.defender.RealTimeProtectionEnabled -eq $false) {
            $score += 100
            $alerts.Add((Add-Alert `
                -Severity "CRITICAL" `
                -Title "Defender Echtzeitschutz deaktiviert" `
                -Message "Windows Defender RealTimeProtectionEnabled ist FALSE." `
                -Score 100 `
                -Data $Snapshot.defender)) | Out-Null
        }
    }

    # Firewall
    foreach ($fw in @($Snapshot.firewall)) {
        if ($fw.Enabled -eq $false) {
            $score += 80
            $alerts.Add((Add-Alert `
                -Severity "HIGH" `
                -Title "Firewall Profil deaktiviert" `
                -Message "Firewall-Profil deaktiviert: $($fw.Name)" `
                -Score 80 `
                -Data $fw)) | Out-Null
        }
    }

    # Risk Ports
    foreach ($c in @($Snapshot.connections)) {
        $remotePort = $null
        if ($c.RemotePort) {
            try { $remotePort = [int]$c.RemotePort } catch { $remotePort = $null }
        }

        if ($null -ne $remotePort) {
            if ($RiskPorts -contains $remotePort) {
                $sev = "MEDIUM"
                $s = 45

                if ($remotePort -in @(445,3389,5985,5986)) {
                    $sev = "HIGH"
                    $s = 75
                }

                $score += $s
                $alerts.Add((Add-Alert `
                    -Severity $sev `
                    -Title "Risiko-Port Verbindung" `
                    -Message "Established TCP zu Risiko-Port $remotePort durch Prozess $($c.Process)." `
                    -Score $s `
                    -Data $c)) | Out-Null
            }
        }
    }

    # Suspicious command lines
    foreach ($p in @($Snapshot.processes)) {
        $cmd = ""
        if ($p.CommandLine) {
            $cmd = ([string]$p.CommandLine).ToLowerInvariant()
        }

        $procName = ""
        if ($p.Name) {
            $procName = ([string]$p.Name).ToLowerInvariant()
        }

        if ($procName -in @("powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe")) {
            $hits = @()

            foreach ($pattern in $SuspiciousCmdPatterns) {
                if ($cmd.Contains($pattern)) {
                    $hits += $pattern
                }
            }

            if ($hits.Count -gt 0) {
                $s = 85
                $score += $s
                $alerts.Add((Add-Alert `
                    -Severity "HIGH" `
                    -Title "Verdächtige Kommandozeile" `
                    -Message "Verdächtige Parameter erkannt bei $($p.Name)." `
                    -Score $s `
                    -Data ([ordered]@{
                        process = $p
                        hits    = $hits
                    }))) | Out-Null
            }
        }
    }

    # Baseline / Delta
    $baseline = Load-Baseline

    $delta = [ordered]@{
        baseline_exists = $null -ne $baseline
        new_admins      = @()
        new_neighbors   = @()
        new_wlan_bssid  = @()
        new_tasks       = @()
        new_services    = @()
    }

    if ($null -eq $baseline) {
        Save-Baseline -Snapshot $Snapshot
    } else {
        $oldAdmins = [System.Collections.Generic.HashSet[string]]::new([string[]]@($baseline.admins | ForEach-Object { $_.Name }))
        foreach ($a in @($Snapshot.admins)) {
            if ($a.Name -and (-not $oldAdmins.Contains($a.Name))) {
                $delta.new_admins += $a
                $score += 90
                $alerts.Add((Add-Alert `
                    -Severity "HIGH" `
                    -Title "Neuer lokaler Administrator" `
                    -Message "Neuer Admin seit Baseline: $($a.Name)" `
                    -Score 90 `
                    -Data $a)) | Out-Null
            }
        }

        $oldNeighbors = [System.Collections.Generic.HashSet[string]]::new([string[]]@($baseline.network.neighbors | ForEach-Object { "$($_.IPAddress)|$($_.LinkLayerAddress)" }))
        foreach ($n in @($Snapshot.network.neighbors)) {
            $key = "$($n.IPAddress)|$($n.LinkLayerAddress)"
            if ($n.IPAddress -and (-not $oldNeighbors.Contains($key))) {
                $delta.new_neighbors += $n
                $score += 25
                $alerts.Add((Add-Alert `
                    -Severity "LOW" `
                    -Title "Neuer LAN-Nachbar" `
                    -Message "Neuer Netzwerk-Nachbar seit Baseline: $($n.IPAddress) ($($n.LinkLayerAddress))" `
                    -Score 25 `
                    -Data $n)) | Out-Null
            }
        }

        $oldBssid = [System.Collections.Generic.HashSet[string]]::new([string[]]@($baseline.wlan | ForEach-Object { $_.BSSID }))
        foreach ($w in @($Snapshot.wlan)) {
            if ($w.BSSID -and (-not $oldBssid.Contains($w.BSSID))) {
                $delta.new_wlan_bssid += $w
                $score += 10
                $alerts.Add((Add-Alert `
                    -Severity "LOW" `
                    -Title "Neue WLAN-BSSID" `
                    -Message "Neue WLAN-BSSID seit Baseline: $($w.BSSID) (SSID: $($w.SSID))" `
                    -Score 10 `
                    -Data $w)) | Out-Null
            }
        }

        $oldTasks = [System.Collections.Generic.HashSet[string]]::new([string[]]@($baseline.tasks | ForEach-Object { "$($_.TaskPath)$($_.TaskName)" }))
        foreach ($t in @($Snapshot.tasks)) {
            $key = "$($t.TaskPath)$($t.TaskName)"
            if ($t.TaskName -and (-not $oldTasks.Contains($key))) {
                $delta.new_tasks += $t
                $score += 30
                $alerts.Add((Add-Alert `
                    -Severity "MEDIUM" `
                    -Title "Neue geplante Aufgabe" `
                    -Message "Neue Scheduled Task seit Baseline: $($t.TaskPath)$($t.TaskName)" `
                    -Score 30 `
                    -Data $t)) | Out-Null
            }
        }

        $oldServices = [System.Collections.Generic.HashSet[string]]::new([string[]]@($baseline.services | ForEach-Object { $_.Name }))
        foreach ($s in @($Snapshot.services)) {
            if ($s.Name -and (-not $oldServices.Contains($s.Name))) {
                $delta.new_services += $s
                $score += 20
                $alerts.Add((Add-Alert `
                    -Severity "MEDIUM" `
                    -Title "Neuer laufender Dienst" `
                    -Message "Neuer laufender Dienst seit Baseline: $($s.Name)" `
                    -Score 20 `
                    -Data $s)) | Out-Null
            }
        }
    }

    foreach ($a in @($alerts)) {
        Write-JsonLine -Path $AlertLog -Object $a
    }

    [ordered]@{
        time         = (Get-Date).ToString("o")
        score        = [Math]::Min($score, 999)
        alert_count  = @($alerts).Count
        alerts       = $alerts
        delta        = $delta
        principles   = "LOCAL / DEFENSIVE / READ-ONLY"
        core_sentence = "Fakten vor Angst. Baseline vor Chaos. Sichtbarkeit vor Kontrolle."
    }
}

# =========================
# HTML PORTAL
# =========================

function Make-Rows {
    param(
        [AllowNull()][object[]]$Items,
        [Parameter(Mandatory)][string[]]$Props
    )

    foreach ($item in @($Items)) {
        $tds = foreach ($p in $Props) {
            "<td>$(HtmlEncode $item.$p)</td>"
        }

        "<tr>$($tds -join '')</tr>"
    }
}

function New-Portal {
    param(
        [Parameter(Mandatory)][object]$Snapshot,
        [Parameter(Mandatory)][object]$Analysis
    )

    $score = [int]$Analysis.score
    $health = "OK"

    if ($score -ge 150) { $health = "WARN" }
    if ($score -ge 300) { $health = "HIGH" }
    if ($score -ge 500) { $health = "CRITICAL" }

    $lastHash = "N/A"
    if (Test-Path -LiteralPath $TangleState) {
        try {
            $lastHash = (Get-Content -LiteralPath $TangleState -Raw | ConvertFrom-Json).last_hash
        } catch {
            $lastHash = "N/A"
        }
    }

    $alertRows = foreach ($a in @($Analysis.alerts | Sort-Object score -Descending | Select-Object -First 50)) {
        "<tr><td>$(HtmlEncode $a.severity)</td><td>$(HtmlEncode $a.title)</td><td>$(HtmlEncode $a.message)</td><td>$(HtmlEncode $a.score)</td><td>$(HtmlEncode $a.time)</td></tr>"
    }

    $connRows     = Make-Rows -Items (@($Snapshot.connections) | Select-Object -First 100) -Props @("Process","PID","LocalAddress","LocalPort","RemoteAddress","RemotePort","State")
    $procRows     = Make-Rows -Items (@($Snapshot.processes) | Select-Object -First 100) -Props @("Name","ProcessId","ParentProcessId","ExecutablePath","CommandLine")
    $wlanRows     = Make-Rows -Items (@($Snapshot.wlan) | Select-Object -First 100) -Props @("SSID","BSSID","Authentication","Encryption","Signal","RadioType","Channel")
    $neighborRows = Make-Rows -Items (@($Snapshot.network.neighbors) | Select-Object -First 100) -Props @("InterfaceAlias","IPAddress","LinkLayerAddress","State")
    $adminRows    = Make-Rows -Items (@($Snapshot.admins)) -Props @("Name","ObjectClass","PrincipalSource")
    $taskRows     = Make-Rows -Items (@($Snapshot.tasks) | Select-Object -First 100) -Props @("TaskName","TaskPath","State")
    $serviceRows  = Make-Rows -Items (@($Snapshot.services) | Select-Object -First 100) -Props @("Name","DisplayName","State","StartMode","StartName")
    $fwRows       = Make-Rows -Items (@($Snapshot.firewall)) -Props @("Name","Enabled","DefaultInboundAction","DefaultOutboundAction")

    $html = @"
<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="UTF-8" />
<title>AVA 3.14 NEXT LAYER — SOC HUD</title>
<style>
  body { background:#0b0f14; color:#d7e3ea; font-family:Consolas,monospace; margin:0; padding:20px; }
  h1 { color:#7fd1ff; }
  h2 { color:#9fe3a4; border-bottom:1px solid #24313c; padding-bottom:4px; }
  table { width:100%; border-collapse:collapse; margin-bottom:24px; font-size:12px; }
  th, td { border:1px solid #24313c; padding:4px 8px; text-align:left; word-break:break-all; }
  th { background:#101823; color:#7fd1ff; }
  tr:nth-child(even) { background:#0e1520; }
  .health-OK { color:#9fe3a4; }
  .health-WARN { color:#f0d264; }
  .health-HIGH { color:#f0a464; }
  .health-CRITICAL { color:#ff6b6b; }
  .badge { display:inline-block; padding:2px 10px; border-radius:4px; background:#1a2733; }
  .footer { color:#5b6b78; margin-top:30px; font-size:12px; }
</style>
</head>
<body>
<h1>AVA 3.14 NEXT LAYER — LOCAL DEFENSIVE VISIBILITY</h1>
<p>
  <span class="badge">Host: $(HtmlEncode $Snapshot.computer)</span>
  <span class="badge">User: $(HtmlEncode $Snapshot.user)</span>
  <span class="badge">Zeit: $(HtmlEncode $Snapshot.time)</span>
  <span class="badge health-$health">Health: $health (Score $score)</span>
  <span class="badge">Alerts: $(HtmlEncode $Analysis.alert_count)</span>
</p>
<p>Tangle Hash Chain (letzter Hash): <code>$(HtmlEncode $lastHash)</code></p>
<p><em>$(HtmlEncode $Analysis.principles) — $(HtmlEncode $Analysis.core_sentence)</em></p>

<h2>Alerts</h2>
<table>
<tr><th>Severity</th><th>Title</th><th>Message</th><th>Score</th><th>Time</th></tr>
$($alertRows -join "`n")
</table>

<h2>Defender</h2>
<pre>$(HtmlEncode ($Snapshot.defender | ConvertTo-Json -Depth 10))</pre>

<h2>Firewall</h2>
<table>
<tr><th>Name</th><th>Enabled</th><th>Inbound</th><th>Outbound</th></tr>
$($fwRows -join "`n")
</table>

<h2>Lokale Administratoren</h2>
<table>
<tr><th>Name</th><th>ObjectClass</th><th>PrincipalSource</th></tr>
$($adminRows -join "`n")
</table>

<h2>Geplante Aufgaben (non-Microsoft)</h2>
<table>
<tr><th>TaskName</th><th>TaskPath</th><th>State</th></tr>
$($taskRows -join "`n")
</table>

<h2>Laufende Dienste</h2>
<table>
<tr><th>Name</th><th>DisplayName</th><th>State</th><th>StartMode</th><th>StartName</th></tr>
$($serviceRows -join "`n")
</table>

<h2>Prozesse</h2>
<table>
<tr><th>Name</th><th>PID</th><th>PPID</th><th>Pfad</th><th>Kommandozeile</th></tr>
$($procRows -join "`n")
</table>

<h2>TCP Verbindungen (Established)</h2>
<table>
<tr><th>Process</th><th>PID</th><th>Local</th><th>LocalPort</th><th>Remote</th><th>RemotePort</th><th>State</th></tr>
$($connRows -join "`n")
</table>

<h2>WLAN Netzwerke</h2>
<table>
<tr><th>SSID</th><th>BSSID</th><th>Auth</th><th>Encryption</th><th>Signal</th><th>RadioType</th><th>Channel</th></tr>
$($wlanRows -join "`n")
</table>

<h2>LAN Nachbarn</h2>
<table>
<tr><th>Interface</th><th>IPAddress</th><th>MAC</th><th>State</th></tr>
$($neighborRows -join "`n")
</table>

<div class="footer">
AVA 3.14 NEXT LAYER — ALL &middot; Defensiv / Lokal / Read-Only &middot; Generiert: $(HtmlEncode ((Get-Date).ToString("o")))
</div>
</body>
</html>
"@

    Set-Content -LiteralPath $PortalHtml -Value $html -Encoding UTF8
}

# =========================
# SCHEDULED TASK
# =========================

function Install-AvaTask {
    if ($IntervalSeconds -lt 60) {
        throw "IntervalSeconds muss mindestens 60 sein (New-ScheduledTaskTrigger -RepetitionInterval Minimum: 1 Minute). Aktueller Wert: $IntervalSeconds"
    }

    $action = New-ScheduledTaskAction -Execute "powershell.exe" `
        -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -RunOnce"

    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
        -RepetitionInterval (New-TimeSpan -Seconds $IntervalSeconds) `
        -RepetitionDuration ([TimeSpan]::MaxValue)

    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Force | Out-Null

    Write-Host "[AVA 3.14] Scheduled Task '$TaskName' installiert (Intervall: $IntervalSeconds Sekunden)." -ForegroundColor Green
}

function Remove-AvaTask {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "[AVA 3.14] Scheduled Task '$TaskName' entfernt." -ForegroundColor Yellow
    } else {
        Write-Host "[AVA 3.14] Scheduled Task '$TaskName' existiert nicht." -ForegroundColor Yellow
    }
}

# =========================
# ORCHESTRATION
# =========================

function Invoke-AvaCycle {
    Ensure-Dirs

    Rotate-LogIfLarge -Path $EventLog
    Rotate-LogIfLarge -Path $AlertLog
    Rotate-LogIfLarge -Path $TangleLog

    $snapshot = New-Snapshot
    $analysis = Analyze-Snapshot -Snapshot $snapshot

    $snapshot | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath $SnapshotJson -Encoding UTF8
    $analysis | ConvertTo-Json -Depth 40 | Set-Content -LiteralPath $AnalysisJson -Encoding UTF8

    Write-JsonLine -Path $EventLog -Object ([ordered]@{
        time  = (Get-Date).ToString("o")
        type  = "snapshot"
        score = $analysis.score
    })

    Write-Tangle -Type "snapshot_analysis" -Summary "Score=$($analysis.score) Alerts=$($analysis.alert_count)" -Data ([ordered]@{
        score       = $analysis.score
        alert_count = $analysis.alert_count
    })

    New-Portal -Snapshot $snapshot -Analysis $analysis

    Write-Host "[AVA 3.14] Zyklus abgeschlossen. Score=$($analysis.score) Alerts=$($analysis.alert_count) Portal=$PortalHtml" -ForegroundColor Cyan
}

# =========================
# MAIN
# =========================

Ensure-Dirs

if ($ResetBaseline) {
    if (Test-Path -LiteralPath $BaselinePath) {
        Remove-Item -LiteralPath $BaselinePath -Force
    }
    Write-Host "[AVA 3.14] Baseline zurückgesetzt." -ForegroundColor Yellow
}

if ($InstallTask) {
    Install-AvaTask
}

if ($RemoveTask) {
    Remove-AvaTask
}

if ($Loop) {
    Write-Host "[AVA 3.14] Loop-Modus gestartet (Intervall: $IntervalSeconds Sekunden). STRG+C zum Beenden." -ForegroundColor Cyan
    while ($true) {
        try {
            Invoke-AvaCycle
        } catch {
            Write-Warning "[AVA 3.14] Zyklus fehlgeschlagen: $($_.Exception.Message)"
        }
        Start-Sleep -Seconds $IntervalSeconds
    }
} elseif ($RunOnce -or (-not $InstallTask -and -not $RemoveTask -and -not $ResetBaseline)) {
    Invoke-AvaCycle
}
