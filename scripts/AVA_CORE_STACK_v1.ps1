<#
AVA SAFE STANDARD (V6)
Lokal / Defensiv / Read-Only
Keine Angriffe / Keine Exploits / Keine Fremdscans / Keine automatische Ausbreitung / Keine Änderungen am System
#>

#requires -RunAsAdministrator
<#
AVA CORE STACK v1
Defensiv / Lokal / Read-Only
Windows Defender Telemetrie
PowerShell Prozessanalyse
Netzwerk TCP/UDP
Baseline + Delta Engine
Event-/Alert-Tangle
HTML Portal
Optional: Nmap Inventarisierung nur wenn installiert
#>

[CmdletBinding()]
param(
    [switch]$RunOnce,
    [switch]$CreateBaseline,
    [switch]$OpenPortal
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$Root      = 'C:\Windows\SecurityGuardian'
$LogDir    = Join-Path $Root 'Logs'
$StateDir  = Join-Path $Root 'State'
$ReportDir = Join-Path $Root 'Reports'

$EventLog     = Join-Path $LogDir 'events_tangle.jsonl'
$AlertLog     = Join-Path $LogDir 'alerts.jsonl'
$BaselineFile = Join-Path $StateDir 'baseline_core.json'
$TangleState  = Join-Path $StateDir 'tangle_state.json'
$IntegrityFile = Join-Path $StateDir 'ava_integrity_baseline.json'
$PortalFile   = Join-Path $ReportDir 'ava_core_portal.html'
$GraphFile    = Join-Path $ReportDir 'ava_core_graph.json'
$MaxTcpDisplayRows = 50
$TrendDays = 7

foreach ($d in @($Root, $LogDir, $StateDir, $ReportDir)) {
    New-Item -ItemType Directory -Force -Path $d | Out-Null
}

function HtmlEncode {
    param($v)
    if ($null -eq $v) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$v)
}

function Sha256Text {
    param([string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Text)
        $hash = $sha.ComputeHash($bytes)
        return (($hash | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally {
        $sha.Dispose()
    }
}

function Get-LastTangleHash {
    if (Test-Path -LiteralPath $TangleState) {
        try {
            return (Get-Content -Path $TangleState -Raw | ConvertFrom-Json).last_hash
        }
        catch {}
    }
    return 'GENESIS'
}

function Write-TangleEvent {
    param(
        [Parameter(Mandatory)][string]$Type,
        [string]$Severity = 'INFO',
        [Parameter(Mandatory)][string]$Message,
        [hashtable]$Data = @{}
    )

    $prev = Get-LastTangleHash
    $obj = [ordered]@{
        time          = (Get-Date).ToString('s')
        computer      = $env:COMPUTERNAME
        user          = $env:USERNAME
        type          = $Type
        severity      = $Severity
        message       = $Message
        data          = $Data
        previous_hash = $prev
    }

    $raw = $obj | ConvertTo-Json -Depth 8 -Compress
    $hash = Sha256Text -Text $raw
    $obj.hash = $hash

    ($obj | ConvertTo-Json -Depth 8 -Compress) | Add-Content -Path $EventLog -Encoding UTF8
    (@{ last_hash = $hash; updated = (Get-Date).ToString('s') } | ConvertTo-Json) |
        Set-Content -Path $TangleState -Encoding UTF8

    if ($Severity -in @('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')) {
        ($obj | ConvertTo-Json -Depth 8 -Compress) | Add-Content -Path $AlertLog -Encoding UTF8
    }
}

function Read-JsonLines {
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$Tail = 2000
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return @()
    }

    return @(
        Get-Content -Path $Path -Tail $Tail -ErrorAction SilentlyContinue |
            ForEach-Object {
                try {
                    $_ | ConvertFrom-Json -ErrorAction Stop
                }
                catch {
                    $null
                }
            } |
            Where-Object { $_ -ne $null }
    )
}

function ConvertTo-DateSafe {
    param([object]$Value)
    if ($null -eq $Value) { return $null }

    try {
        return [DateTime]::Parse([string]$Value)
    }
    catch {
        return $null
    }
}

function Get-RemoteIpReputation {
    param([string]$Address)

    if ([string]::IsNullOrWhiteSpace($Address)) {
        return [ordered]@{ class = 'UNKNOWN'; note = 'Keine Adresse' }
    }

    $trimmed = $Address.Trim()
    if ($trimmed -in @('127.0.0.1', '::1', '0.0.0.0', '::')) {
        return [ordered]@{ class = 'LOOPBACK'; note = 'Loopback/Localhost' }
    }

    if ($trimmed -match '^fe80:' -or $trimmed -match '^fc' -or $trimmed -match '^fd') {
        return [ordered]@{ class = 'PRIVATE'; note = 'IPv6 lokal/ULA' }
    }

    if ($trimmed -match '^10\.' -or
        $trimmed -match '^192\.168\.' -or
        $trimmed -match '^172\.(1[6-9]|2[0-9]|3[0-1])\.') {
        return [ordered]@{ class = 'PRIVATE'; note = 'RFC1918 privat' }
    }

    if ($trimmed -match '^169\.254\.') {
        return [ordered]@{ class = 'LINK_LOCAL'; note = 'APIPA / Link-Local' }
    }

    $ipObj = $null
    if (-not [System.Net.IPAddress]::TryParse($trimmed, [ref]$ipObj)) {
        return [ordered]@{ class = 'UNPARSEABLE'; note = 'Nicht als IP interpretierbar' }
    }

    return [ordered]@{ class = 'PUBLIC_UNKNOWN'; note = 'Öffentliche IP (nur Einordnung, kein Lookup)' }
}

function Get-DefenderInfo {
    try {
        $mp = Get-MpComputerStatus
        return [ordered]@{
            available           = $true
            realtime_protection = $mp.RealTimeProtectionEnabled
            antivirus_enabled   = $mp.AntivirusEnabled
            antispyware_enabled = $mp.AntispywareEnabled
            signature_age       = $mp.AntivirusSignatureAge
            last_quick_scan     = $mp.QuickScanEndTime
            last_full_scan      = $mp.FullScanEndTime
            tamper_protection   = $mp.IsTamperProtected
        }
    }
    catch {
        return [ordered]@{
            available = $false
            error     = $_.Exception.Message
        }
    }
}

function Get-PowerShellProcessInfo {
    $bad = @(
        '-enc', 'encodedcommand', '-nop', 'noprofile',
        '-w hidden', 'windowstyle hidden',
        'downloadstring', 'invoke-expression', 'iex',
        'bypass', '-ep bypass', 'frombase64string'
    )

    Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -in @('powershell.exe', 'pwsh.exe') } |
        ForEach-Object {
            $cmd = [string]$_.CommandLine
            $lower = $cmd.ToLowerInvariant()
            $hits = @($bad | Where-Object { $lower.Contains($_) })

            [ordered]@{
                pid          = $_.ProcessId
                ppid         = $_.ParentProcessId
                name         = $_.Name
                path         = $_.ExecutablePath
                command_line = $cmd
                suspicious   = ($hits.Count -gt 0)
                hits         = $hits
            }
        }
}

function Get-NetworkInfo {
    $tcp = @()
    $udp = @()

    try {
        $tcp = Get-NetTCPConnection |
            Where-Object { $_.State -eq 'Established' } |
            Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
    }
    catch {}

    try {
        $udp = Get-NetUDPEndpoint |
            Select-Object LocalAddress, LocalPort, OwningProcess
    }
    catch {}

    $procMap = @{}
    Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procMap[[int]$_.Id] = $_.ProcessName }

    $tcpOut = foreach ($c in $tcp) {
        $rep = Get-RemoteIpReputation -Address ([string]$c.RemoteAddress)
        [ordered]@{
            protocol       = 'TCP'
            local_address  = $c.LocalAddress
            local_port     = $c.LocalPort
            remote_address = $c.RemoteAddress
            remote_port    = $c.RemotePort
            remote_reputation_class = $rep.class
            remote_reputation_note  = $rep.note
            state          = $c.State
            pid            = $c.OwningProcess
            process        = $procMap[[int]$c.OwningProcess]
        }
    }

    $udpOut = foreach ($u in $udp) {
        [ordered]@{
            protocol      = 'UDP'
            local_address = $u.LocalAddress
            local_port    = $u.LocalPort
            pid           = $u.OwningProcess
            process       = $procMap[[int]$u.OwningProcess]
        }
    }

    return [ordered]@{
        tcp = @($tcpOut)
        udp = @($udpOut)
    }
}

function Get-Admins {
    try {
        $adminGroup = Get-LocalGroup | Where-Object { $_.SID.Value -eq 'S-1-5-32-544' } | Select-Object -First 1
        if ($adminGroup) {
            return Get-LocalGroupMember -Group $adminGroup.Name |
                Select-Object Name, ObjectClass, PrincipalSource
        }
    }
    catch {}

    try {
        return Get-LocalGroupMember -Group 'Administratoren' |
            Select-Object Name, ObjectClass, PrincipalSource
    }
    catch {
        try {
            return Get-LocalGroupMember -Group 'Administrators' |
                Select-Object Name, ObjectClass, PrincipalSource
        }
        catch {
            return @()
        }
    }
}

function Get-TasksLite {
    try {
        return Get-ScheduledTask |
            Where-Object {
                $_.TaskPath -notlike '\Microsoft\*' -and
                $_.TaskName -notlike 'AVA*'
            } |
            Select-Object TaskName, TaskPath, State
    }
    catch {
        return @()
    }
}

function Get-ServiceLite {
    try {
        return Get-CimInstance Win32_Service |
            Where-Object { $_.State -eq 'Running' } |
            Select-Object Name, DisplayName, State, StartMode, StartName, PathName
    }
    catch {
        return @()
    }
}

function Get-NmapInfo {
    $nmap = Get-Command nmap.exe -ErrorAction SilentlyContinue
    if (-not $nmap) {
        return [ordered]@{
            installed = $false
            note      = 'Nmap nicht gefunden. Optional installieren, falls gewünscht.'
        }
    }

    return [ordered]@{
        installed = $true
        path      = $nmap.Source
        note      = 'Nur Erkennung. Kein Scan ausgeführt.'
    }
}

function New-Snapshot {
    return [ordered]@{
        time       = (Get-Date).ToString('s')
        computer   = $env:COMPUTERNAME
        user       = $env:USERNAME
        run_once   = [bool]$RunOnce
        defender   = Get-DefenderInfo
        powershell = @(Get-PowerShellProcessInfo)
        network    = Get-NetworkInfo
        admins     = @(Get-Admins)
        tasks      = @(Get-TasksLite)
        services   = @(Get-ServiceLite)
        nmap       = Get-NmapInfo
        integrity  = Get-AvaFileIntegrity
    }
}

function Get-AvaFileIntegrity {
    $scriptRoot = Split-Path -Parent $PSCommandPath
    $patternFiles = @(
        Get-ChildItem -Path $scriptRoot -Filter 'AVA*.ps1' -File -ErrorAction SilentlyContinue
        Get-ChildItem -Path $scriptRoot -Filter 'ava*.ps1' -File -ErrorAction SilentlyContinue
    )

    $targets = @($patternFiles | Sort-Object -Property FullName -Unique)
    $currentMap = @{}
    $currentList = foreach ($f in $targets) {
        try {
            $h = (Get-FileHash -Path $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
            $currentMap[$f.FullName] = $h
            [ordered]@{ path = $f.FullName; sha256 = $h }
        }
        catch {
            [ordered]@{ path = $f.FullName; sha256 = ''; error = $_.Exception.Message }
        }
    }

    $baselineMap = @{}
    $baselineExists = $false
    if (Test-Path -LiteralPath $IntegrityFile) {
        try {
            $saved = Get-Content -Path $IntegrityFile -Raw | ConvertFrom-Json -ErrorAction Stop
            foreach ($item in @($saved.files)) {
                if ($item.path -and $item.sha256) {
                    $baselineMap[[string]$item.path] = [string]$item.sha256
                }
            }
            $baselineExists = $baselineMap.Count -gt 0
        }
        catch {}
    }

    $changed = New-Object System.Collections.Generic.List[object]
    $added = New-Object System.Collections.Generic.List[object]
    $missing = New-Object System.Collections.Generic.List[object]

    foreach ($entry in $currentList) {
        $path = [string]$entry.path
        if (-not $baselineMap.ContainsKey($path)) {
            $added.Add($entry) | Out-Null
            continue
        }

        if ($entry.sha256 -and $baselineMap[$path] -ne $entry.sha256) {
            $changed.Add([ordered]@{
                path      = $path
                old_sha256 = $baselineMap[$path]
                new_sha256 = $entry.sha256
            }) | Out-Null
        }
    }

    foreach ($k in $baselineMap.Keys) {
        if (-not $currentMap.ContainsKey($k)) {
            $missing.Add([ordered]@{ path = $k; old_sha256 = $baselineMap[$k] }) | Out-Null
        }
    }

    return [ordered]@{
        baseline_exists = $baselineExists
        checked_files   = @($currentList)
        changed         = @($changed)
        added           = @($added)
        missing         = @($missing)
    }
}

function Save-AvaFileIntegrityBaseline {
    param([object]$IntegrityState)

    [ordered]@{
        updated = (Get-Date).ToString('s')
        files   = @($IntegrityState.checked_files)
    } | ConvertTo-Json -Depth 8 | Set-Content -Path $IntegrityFile -Encoding UTF8
}

function Get-TrendData {
    $events = @(Read-JsonLines -Path $EventLog -Tail 3000)
    $alerts = @(Read-JsonLines -Path $AlertLog -Tail 3000)
    $start = (Get-Date).Date.AddDays(-1 * ($TrendDays - 1))
    $days = for ($i = 0; $i -lt $TrendDays; $i++) {
        $d = $start.AddDays($i)
        [ordered]@{
            day      = $d.ToString('yyyy-MM-dd')
            snapshots = 0
            alerts    = 0
            critical  = 0
            high      = 0
            medium    = 0
            low       = 0
        }
    }

    $dayMap = @{}
    foreach ($d in $days) {
        $dayMap[$d.day] = $d
    }

    foreach ($e in $events) {
        $dt = ConvertTo-DateSafe -Value $e.time
        if ($null -eq $dt) { continue }
        if ($dt.Date -lt $start) { continue }
        $key = $dt.ToString('yyyy-MM-dd')
        if (-not $dayMap.ContainsKey($key)) { continue }

        if ([string]$e.type -eq 'SNAPSHOT') {
            $dayMap[$key].snapshots++
        }
    }

    foreach ($a in $alerts) {
        $dt = ConvertTo-DateSafe -Value $a.time
        if ($null -eq $dt) { continue }
        if ($dt.Date -lt $start) { continue }
        $key = $dt.ToString('yyyy-MM-dd')
        if (-not $dayMap.ContainsKey($key)) { continue }

        $dayMap[$key].alerts++
        switch -Exact ([string]$a.severity) {
            'CRITICAL' { $dayMap[$key].critical++ }
            'HIGH' { $dayMap[$key].high++ }
            'MEDIUM' { $dayMap[$key].medium++ }
            'LOW' { $dayMap[$key].low++ }
            default {}
        }
    }

    return [ordered]@{
        days   = @($days)
        events = $events
        alerts = $alerts
    }
}

function Get-RiskAssessment {
    param(
        [object[]]$Alerts,
        [object]$Snapshot,
        [object]$Trend
    )

    $critical = @($Alerts | Where-Object { $_.severity -eq 'CRITICAL' }).Count
    $high = @($Alerts | Where-Object { $_.severity -eq 'HIGH' }).Count
    $medium = @($Alerts | Where-Object { $_.severity -eq 'MEDIUM' }).Count
    $low = @($Alerts | Where-Object { $_.severity -eq 'LOW' }).Count
    $suspiciousPs = @($Snapshot.powershell | Where-Object { $_.suspicious }).Count
    $publicTcp = @($Snapshot.network.tcp | Where-Object { $_.remote_reputation_class -eq 'PUBLIC_UNKNOWN' }).Count
    $trendAlerts = @($Trend.days | ForEach-Object { [int]$_.alerts })
    $trendSpike = if ($trendAlerts.Count -gt 0) { ($trendAlerts | Measure-Object -Maximum).Maximum } else { 0 }

    $score = ($critical * 35) + ($high * 20) + ($medium * 10) + ($low * 4) + ($suspiciousPs * 8) + ([Math]::Min($publicTcp, 10) * 2)
    if ($trendSpike -ge 10) { $score += 8 }
    if ($score -gt 100) { $score = 100 }

    $level = 'OK'
    if ($score -ge 85) { $level = 'CRITICAL' }
    elseif ($score -ge 65) { $level = 'HIGH' }
    elseif ($score -ge 40) { $level = 'MEDIUM' }
    elseif ($score -gt 0) { $level = 'LOW' }

    $reasons = New-Object System.Collections.Generic.List[string]
    if ($critical -gt 0) { $reasons.Add("CRITICAL Alerts: $critical") | Out-Null }
    if ($high -gt 0) { $reasons.Add("HIGH Alerts: $high") | Out-Null }
    if ($suspiciousPs -gt 0) { $reasons.Add("Verdächtige PowerShell-Prozesse: $suspiciousPs") | Out-Null }
    if ($publicTcp -gt 0) { $reasons.Add("Öffentliche Remote-IP Verbindungen: $publicTcp (nur Einordnung)") | Out-Null }
    if ($trendSpike -ge 10) { $reasons.Add("Trend-Peak der Alerts in den letzten $TrendDays Tagen: $trendSpike") | Out-Null }
    if ($reasons.Count -eq 0) { $reasons.Add('Keine relevanten Risikotreiber erkannt.') | Out-Null }

    return [ordered]@{
        score    = [int]$score
        level    = $level
        critical = $critical
        high     = $high
        medium   = $medium
        low      = $low
        reasons  = @($reasons)
    }
}

function Build-EntityGraph {
    param(
        [object]$Snapshot,
        [object[]]$Alerts,
        [object]$Trend
    )

    $nodes = @{}
    $links = New-Object System.Collections.Generic.List[object]

    function Add-GraphNode {
        param([string]$Id, [string]$Label, [string]$Type)
        if (-not $nodes.ContainsKey($Id)) {
            $nodes[$Id] = [ordered]@{ id = $Id; label = $Label; type = $Type }
        }
    }

    function Add-GraphLink {
        param([string]$Source, [string]$Target, [string]$Relation)
        $links.Add([ordered]@{ source = $Source; target = $Target; relation = $Relation }) | Out-Null
    }

    $hostId = "host:$($Snapshot.computer)"
    Add-GraphNode -Id $hostId -Label $Snapshot.computer -Type 'host'

    foreach ($p in $Snapshot.powershell) {
        $procId = "process:$($p.pid)"
        Add-GraphNode -Id $procId -Label "$($p.name)#$($p.pid)" -Type 'process'
        Add-GraphLink -Source $hostId -Target $procId -Relation 'runs'

        if ($p.ppid) {
            $parentId = "process:$($p.ppid)"
            Add-GraphNode -Id $parentId -Label "Parent#$($p.ppid)" -Type 'process_parent'
            Add-GraphLink -Source $parentId -Target $procId -Relation 'parent_child'
        }
    }

    foreach ($c in $Snapshot.network.tcp) {
        $procId = "process:$($c.pid)"
        $netId = "network:$($c.remote_address):$($c.remote_port)"
        Add-GraphNode -Id $netId -Label "$($c.remote_address):$($c.remote_port)" -Type 'network'
        Add-GraphLink -Source $procId -Target $netId -Relation 'connects_to'
    }

    $recentEvents = @($Trend.events | Select-Object -Last 80)
    foreach ($e in $recentEvents) {
        $memoryId = "memory:$($e.hash)"
        Add-GraphNode -Id $memoryId -Label "$($e.type)@$($e.time)" -Type 'ava_memory'
        Add-GraphLink -Source $hostId -Target $memoryId -Relation 'records'

        if ($e.previous_hash) {
            $prevId = "memory:$($e.previous_hash)"
            Add-GraphNode -Id $prevId -Label "prev:$($e.previous_hash)" -Type 'ava_memory'
            Add-GraphLink -Source $prevId -Target $memoryId -Relation 'hash_chain'
        }
    }

    foreach ($a in $Alerts) {
        $alertId = "alert:$($a.type):$($a.message)"
        Add-GraphNode -Id $alertId -Label "$($a.type)" -Type 'alert'
        Add-GraphLink -Source $hostId -Target $alertId -Relation 'has_alert'

        if ($a.data -and $a.data.pid) {
            $procId = "process:$($a.data.pid)"
            Add-GraphNode -Id $procId -Label "PID $($a.data.pid)" -Type 'process'
            Add-GraphLink -Source $alertId -Target $procId -Relation 'related_process'
        }

        if ($a.data -and $a.data.remote_address) {
            $netId = "network:$($a.data.remote_address):$($a.data.remote_port)"
            Add-GraphNode -Id $netId -Label "$($a.data.remote_address):$($a.data.remote_port)" -Type 'network'
            Add-GraphLink -Source $alertId -Target $netId -Relation 'related_network'
        }

        $latestMemory = $recentEvents | Select-Object -Last 1
        if ($latestMemory -and $latestMemory.hash) {
            $memoryId = "memory:$($latestMemory.hash)"
            Add-GraphNode -Id $memoryId -Label "$($latestMemory.type)@$($latestMemory.time)" -Type 'ava_memory'
            Add-GraphLink -Source $memoryId -Target $alertId -Relation 'memory_to_alert'
        }
    }

    return [ordered]@{
        generated = (Get-Date).ToString('s')
        nodes     = @($nodes.Values)
        links     = @($links)
    }
}

function Compare-WithBaseline {
    param($Snapshot)

    $alerts = New-Object System.Collections.Generic.List[object]
    if (-not (Test-Path -LiteralPath $BaselineFile)) {
        $alerts.Add([ordered]@{
            severity = 'LOW'
            type     = 'BASELINE'
            message  = 'Keine Baseline vorhanden. Starte mit -CreateBaseline.'
        })
        return $alerts
    }

    $base = Get-Content -Path $BaselineFile -Raw | ConvertFrom-Json

    foreach ($p in $Snapshot.powershell) {
        if ($p.suspicious) {
            $alerts.Add([ordered]@{
                severity = 'HIGH'
                type     = 'POWERSHELL'
                message  = "Verdächtiger PowerShell-Prozess erkannt: PID $($p.pid)"
                data     = $p
            })
        }
    }

    if ($Snapshot.defender.available -and -not $Snapshot.defender.realtime_protection) {
        $alerts.Add([ordered]@{
            severity = 'CRITICAL'
            type     = 'DEFENDER'
            message  = 'Defender Echtzeitschutz ist AUS.'
        })
    }

    $baseAdmins = @($base.admins | ForEach-Object { $_.Name })
    foreach ($a in $Snapshot.admins) {
        if ($baseAdmins -notcontains $a.Name) {
            $alerts.Add([ordered]@{
                severity = 'HIGH'
                type     = 'ADMIN_DELTA'
                message  = "Neuer lokaler Admin seit Baseline: $($a.Name)"
                data     = @{ admin = $a.Name }
            })
        }
    }

    $baseTasks = @($base.tasks | ForEach-Object { "$($_.TaskPath)$($_.TaskName)" })
    foreach ($t in $Snapshot.tasks) {
        $id = "$($t.TaskPath)$($t.TaskName)"
        if ($baseTasks -notcontains $id) {
            $alerts.Add([ordered]@{
                severity = 'MEDIUM'
                type     = 'TASK_DELTA'
                message  = "Neue geplante Aufgabe seit Baseline: $id"
            })
        }
    }

    if (-not $Snapshot.integrity.baseline_exists) {
        $alerts.Add([ordered]@{
            severity = 'LOW'
            type     = 'INTEGRITY_BASELINE'
            message  = 'Integritäts-Baseline fehlt. Erzeuge Baseline mit -CreateBaseline.'
        })
    }

    foreach ($cng in $Snapshot.integrity.changed) {
        $alerts.Add([ordered]@{
            severity = 'HIGH'
            type     = 'INTEGRITY_CHANGED'
            message  = "AVA Datei geändert: $($cng.path)"
            data     = $cng
        })
    }

    foreach ($miss in $Snapshot.integrity.missing) {
        $alerts.Add([ordered]@{
            severity = 'HIGH'
            type     = 'INTEGRITY_MISSING'
            message  = "AVA Datei fehlt seit Baseline: $($miss.path)"
            data     = $miss
        })
    }

    foreach ($add in $Snapshot.integrity.added) {
        $alerts.Add([ordered]@{
            severity = 'MEDIUM'
            type     = 'INTEGRITY_NEW'
            message  = "Neue AVA Datei erkannt: $($add.path)"
            data     = $add
        })
    }

    # FTP, Telnet, RPC, NetBIOS, SMB, RDP, WinRM (5985 HTTP / 5986 HTTPS)
    $riskPorts = @(21, 23, 135, 139, 445, 3389, 5985, 5986)
    foreach ($c in $Snapshot.network.tcp) {
        if ($riskPorts -contains [int]$c.local_port -or $riskPorts -contains [int]$c.remote_port) {
            $alerts.Add([ordered]@{
                severity = 'MEDIUM'
                type     = 'NETWORK_RISK_PORT'
                message  = "Risikorelevante TCP-Verbindung/Port erkannt: $($c.process) PID $($c.pid)"
                data     = $c
            })
        }

        if ($c.remote_reputation_class -eq 'PUBLIC_UNKNOWN') {
            $alerts.Add([ordered]@{
                severity = 'LOW'
                type     = 'REMOTE_IP_CONTEXT'
                message  = "Öffentliche Remote-IP erkannt (nur Einordnung): $($c.remote_address)"
                data     = @{
                    remote_address = $c.remote_address
                    remote_port    = $c.remote_port
                    reputation     = $c.remote_reputation_class
                    note           = $c.remote_reputation_note
                    pid            = $c.pid
                    process        = $c.process
                }
            })
        }
    }

    return $alerts
}

function Build-Portal {
    param(
        [object]$Snapshot,
        [object[]]$Alerts,
        [object]$Trend,
        [object]$Risk,
        [object]$Graph
    )

    $riskColor = switch ($Risk.level) {
        'CRITICAL' { '#ef4444' }
        'HIGH' { '#f97316' }
        'MEDIUM' { '#eab308' }
        'LOW' { '#22c55e' }
        default { '#6b7280' }
    }

    $alertRows = foreach ($a in ($Alerts | Select-Object -First 80)) {
        "<tr><td>$(HtmlEncode $a.severity)</td><td>$(HtmlEncode $a.type)</td><td>$(HtmlEncode $a.message)</td></tr>"
    }
    if (-not $alertRows) { $alertRows = @("<tr><td colspan='3'>Keine Alerts</td></tr>") }

    $psRows = foreach ($p in $Snapshot.powershell) {
        "<tr><td>$(HtmlEncode $p.ppid)</td><td>$(HtmlEncode $p.pid)</td><td>$(HtmlEncode $p.name)</td><td>$(HtmlEncode $p.suspicious)</td><td>$(HtmlEncode ($p.hits -join ', '))</td></tr>"
    }
    if (-not $psRows) { $psRows = @("<tr><td colspan='5'>Keine laufenden PowerShell-Prozesse erkannt.</td></tr>") }

    $tcpRows = foreach ($c in ($Snapshot.network.tcp | Select-Object -First $MaxTcpDisplayRows)) {
        "<tr><td>$(HtmlEncode $c.process)</td><td>$(HtmlEncode $c.pid)</td><td>$(HtmlEncode $c.local_port)</td><td>$(HtmlEncode $c.remote_address)</td><td>$(HtmlEncode $c.remote_port)</td><td>$(HtmlEncode $c.remote_reputation_class)</td><td>$(HtmlEncode $c.remote_reputation_note)</td></tr>"
    }
    if (-not $tcpRows) { $tcpRows = @("<tr><td colspan='7'>Keine etablierten TCP-Verbindungen.</td></tr>") }

    $trendRows = foreach ($d in $Trend.days) {
        $width = [Math]::Min([int]$d.alerts * 14, 320)
        "<tr><td>$(HtmlEncode $d.day)</td><td>$(HtmlEncode $d.snapshots)</td><td>$(HtmlEncode $d.alerts)</td><td>$(HtmlEncode $d.critical)</td><td>$(HtmlEncode $d.high)</td><td><div class='bar' style='width:${width}px'></div></td></tr>"
    }

    $reasonItems = foreach ($r in $Risk.reasons) { "<li>$(HtmlEncode $r)</li>" }
    $integrity = $Snapshot.integrity
    $integritySummary = "Baseline: $(if ($integrity.baseline_exists) { 'vorhanden' } else { 'fehlt' }) | Geprüft: $(@($integrity.checked_files).Count) | Geändert: $(@($integrity.changed).Count) | Neu: $(@($integrity.added).Count) | Fehlend: $(@($integrity.missing).Count)"
    $graphSummary = "Nodes: $(@($Graph.nodes).Count) | Links: $(@($Graph.links).Count) | Datei: $GraphFile"

@"
<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>AVA CORE STACK Portal</title>
  <style>
    body { font-family: Segoe UI, Tahoma, Arial, sans-serif; background: #0b1220; color: #e2e8f0; margin: 0; padding: 20px; }
    h1 { margin: 0 0 8px; color: #22d3ee; }
    h2 { margin: 0 0 8px; color: #93c5fd; }
    .meta { color: #94a3b8; margin-bottom: 16px; }
    .cards { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 16px; }
    .card { background: #172033; border: 1px solid #22314f; border-radius: 8px; padding: 12px 16px; min-width: 140px; }
    .card .n { font-size: 1.4rem; font-weight: 700; }
    .risk { border-top: 3px solid $riskColor; }
    .section { margin-top: 22px; background: #10192b; border: 1px solid #22314f; border-radius: 8px; padding: 12px; }
    table { width: 100%; border-collapse: collapse; font-size: 0.86rem; }
    th, td { border-bottom: 1px solid #243247; padding: 8px; text-align: left; vertical-align: top; }
    th { color: #7dd3fc; }
    .bar { height: 8px; background: linear-gradient(90deg,#22d3ee,#3b82f6); border-radius: 4px; }
    ul { margin: 8px 0 0 18px; }
    code { color: #93c5fd; }
  </style>
</head>
<body>
<h1>AVA CORE STACK 🌀🗿🔑</h1>
<p class="meta">Zeit: $(HtmlEncode $Snapshot.time) | Host: $(HtmlEncode $Snapshot.computer) | User: $(HtmlEncode $Snapshot.user)</p>

<div class="cards">
  <div class="card risk"><div>Risiko</div><div class="n">$(HtmlEncode $Risk.score)</div><div>$(HtmlEncode $Risk.level)</div></div>
  <div class="card"><div>Alerts gesamt</div><div class="n">$(HtmlEncode $Alerts.Count)</div></div>
  <div class="card"><div>Critical/High</div><div class="n">$(HtmlEncode $Risk.critical)/$(HtmlEncode $Risk.high)</div></div>
  <div class="card"><div>TCP/UDP</div><div class="n">$(HtmlEncode $Snapshot.network.tcp.Count)/$(HtmlEncode $Snapshot.network.udp.Count)</div></div>
</div>

<div class="section">
  <h2>🗿 Risiko-Score mit Begründung</h2>
  <ul>$($reasonItems -join '')</ul>
</div>

<div class="section">
  <h2>📈 Zeitachse / Trend (letzte $TrendDays Tage)</h2>
  <table>
    <thead><tr><th>Tag</th><th>Snapshots</th><th>Alerts</th><th>Critical</th><th>High</th><th>Alert-Intensität</th></tr></thead>
    <tbody>$($trendRows -join '')</tbody>
  </table>
</div>

<div class="section">
  <h2>🔒 Integritätsprüfung AVA-Dateien</h2>
  <p>$(HtmlEncode $integritySummary)</p>
</div>

<div class="section">
  <h2>🧠 Prozess-Graph / AVA Memory ↔ Alert ↔ Prozess ↔ Netzwerk</h2>
  <p>$(HtmlEncode $graphSummary)</p>
  <p><code>$GraphFile</code></p>
</div>

<div class="section">
  <h2>Alerts</h2>
  <table>
    <thead><tr><th>Severity</th><th>Type</th><th>Message</th></tr></thead>
    <tbody>$($alertRows -join '')</tbody>
  </table>
</div>

<div class="section">
  <h2>PowerShell Prozesse (Parent ↔ Child)</h2>
  <table>
    <thead><tr><th>PPID</th><th>PID</th><th>Name</th><th>Suspicious</th><th>Hits</th></tr></thead>
    <tbody>$($psRows -join '')</tbody>
  </table>
</div>

<div class="section">
  <h2>TCP Netzwerk + Remote-IP Einordnung</h2>
  <table>
    <thead><tr><th>Prozess</th><th>PID</th><th>LocalPort</th><th>RemoteAddress</th><th>RemotePort</th><th>Klasse</th><th>Hinweis</th></tr></thead>
    <tbody>$($tcpRows -join '')</tbody>
  </table>
</div>
</body>
</html>
"@ | Set-Content -Path $PortalFile -Encoding UTF8
}

$snapshot = New-Snapshot

if ($CreateBaseline) {
    $snapshot | ConvertTo-Json -Depth 12 | Set-Content -Path $BaselineFile -Encoding UTF8
    Save-AvaFileIntegrityBaseline -IntegrityState $snapshot.integrity
    Write-TangleEvent -Type 'BASELINE' -Severity 'INFO' -Message 'Baseline erstellt.' -Data @{ path = $BaselineFile }
    Write-TangleEvent -Type 'INTEGRITY_BASELINE' -Severity 'INFO' -Message 'Integritäts-Baseline aktualisiert.' -Data @{ path = $IntegrityFile }
    Write-Host "AVA Baseline erstellt: $BaselineFile" -ForegroundColor Green
}

$alerts = Compare-WithBaseline -Snapshot $snapshot
$trend = Get-TrendData
$todayKey = (Get-Date).ToString('yyyy-MM-dd')
$todayTrend = @($trend.days | Where-Object { $_.day -eq $todayKey } | Select-Object -First 1)
if ($todayTrend) {
    $todayTrend[0].snapshots++
    foreach ($a in $alerts) {
        $todayTrend[0].alerts++
        switch -Exact ([string]$a.severity) {
            'CRITICAL' { $todayTrend[0].critical++ }
            'HIGH' { $todayTrend[0].high++ }
            'MEDIUM' { $todayTrend[0].medium++ }
            'LOW' { $todayTrend[0].low++ }
            default {}
        }
    }
}

$risk = Get-RiskAssessment -Alerts $alerts -Snapshot $snapshot -Trend $trend

Write-TangleEvent -Type 'SNAPSHOT' -Severity 'INFO' -Message 'Snapshot erstellt.' -Data @{
    powershell_count = @($snapshot.powershell).Count
    tcp_count        = @($snapshot.network.tcp).Count
    udp_count        = @($snapshot.network.udp).Count
    admin_count      = @($snapshot.admins).Count
    task_count       = @($snapshot.tasks).Count
    service_count    = @($snapshot.services).Count
    run_once         = [bool]$RunOnce
    risk_score       = $risk.score
    risk_level       = $risk.level
}

foreach ($a in $alerts) {
    $sev = if ($a.severity) { $a.severity } else { 'LOW' }
    $typ = if ($a.type) { $a.type } else { 'ALERT' }
    $msg = if ($a.message) { $a.message } else { 'Alert ohne Meldung' }
    Write-TangleEvent -Type $typ -Severity $sev -Message $msg -Data @{ alert = $a }
}

$graph = Build-EntityGraph -Snapshot $snapshot -Alerts $alerts -Trend $trend
$graph | ConvertTo-Json -Depth 12 | Set-Content -Path $GraphFile -Encoding UTF8

Build-Portal -Snapshot $snapshot -Alerts $alerts -Trend $trend -Risk $risk -Graph $graph

Write-Host ''
Write-Host 'AVA CORE STACK abgeschlossen.' -ForegroundColor Cyan
Write-Host "Portal: $PortalFile" -ForegroundColor Green
Write-Host "Graph: $GraphFile" -ForegroundColor Green
Write-Host "Eventlog: $EventLog" -ForegroundColor Green
Write-Host "Alerts: $AlertLog" -ForegroundColor Green

if ($OpenPortal) {
    Start-Process $PortalFile
}
