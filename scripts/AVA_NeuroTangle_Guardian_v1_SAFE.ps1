#requires -Version 5.1
<#
.SYNOPSIS
    Local AVA snapshot, baseline, evidence chain and HTML portal.

.DESCRIPTION
    This script is for a local authorized Windows host only.
    Once, Loop and OpenPortal read local state and write AVA-owned files.
    No remote scanning. No remote scanning or counterattack.
    InstallTask and UninstallTask are optional local changes and require exact
    interactive confirmation.
#>

[CmdletBinding()]
param(
    [ValidateSet('Once', 'Loop', 'OpenPortal', 'InstallTask', 'UninstallTask')]
    [string]$Mode = 'Once',

    [ValidateRange(30, 86400)]
    [int]$IntervalSeconds = 60,

    [ValidateRange(0, 1000000)]
    [int]$MaxCycles = 0,

    [switch]$OpenPortal
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:IsAdministrator = ([Security.Principal.WindowsPrincipal]
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )

$script:Root = if ($script:IsAdministrator) {
    'C:\Windows\SecurityGuardian\AVA_NeuroTangle_SAFE'
} else {
    Join-Path $env:LOCALAPPDATA 'AVA_NeuroTangle_SAFE'
}

$script:Logs = Join-Path $script:Root 'Logs'
$script:State = Join-Path $script:Root 'State'
$script:Reports = Join-Path $script:Root 'Reports'
$script:Portal = Join-Path $script:Root 'Portal'
$script:EventsFile = Join-Path $script:Logs 'events.jsonl'
$script:AlertsFile = Join-Path $script:Logs 'alerts.jsonl'
$script:TangleFile = Join-Path $script:Logs 'tangle.jsonl'
$script:BaselineFile = Join-Path $script:State 'baseline.json'
$script:TangleStateFile = Join-Path $script:State 'tangle_state.json'
$script:SnapshotFile = Join-Path $script:Reports 'latest_snapshot.json'
$script:AnalysisFile = Join-Path $script:Reports 'latest_analysis.json'
$script:ManifestFile = Join-Path $script:Reports 'sha256_manifest.json'
$script:PortalFile = Join-Path $script:Portal 'ava_neuro_tangle_portal.html'
$script:TaskName = 'AVA_NeuroTangle_60s_SAFE'
$script:RiskPorts = @(21, 23, 135, 139, 445, 3389, 5985, 5986)
$script:SuspiciousCommandPattern = '(?i)(-enc\b|encodedcommand|downloadstring|invoke-expression|\biex\b|-nop\b|windowstyle\s+hidden|executionpolicy\s+bypass|frombase64string|bitsadmin|certutil|mshta|regsvr32|rundll32)'

function Initialize-AVAStorage {
    foreach ($directory in @($script:Root, $script:Logs, $script:State, $script:Reports, $script:Portal)) {
        if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }
    }
}

function Get-AVAUtc {
    return (Get-Date).ToUniversalTime().ToString('o')
}

function Get-AVAHash {
    param([AllowNull()][object]$InputObject)

    $text = if ($null -eq $InputObject) {
        ''
    } elseif ($InputObject -is [string]) {
        [string]$InputObject
    } else {
        $InputObject | ConvertTo-Json -Depth 20 -Compress
    }

    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($text)
        return ([BitConverter]::ToString($sha256.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha256.Dispose()
    }
}

function Write-AVAJson {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][object]$Data
    )

    $Data | ConvertTo-Json -Depth 20 | Out-File -LiteralPath $Path -Encoding utf8 -Force
}

function Add-AVAJsonLine {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][object]$Data
    )

    Add-Content -LiteralPath $Path -Value ($Data | ConvertTo-Json -Depth 20 -Compress) -Encoding utf8
}

function Read-AVAJson {
    param(
        [Parameter(Mandatory)][string]$Path,
        [AllowNull()][object]$DefaultValue
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $DefaultValue
    }

    try {
        return Get-Content -LiteralPath $Path -Raw -Encoding utf8 | ConvertFrom-Json
    } catch {
        Write-Warning "Could not read '$Path': $($_.Exception.Message)"
        return $DefaultValue
    }
}

function Invoke-AVASafeCollect {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock
    )

    try {
        return & $ScriptBlock
    } catch {
        return [pscustomobject][ordered]@{
            Collector = $Name
            Error = $_.Exception.Message
        }
    }
}

function Get-AVASnapshot {
    $processes = Invoke-AVASafeCollect -Name 'Processes' -ScriptBlock {
        @(Get-CimInstance Win32_Process | ForEach-Object {
            [pscustomobject][ordered]@{
                PID = [int]$_.ProcessId
                ParentPID = [int]$_.ParentProcessId
                Name = $_.Name
                Path = $_.ExecutablePath
                CommandLine = $_.CommandLine
            }
        })
    }

    $connections = Invoke-AVASafeCollect -Name 'Connections' -ScriptBlock {
        $processMap = @{}
        Get-Process | ForEach-Object {
            $processMap[[int]$_.Id] = $_.ProcessName
        }

        @(Get-NetTCPConnection | Where-Object {
            $_.State -in @('Listen', 'Established', 'SynSent')
        } | ForEach-Object {
            [pscustomobject][ordered]@{
                LocalAddress = $_.LocalAddress
                LocalPort = [int]$_.LocalPort
                RemoteAddress = $_.RemoteAddress
                RemotePort = [int]$_.RemotePort
                State = $_.State
                OwningProcess = [int]$_.OwningProcess
                ProcessName = if ($processMap.ContainsKey([int]$_.OwningProcess)) {
                    $processMap[[int]$_.OwningProcess]
                } else {
                    ''
                }
            }
        })
    }

    return [pscustomobject][ordered]@{
        AVA = 'NEURO_TANGLE_GUARDIAN_SAFE'
        Version = '1.0-safe'
        TimestampUtc = Get-AVAUtc
        Computer = Invoke-AVASafeCollect -Name 'Computer' -ScriptBlock {
            $operatingSystem = Get-CimInstance Win32_OperatingSystem
            [pscustomobject][ordered]@{
                ComputerName = $env:COMPUTERNAME
                UserName = "$env:USERDOMAIN\$env:USERNAME"
                IsAdministrator = $script:IsAdministrator
                OperatingSystem = $operatingSystem.Caption
                Version = $operatingSystem.Version
                BuildNumber = $operatingSystem.BuildNumber
                LastBoot = $operatingSystem.LastBootUpTime
            }
        }
        Defender = Invoke-AVASafeCollect -Name 'Defender' -ScriptBlock {
            $status = Get-MpComputerStatus
            [pscustomobject][ordered]@{
                AntivirusEnabled = $status.AntivirusEnabled
                RealTimeProtectionEnabled = $status.RealTimeProtectionEnabled
                AntivirusSignatureLastUpdated = $status.AntivirusSignatureLastUpdated
            }
        }
        Firewall = Invoke-AVASafeCollect -Name 'Firewall' -ScriptBlock {
            @(Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction)
        }
        Administrators = Invoke-AVASafeCollect -Name 'Administrators' -ScriptBlock {
            $group = Get-LocalGroup | Where-Object { $_.SID.Value -eq 'S-1-5-32-544' } | Select-Object -First 1
            if ($null -eq $group) {
                @()
            } else {
                @(Get-LocalGroupMember -Group $group.Name | ForEach-Object {
                    [pscustomobject][ordered]@{
                        Name = $_.Name
                        ObjectClass = $_.ObjectClass
                        SID = $_.SID.Value
                    }
                })
            }
        }
        Processes = $processes
        Connections = $connections
        Services = Invoke-AVASafeCollect -Name 'Services' -ScriptBlock {
            @(Get-CimInstance Win32_Service | Where-Object { $_.State -eq 'Running' } |
                Select-Object Name, DisplayName, StartMode, StartName, PathName)
        }
        ScheduledTasks = Invoke-AVASafeCollect -Name 'ScheduledTasks' -ScriptBlock {
            @(Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
                [pscustomobject][ordered]@{
                    TaskPath = $_.TaskPath
                    TaskName = $_.TaskName
                    State = $_.State
                    Author = $_.Author
                    Actions = (@($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | ')
                }
            })
        }
        Neighbors = Invoke-AVASafeCollect -Name 'Neighbors' -ScriptBlock {
            @(Get-NetNeighbor -AddressFamily IPv4 | Where-Object { $_.State -ne 'Unreachable' } |
                Select-Object IPAddress, LinkLayerAddress, State, InterfaceIndex)
        }
        WLAN = Invoke-AVASafeCollect -Name 'WLAN' -ScriptBlock {
            [pscustomobject][ordered]@{
                Raw = (netsh.exe wlan show networks mode=bssid 2>&1 | Out-String).Trim()
            }
        }
        RecentEvents = Invoke-AVASafeCollect -Name 'Events' -ScriptBlock {
            @(Get-WinEvent -LogName System -MaxEvents 30 |
                Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message)
        }
    }
}

function New-AVABaseline {
    param([Parameter(Mandatory)][object]$Snapshot)

    return [pscustomobject][ordered]@{
        CreatedUtc = Get-AVAUtc
        Administrators = @($Snapshot.Administrators | ForEach-Object { "$($_.Name)|$($_.SID)" } | Sort-Object -Unique)
        Neighbors = @($Snapshot.Neighbors | ForEach-Object { "$($_.IPAddress)|$($_.LinkLayerAddress)" } | Sort-Object -Unique)
        ScheduledTasks = @($Snapshot.ScheduledTasks | ForEach-Object { "$($_.TaskPath)$($_.TaskName)|$($_.Actions)" } | Sort-Object -Unique)
        Services = @($Snapshot.Services | ForEach-Object { "$($_.Name)|$($_.PathName)" } | Sort-Object -Unique)
    }
}

function Get-AVADelta {
    param(
        [AllowNull()][object[]]$Current,
        [AllowNull()][object[]]$Baseline
    )

    $known = @{}
    foreach ($item in @($Baseline)) {
        if ($null -ne $item) {
            $known[[string]$item] = $true
        }
    }

    return @($Current | Where-Object { $null -ne $_ -and -not $known.ContainsKey([string]$_) })
}

function Get-AVABaseline {
    param([Parameter(Mandatory)][object]$Snapshot)

    if (-not (Test-Path -LiteralPath $script:BaselineFile -PathType Leaf)) {
        $baseline = New-AVABaseline -Snapshot $Snapshot
        Write-AVAJson -Path $script:BaselineFile -Data $baseline
        return $baseline
    }

    return Read-AVAJson -Path $script:BaselineFile -DefaultValue (New-AVABaseline -Snapshot $Snapshot)
}

function Add-AVAFinding {
    param(
        [Parameter(Mandatory)][Collections.Generic.List[object]]$List,
        [Parameter(Mandatory)][int]$Severity,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$Description,
        [AllowNull()][object]$Evidence
    )

    $evidenceText = if ($Evidence -is [string]) {
        [string]$Evidence
    } else {
        $Evidence | ConvertTo-Json -Depth 5 -Compress
    }

    if ($evidenceText.Length -gt 700) {
        $evidenceText = $evidenceText.Substring(0, 700) + '...'
    }

    [void]$List.Add([pscustomobject][ordered]@{
        Severity = $Severity
        Category = $Category
        Key = $Key
        Description = $Description
        Evidence = $evidenceText
    })
}

function New-AVAAnalysis {
    param(
        [Parameter(Mandatory)][object]$Snapshot,
        [Parameter(Mandatory)][object]$Baseline
    )

    $findings = [Collections.Generic.List[object]]::new()

    if ($Snapshot.Defender.RealTimeProtectionEnabled -eq $false -or
        $Snapshot.Defender.AntivirusEnabled -eq $false) {
        Add-AVAFinding -List $findings -Severity 85 -Category 'DEFENDER' -Key 'PROTECTION_OFF' `
            -Description 'Defender protection appears disabled.' -Evidence $Snapshot.Defender
    }

    $disabledFirewall = @($Snapshot.Firewall | Where-Object { $_.Enabled -eq $false })
    if ($disabledFirewall.Count -gt 0) {
        Add-AVAFinding -List $findings -Severity 70 -Category 'FIREWALL' -Key 'PROFILE_OFF' `
            -Description 'At least one firewall profile is disabled.' -Evidence $disabledFirewall
    }

    $riskConnections = @($Snapshot.Connections | Where-Object {
        ($script:RiskPorts -contains [int]$_.LocalPort) -or
        ($script:RiskPorts -contains [int]$_.RemotePort)
    })
    if ($riskConnections.Count -gt 0) {
        Add-AVAFinding -List $findings -Severity 45 -Category 'NETWORK' -Key 'RISK_PORT' `
            -Description 'A monitored port is present. This is an indicator, not attribution.' `
            -Evidence ($riskConnections | Select-Object -First 20)
    }

    $suspiciousProcesses = @($Snapshot.Processes | Where-Object {
        [string]$_.CommandLine -match $script:SuspiciousCommandPattern
    })
    if ($suspiciousProcesses.Count -gt 0) {
        Add-AVAFinding -List $findings -Severity 90 -Category 'PROCESS' -Key 'SUSPICIOUS_COMMAND_LINE' `
            -Description 'A command line matches a monitored pattern.' `
            -Evidence ($suspiciousProcesses | Select-Object -First 20)
    }

    $temporaryProcesses = @($Snapshot.Processes | Where-Object {
        [string]$_.Path -match '(?i)(\\AppData\\Local\\Temp\\|\\Windows\\Temp\\|\\Temp\\)'
    })
    if ($temporaryProcesses.Count -gt 0) {
        Add-AVAFinding -List $findings -Severity 55 -Category 'PROCESS' -Key 'TEMP_PATH_PROCESS' `
            -Description 'A process runs from a temporary path. Review; do not auto-delete.' `
            -Evidence ($temporaryProcesses | Select-Object -First 20)
    }

    $current = New-AVABaseline -Snapshot $Snapshot
    foreach ($delta in @(
            @{ Key = 'NEW_ADMINISTRATOR'; Severity = 95; Current = $current.Administrators; Baseline = $Baseline.Administrators },
            @{ Key = 'NEW_NEIGHBOR'; Severity = 35; Current = $current.Neighbors; Baseline = $Baseline.Neighbors },
            @{ Key = 'NEW_SCHEDULED_TASK'; Severity = 65; Current = $current.ScheduledTasks; Baseline = $Baseline.ScheduledTasks },
            @{ Key = 'NEW_SERVICE'; Severity = 60; Current = $current.Services; Baseline = $Baseline.Services }
        )) {
        $newItems = Get-AVADelta -Current @($delta.Current) -Baseline @($delta.Baseline)
        if ($newItems.Count -gt 0) {
            Add-AVAFinding -List $findings -Severity $delta.Severity -Category 'BASELINE' -Key $delta.Key `
                -Description "$($delta.Key) compared with the local baseline." `
                -Evidence ($newItems | Select-Object -First 30)
        }
    }

    $sum = ($findings | Measure-Object -Property Severity -Sum).Sum
    if ($null -eq $sum) {
        $sum = 0
    }
    $score = [Math]::Min(100, [int]$sum)

    $status = if ($score -ge 85) {
        'CRITICAL'
    } elseif ($score -ge 60) {
        'ALERT'
    } elseif ($score -ge 25) {
        'NOTICE'
    } else {
        'CALM'
    }

    $decision = if ($score -ge 85) {
        'PRESERVE_EVIDENCE_AND_INVESTIGATE'
    } elseif ($score -ge 60) {
        'REVIEW_AND_PRESERVE'
    } elseif ($score -ge 25) {
        'OBSERVE_AND_COMPARE'
    } else {
        'CONTINUE_NORMALLY'
    }

    return [pscustomobject][ordered]@{
        TimestampUtc = Get-AVAUtc
        RiskScore = $score
        Status = $status
        Decision = $decision
        FindingsCount = @($findings).Count
        Findings = @($findings | Sort-Object Severity -Descending)
        Rule = 'Facts before fear. Indicators require verification. No attribution without evidence.'
    }
}

function Add-AVATangle {
    param(
        [Parameter(Mandatory)][object]$Snapshot,
        [Parameter(Mandatory)][object]$Analysis
    )

    $defaultState = [pscustomobject][ordered]@{ Cycle = 0; LastMainHash = '' }
    $state = Read-AVAJson -Path $script:TangleStateFile -DefaultValue $defaultState
    $cycle = [int]$state.Cycle + 1

    $entry = [ordered]@{
        Type = 'MAIN'
        Cycle = $cycle
        TimestampUtc = Get-AVAUtc
        PreviousHash = [string]$state.LastMainHash
        SnapshotHash = Get-AVAHash $Snapshot
        AnalysisHash = Get-AVAHash $Analysis
        RiskScore = $Analysis.RiskScore
        Status = $Analysis.Status
        FindingsCount = $Analysis.FindingsCount
    }
    $entry.CurrentHash = Get-AVAHash $entry

    Add-AVAJsonLine -Path $script:TangleFile -Data $entry
    Write-AVAJson -Path $script:TangleStateFile -Data ([pscustomobject][ordered]@{
        Cycle = $cycle
        LastMainHash = $entry.CurrentHash
    })

    return [pscustomobject][ordered]@{
        Cycle = $cycle
        MainHash = $entry.CurrentHash
        PreviousHash = $entry.PreviousHash
    }
}

function ConvertTo-AVAHtmlTable {
    param(
        [AllowNull()][object[]]$Items,
        [string[]]$Properties,
        [int]$Maximum = 80
    )

    $selected = @($Items | Select-Object -First $Maximum)
    if ($selected.Count -eq 0) {
        return '<p>No entries.</p>'
    }

    return (($selected | Select-Object -Property $Properties | ConvertTo-Html -Fragment) -join "`n")
}

function Write-AVAPortal {
    param(
        [Parameter(Mandatory)][object]$Snapshot,
        [Parameter(Mandatory)][object]$Analysis,
        [Parameter(Mandatory)][object]$Tangle
    )

    $manifest = @(
        $script:BaselineFile,
        $script:TangleStateFile,
        $script:SnapshotFile,
        $script:AnalysisFile,
        $script:EventsFile,
        $script:AlertsFile,
        $script:TangleFile
    ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | ForEach-Object {
        $hash = Get-FileHash -LiteralPath $_ -Algorithm SHA256
        [pscustomobject][ordered]@{
            Path = $_
            Algorithm = $hash.Algorithm
            Hash = $hash.Hash
            Length = (Get-Item -LiteralPath $_).Length
        }
    }
    Write-AVAJson -Path $script:ManifestFile -Data @($manifest)

    $findingsHtml = ConvertTo-AVAHtmlTable -Items $Analysis.Findings `
        -Properties @('Severity', 'Category', 'Key', 'Description', 'Evidence') -Maximum 100
    $connectionsHtml = ConvertTo-AVAHtmlTable -Items $Snapshot.Connections `
        -Properties @('State', 'LocalAddress', 'LocalPort', 'RemoteAddress', 'RemotePort', 'ProcessName')
    $administratorsHtml = ConvertTo-AVAHtmlTable -Items $Snapshot.Administrators `
        -Properties @('Name', 'ObjectClass', 'SID')
    $manifestHtml = ConvertTo-AVAHtmlTable -Items $manifest `
        -Properties @('Algorithm', 'Hash', 'Length', 'Path')

    $computer = [Net.WebUtility]::HtmlEncode([string]$Snapshot.Computer.ComputerName)
    $user = [Net.WebUtility]::HtmlEncode([string]$Snapshot.Computer.UserName)

    $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="$IntervalSeconds">
<title>AVA Neuro Tangle Guardian SAFE</title>
<style>
body{font-family:Segoe UI,Arial;background:#0b0f14;color:#e7edf5;margin:0}
header,section{padding:20px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;padding:20px}
.card{background:#111827;border:1px solid #263241;border-radius:12px;padding:14px}.big{font-size:28px;font-weight:700}
table{border-collapse:collapse;width:100%;font-size:12px}th,td{border:1px solid #263241;padding:6px;word-break:break-word}th{background:#172033}
</style>
</head>
<body>
<header><h1>AVA Neuro Tangle Guardian SAFE</h1><p>Local evidence and triage. No remote action.</p></header>
<div class="grid">
<div class="card"><div>Status</div><div class="big">$($Analysis.Status)</div></div>
<div class="card"><div>Risk score</div><div class="big">$($Analysis.RiskScore)/100</div></div>
<div class="card"><div>Cycle</div><div class="big">$($Tangle.Cycle)</div></div>
<div class="card"><div>Findings</div><div class="big">$($Analysis.FindingsCount)</div></div>
</div>
<section><p>Computer: $computer | User: $user | UTC: $($Snapshot.TimestampUtc)</p><p>Main hash: $($Tangle.MainHash)</p></section>
<section><h2>Findings</h2>$findingsHtml</section>
<section><h2>Administrators</h2>$administratorsHtml</section>
<section><h2>Connections</h2>$connectionsHtml</section>
<section><h2>SHA256 manifest</h2>$manifestHtml</section>
<section><pre>Preserve evidence. Verify context. Do not attribute without proof. Do not attack.</pre></section>
</body>
</html>
"@

    $html | Out-File -LiteralPath $script:PortalFile -Encoding utf8 -Force
}

function Invoke-AVACycle {
    Initialize-AVAStorage
    $snapshot = Get-AVASnapshot
    $baseline = Get-AVABaseline -Snapshot $snapshot
    $analysis = New-AVAAnalysis -Snapshot $snapshot -Baseline $baseline
    $tangle = Add-AVATangle -Snapshot $snapshot -Analysis $analysis

    Write-AVAJson -Path $script:SnapshotFile -Data $snapshot
    Write-AVAJson -Path $script:AnalysisFile -Data $analysis
    Add-AVAJsonLine -Path $script:EventsFile -Data ([pscustomobject][ordered]@{
        Type = 'CYCLE'
        TimestampUtc = Get-AVAUtc
        Cycle = $tangle.Cycle
        RiskScore = $analysis.RiskScore
        Status = $analysis.Status
        MainHash = $tangle.MainHash
    })

    foreach ($finding in @($analysis.Findings)) {
        Add-AVAJsonLine -Path $script:AlertsFile -Data ([pscustomobject][ordered]@{
            Type = 'ALERT'
            TimestampUtc = Get-AVAUtc
            Cycle = $tangle.Cycle
            MainHash = $tangle.MainHash
            Severity = $finding.Severity
            Category = $finding.Category
            Key = $finding.Key
            Description = $finding.Description
            Evidence = $finding.Evidence
        })
    }

    Write-AVAPortal -Snapshot $snapshot -Analysis $analysis -Tangle $tangle
    Write-Host "AVA cycle $($tangle.Cycle): $($analysis.Status), score $($analysis.RiskScore)/100"
}

function Install-AVALocalTask {
    if (-not $script:IsAdministrator) {
        throw 'InstallTask requires an elevated PowerShell window.'
    }
    if ([string]::IsNullOrWhiteSpace($PSCommandPath)) {
        throw 'InstallTask requires this script to be saved as a .ps1 file.'
    }

    $confirmation = Read-Host 'Type exact INSTALL to create the local startup task'
    if ($confirmation -cne 'INSTALL') {
        throw 'Installation cancelled.'
    }

    $argument = "-NoProfile -File `"$PSCommandPath`" -Mode Loop -IntervalSeconds 60"
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $argument
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
    Register-ScheduledTask -TaskName $script:TaskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
    Write-Host "Local task installed: $($script:TaskName)"
}

function Uninstall-AVALocalTask {
    if (-not $script:IsAdministrator) {
        throw 'UninstallTask requires an elevated PowerShell window.'
    }

    $confirmation = Read-Host 'Type exact REMOVE to delete the local AVA task'
    if ($confirmation -cne 'REMOVE') {
        throw 'Removal cancelled.'
    }

    Unregister-ScheduledTask -TaskName $script:TaskName -Confirm:$false -ErrorAction Stop
    Write-Host "Local task removed: $($script:TaskName)"
}

Initialize-AVAStorage

switch ($Mode) {
    'OpenPortal' {
        if (-not (Test-Path -LiteralPath $script:PortalFile -PathType Leaf)) {
            throw "Portal not found: $($script:PortalFile)"
        }
        Start-Process -FilePath $script:PortalFile
    }
    'InstallTask' {
        Install-AVALocalTask
    }
    'UninstallTask' {
        Uninstall-AVALocalTask
    }
    'Once' {
        Invoke-AVACycle
        if ($OpenPortal) {
            Start-Process -FilePath $script:PortalFile
        }
    }
    'Loop' {
        $cycle = 0
        while ($true) {
            Invoke-AVACycle
            if ($OpenPortal -and $cycle -eq 0) {
                Start-Process -FilePath $script:PortalFile
            }
            $cycle++
            if ($MaxCycles -gt 0 -and $cycle -ge $MaxCycles) {
                break
            }
            Start-Sleep -Seconds $IntervalSeconds
        }
    }
}
