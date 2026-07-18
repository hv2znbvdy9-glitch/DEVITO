#requires -Version 5.1
<#+
.SYNOPSIS
    Local defensive AVA snapshot, baseline, evidence chain and HTML portal.

.DESCRIPTION
    This script is for a local authorized Windows host only.
    Once, Loop and OpenPortal read local state and write AVA-owned report files.
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

$script:LogDirectory = Join-Path $script:Root 'Logs'
$script:StateDirectory = Join-Path $script:Root 'State'
$script:ReportDirectory = Join-Path $script:Root 'Reports'
$script:PortalDirectory = Join-Path $script:Root 'Portal'

$script:EventPath = Join-Path $script:LogDirectory 'events.jsonl'
$script:AlertPath = Join-Path $script:LogDirectory 'alerts.jsonl'
$script:TanglePath = Join-Path $script:LogDirectory 'tangle.jsonl'
$script:BaselinePath = Join-Path $script:StateDirectory 'baseline.json'
$script:TangleStatePath = Join-Path $script:StateDirectory 'tangle_state.json'
$script:SnapshotPath = Join-Path $script:ReportDirectory 'latest_snapshot.json'
$script:AnalysisPath = Join-Path $script:ReportDirectory 'latest_analysis.json'
$script:ManifestPath = Join-Path $script:ReportDirectory 'sha256_manifest.json'
$script:PortalPath = Join-Path $script:PortalDirectory 'ava_neuro_tangle_portal.html'
$script:TaskName = 'AVA_NeuroTangle_60s_SAFE'

$script:RiskPorts = @(21, 23, 135, 139, 445, 3389, 5985, 5986)
$script:SuspiciousPattern = '(?i)(-enc\b|encodedcommand|downloadstring|invoke-expression|\biex\b|-nop\b|windowstyle\s+hidden|executionpolicy\s+bypass|frombase64string|bitsadmin|certutil|mshta|regsvr32|rundll32)'

function Initialize-AVADirectory {
    foreach ($directory in @(
            $script:Root,
            $script:LogDirectory,
            $script:StateDirectory,
            $script:ReportDirectory,
            $script:PortalDirectory
        )) {
        if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }
    }
}

function Get-AVAUtcTimestamp {
    return (Get-Date).ToUniversalTime().ToString('o')
}

function Get-AVASha256 {
    param([AllowNull()][object]$InputObject)

    $text = if ($null -eq $InputObject) {
        ''
    } elseif ($InputObject -is [string]) {
        [string]$InputObject
    } else {
        $InputObject | ConvertTo-Json -Depth 30 -Compress
    }

    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($text)
        return ([BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    } finally {
        $algorithm.Dispose()
    }
}

function Write-AVAJson {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][object]$Data
    )

    $Data | ConvertTo-Json -Depth 30 | Out-File -LiteralPath $Path -Encoding utf8 -Force
}

function Add-AVAJsonLine {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][object]$Data
    )

    $line = $Data | ConvertTo-Json -Depth 30 -Compress
    Add-Content -LiteralPath $Path -Value $line -Encoding utf8
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

function Invoke-AVASafeCollector {
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
    $processes = Invoke-AVASafeCollector -Name 'Processes' -ScriptBlock {
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

    $connections = Invoke-AVASafeCollector -Name 'Connections' -ScriptBlock {
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
        TimestampUtc = Get-AVAUtcTimestamp
        Computer = Invoke-AVASafeCollector -Name 'Computer' -ScriptBlock {
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
        Defender = Invoke-AVASafeCollector -Name 'Defender' -ScriptBlock {
            $status = Get-MpComputerStatus
            [pscustomobject][ordered]@{
                AMServiceEnabled = $status.AMServiceEnabled
                AntivirusEnabled = $status.AntivirusEnabled
                RealTimeProtectionEnabled = $status.RealTimeProtectionEnabled
                AntivirusSignatureLastUpdated = $status.AntivirusSignatureLastUpdated
            }
        }
        Firewall = Invoke-AVASafeCollector -Name 'Firewall' -ScriptBlock {
            @(Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction)
        }
        Administrators = Invoke-AVASafeCollector -Name 'Administrators' -ScriptBlock {
            $group = Get-LocalGroup | Where-Object {
                $_.SID.Value -eq 'S-1-5-32-544'
            } | Select-Object -First 1

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
        Services = Invoke-AVASafeCollector -Name 'Services' -ScriptBlock {
            @(Get-CimInstance Win32_Service | Where-Object {
                $_.State -eq 'Running'
            } | Select-Object Name, DisplayName, StartMode, StartName, PathName)
        }
        ScheduledTasks = Invoke-AVASafeCollector -Name 'ScheduledTasks' -ScriptBlock {
            @(Get-ScheduledTask | Where-Object {
                $_.TaskPath -notlike '\Microsoft\*'
            } | ForEach-Object {
                [pscustomobject][ordered]@{
                    TaskPath = $_.TaskPath
                    TaskName = $_.TaskName
                    State = $_.State
                    Author = $_.Author
                    Actions = (@($_.Actions | ForEach-Object {
                        "$($_.Execute) $($_.Arguments)"
                    }) -join ' | ')
                }
            })
        }
        Neighbors = Invoke-AVASafeCollector -Name 'Neighbors' -ScriptBlock {
            @(Get-NetNeighbor -AddressFamily IPv4 | Where-Object {
                $_.State -ne 'Unreachable'
            } | Select-Object IPAddress, LinkLayerAddress, State, InterfaceIndex)
        }
        WLAN = Invoke-AVASafeCollector -Name 'WLAN' -ScriptBlock {
            [pscustomobject][ordered]@{
                Raw = (netsh.exe wlan show networks mode=bssid 2>&1 | Out-String).Trim()
            }
        }
        RecentEvents = Invoke-AVASafeCollector -Name 'Events' -ScriptBlock {
            @(Get-WinEvent -LogName System -MaxEvents 30 |
                Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message)
        }
    }
}

function New-AVABaselineShape {
    param([Parameter(Mandatory)][object]$Snapshot)

    return [pscustomobject][ordered]@{
        CreatedUtc = Get-AVAUtcTimestamp
        Administrators = @($Snapshot.Administrators | ForEach-Object {
            "$($_.Name)|$($_.SID)"
        } | Sort-Object -Unique)
        Neighbors = @($Snapshot.Neighbors | ForEach-Object {
            "$($_.IPAddress)|$($_.LinkLayerAddress)"
        } | Sort-Object -Unique)
        ScheduledTasks = @($Snapshot.ScheduledTasks | ForEach-Object {
            "$($_.TaskPath)$($_.TaskName)|$($_.Actions)"
        } | Sort-Object -Unique)
        Services = @($Snapshot.Services | ForEach-Object {
            "$($_.Name)|$($_.PathName)"
        } | Sort-Object -Unique)
    }
}

function Get-AVASetDelta {
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

    return @($Current | Where-Object {
        $null -ne $_ -and -not $known.ContainsKey([string]$_)
    })
}

function Get-AVABaseline {
    param([Parameter(Mandatory)][object]$Snapshot)

    if (-not (Test-Path -LiteralPath $script:BaselinePath -PathType Leaf)) {
        $baseline = New-AVABaselineShape -Snapshot $Snapshot
        Write-AVAJson -Path $script:BaselinePath -Data $baseline
        return $baseline
    }

    return Read-AVAJson -Path $script:BaselinePath -DefaultValue (New-AVABaselineShape -Snapshot $Snapshot)
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
        $Evidence | ConvertTo-Json -Depth 6 -Compress
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
        Add-AVAFinding -List $findings -Severity 85 -Category 'DEFENDER' `
            -Key 'PROTECTION_OFF' -Description 'Defender protection appears disabled.' `
            -Evidence $Snapshot.Defender
    }

    $disabledFirewall = @($Snapshot.Firewall | Where-Object { $_.Enabled -eq $false })
    if ($disabledFirewall.Count -gt 0) {
        Add-AVAFinding -List $findings -Severity 70 -Category 'FIREWALL' `
            -Key 'PROFILE_OFF' -Description 'At least one firewall profile is disabled.' `
            -Evidence $disabledFirewall
    }

    $riskConnection = @($Snapshot.Connections | Where-Object {
        ($script:RiskPorts -contains [int]$_.LocalPort) -or
        ($script:RiskPorts -contains [int]$_.RemotePort)
    })
    if ($riskConnection.Count -gt 0) {
        Add-AVAFinding -List $findings -Severity 45 -Category 'NETWORK' `
            -Key 'RISK_PORT' -Description 'A monitored port is present. This is an indicator, not attribution.' `
            -Evidence ($riskConnection | Select-Object -First 20)
    }

    $suspiciousProcess = @($Snapshot.Processes | Where-Object {
        [string]$_.CommandLine -match $script:SuspiciousPattern
    })
    if ($suspiciousProcess.Count -gt 0) {
        Add-AVAFinding -List $findings -Severity 90 -Category 'PROCESS' `
            -Key 'SUSPICIOUS_COMMAND_LINE' -Description 'A command line matches a monitored pattern.' `
            -Evidence ($suspiciousProcess | Select-Object -First 20)
    }

    $temporaryProcess = @($Snapshot.Processes | Where-Object {
        [string]$_.Path -match '(?i)(\\AppData\\Local\\Temp\\|\\Windows\\Temp\\|\\Temp\\)'
    })
    if ($temporaryProcess.Count -gt 0) {
        Add-AVAFinding -List $findings -Severity 55 -Category 'PROCESS' `
            -Key 'TEMP_PATH_PROCESS' -Description 'A process runs from a temporary path. Review; do not auto-delete.' `
            -Evidence ($temporaryProcess | Select-Object -First 20)
    }

    $current = New-AVABaselineShape -Snapshot $Snapshot
    foreach ($delta in @(
            @{ Name = 'NEW_ADMINISTRATOR'; Severity = 95; Current = $current.Administrators; Baseline = $Baseline.Administrators },
            @{ Name = 'NEW_NEIGHBOR'; Severity = 35; Current = $current.Neighbors; Baseline = $Baseline.Neighbors },
            @{ Name = 'NEW_SCHEDULED_TASK'; Severity = 65; Current = $current.ScheduledTasks; Baseline = $Baseline.ScheduledTasks },
            @{ Name = 'NEW_SERVICE'; Severity = 60; Current = $current.Services; Baseline = $Baseline.Services }
        )) {
        $newItem = Get-AVASetDelta -Current @($delta.Current) -Baseline @($delta.Baseline)
        if ($newItem.Count -gt 0) {
            Add-AVAFinding -List $findings -Severity $delta.Severity -Category 'BASELINE' `
                -Key $delta.Name -Description "$($delta.Name) compared with the local baseline." `
                -Evidence ($newItem | Select-Object -First 30)
        }
    }

    $measure = @($findings | Measure-Object -Property Severity -Sum)
    $sum = if ($null -eq $measure[0].Sum) { 0 } else { [int]$measure[0].Sum }
    $score = [Math]::Min(100, $sum)

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
        TimestampUtc = Get-AVAUtcTimestamp
        RiskScore = $score
        Status = $status
        Decision = $decision
        FindingsCount = @($findings).Count
        Findings = @($findings | Sort-Object Severity -Descending)
        Rule = 'Facts before fear. Indicators require verification. No attribution without evidence.'
    }
}

function Add-AVATangleEntry {
    param(
        [Parameter(Mandatory)][object]$Snapshot,
        [Parameter(Mandatory)][object]$Analysis
    )

    $defaultState = [pscustomobject][ordered]@{ Cycle = 0; LastMainHash = '' }
    $state = Read-AVAJson -Path $script:TangleStatePath -DefaultValue $defaultState
    $cycle = [int]$state.Cycle + 1

    $payload = [ordered]@{
        Type = 'MAIN'
        Cycle = $cycle
        TimestampUtc = Get-AVAUtcTimestamp
        PreviousHash = [string]$state.LastMainHash
        SnapshotHash = Get-AVASha256 $Snapshot
        AnalysisHash = Get-AVASha256 $Analysis
        RiskScore = $Analysis.RiskScore
        Status = $Analysis.Status
        FindingsCount = $Analysis.FindingsCount
    }
    $payload.CurrentHash = Get-AVASha256 $payload

    Add-AVAJsonLine -Path $script:TanglePath -Data $payload
    Write-AVAJson -Path $script:TangleStatePath -Data ([pscustomobject][ordered]@{
        Cycle = $cycle
        LastMainHash = $payload.CurrentHash
    })

    return [pscustomobject][ordered]@{
        Cycle = $cycle
        MainHash = $payload.CurrentHash
        PreviousHash = $payload.PreviousHash
    }
}

function ConvertTo-AVAHtmlTable {
    param(
        [AllowNull()][object[]]$Item,
        [string[]]$Property,
        [int]$Maximum = 80
    )

    $selected = @($Item | Select-Object -First $Maximum)
    if ($selected.Count -eq 0) {
        return '<p>No entries.</p>'
    }

    return (($selected | Select-Object -Property $Property | ConvertTo-Html -Fragment) -join "`n")
}

function Write-AVAPortal {
    param(
        [Parameter(Mandatory)][object]$Snapshot,
        [Parameter(Mandatory)][object]$Analysis,
        [Parameter(Mandatory)][object]$Tangle
    )

    $manifest = @(
        $script:BaselinePath,
        $script:TangleStatePath,
        $script:SnapshotPath,
        $script:AnalysisPath,
        $script:EventPath,
        $script:AlertPath,
        $script:TanglePath
    ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | ForEach-Object {
        $hash = Get-FileHash -LiteralPath $_ -Algorithm SHA256
        [pscustomobject][ordered]@{
            Path = $_
            Algorithm = $hash.Algorithm
            Hash = $hash.Hash
            Length = (Get-Item -LiteralPath $_).Length
        }
    }
    Write-AVAJson -Path $script:ManifestPath -Data @($manifest)

    $findingHtml = ConvertTo-AVAHtmlTable -Item $Analysis.Findings `
        -Property @('Severity', 'Category', 'Key', 'Description', 'Evidence') -Maximum 100
    $connectionHtml = ConvertTo-AVAHtmlTable -Item $Snapshot.Connections `
        -Property @('State', 'LocalAddress', 'LocalPort', 'RemoteAddress', 'RemotePort', 'ProcessName')
    $administratorHtml = ConvertTo-AVAHtmlTable -Item $Snapshot.Administrators `
        -Property @('Name', 'ObjectClass', 'SID')
    $manifestHtml = ConvertTo-AVAHtmlTable -Item $manifest `
        -Property @('Algorithm', 'Hash', 'Length', 'Path')

    $encodedComputer = [Net.WebUtility]::HtmlEncode([string]$Snapshot.Computer.ComputerName)
    $encodedUser = [Net.WebUtility]::HtmlEncode([string]$Snapshot.Computer.UserName)

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
<section><p>Computer: $encodedComputer | User: $encodedUser | UTC: $($Snapshot.TimestampUtc)</p><p>Main hash: $($Tangle.MainHash)</p></section>
<section><h2>Findings</h2>$findingHtml</section>
<section><h2>Administrators</h2>$administratorHtml</section>
<section><h2>Connections</h2>$connectionHtml</section>
<section><h2>SHA256 manifest</h2>$manifestHtml</section>
<section><pre>Preserve evidence. Verify context. Do not attribute without proof. Do not attack.</pre></section>
</body>
</html>
"@

    $html | Out-File -LiteralPath $script:PortalPath -Encoding utf8 -Force
}

function Invoke-AVACycle {
    Initialize-AVADirectory
    $snapshot = Get-AVASnapshot
    $baseline = Get-AVABaseline -Snapshot $snapshot
    $analysis = New-AVAAnalysis -Snapshot $snapshot -Baseline $baseline
    $tangle = Add-AVATangleEntry -Snapshot $snapshot -Analysis $analysis

    Write-AVAJson -Path $script:SnapshotPath -Data $snapshot
    Write-AVAJson -Path $script:AnalysisPath -Data $analysis
    Add-AVAJsonLine -Path $script:EventPath -Data ([pscustomobject][ordered]@{
        Type = 'CYCLE'
        TimestampUtc = Get-AVAUtcTimestamp
        Cycle = $tangle.Cycle
        RiskScore = $analysis.RiskScore
        Status = $analysis.Status
        MainHash = $tangle.MainHash
    })

    foreach ($finding in @($analysis.Findings)) {
        Add-AVAJsonLine -Path $script:AlertPath -Data ([pscustomobject][ordered]@{
            Type = 'ALERT'
            TimestampUtc = Get-AVAUtcTimestamp
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

    return [pscustomobject][ordered]@{
        Snapshot = $snapshot
        Analysis = $analysis
        Tangle = $tangle
    }
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

Initialize-AVADirectory

switch ($Mode) {
    'OpenPortal' {
        if (-not (Test-Path -LiteralPath $script:PortalPath -PathType Leaf)) {
            throw "Portal not found: $($script:PortalPath)"
        }
        Start-Process -FilePath $script:PortalPath
    }
    'InstallTask' {
        Install-AVALocalTask
    }
    'UninstallTask' {
        Uninstall-AVALocalTask
    }
    'Once' {
        Invoke-AVACycle | Out-Null
        if ($OpenPortal) {
            Start-Process -FilePath $script:PortalPath
        }
    }
    'Loop' {
        $cycle = 0
        while ($true) {
            Invoke-AVACycle | Out-Null
            if ($OpenPortal -and $cycle -eq 0) {
                Start-Process -FilePath $script:PortalPath
            }
            $cycle++
            if ($MaxCycles -gt 0 -and $cycle -ge $MaxCycles) {
                break
            }
            Start-Sleep -Seconds $IntervalSeconds
        }
    }
}
