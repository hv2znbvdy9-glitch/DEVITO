#requires -Version 5.1
<#
.SYNOPSIS
    Local, bounded AVA evidence collection and verification.

.DESCRIPTION
    This script is for a local authorized Windows host only.
    It reads local state and writes only beneath an explicitly local AVA directory.
    No remote scanning. No remote scanning or counterattack. No persistence tasks.
    Every loop is finite, every existing state file is parsed fail-closed, and every
    main-chain entry hashes the exact snapshot and analysis bytes stored on disk.

    Marker: AVA 01610 1
#>

[CmdletBinding()]
param(
    [ValidateSet('Once', 'Loop', 'OpenPortal')]
    [string]$Mode = 'Once',

    [ValidateRange(30, 86400)]
    [int]$IntervalSeconds = 60,

    [ValidateRange(1, 10080)]
    [int]$MaxCycles = 1,

    [switch]$OpenPortal,

    [string]$OutputDirectory = '',

    [ValidateRange(1048576, 1073741824)]
    [long]$MaxLogBytes = 10485760,

    [ValidateRange(104857600, 10737418240)]
    [long]$MaxEvidenceBytes = 1073741824,

    [ValidateRange(1, 100000)]
    [int]$MaxChainCycles = 10080
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Marker = 'AVA 01610 1'
$script:Version = '1.1-safe'
$script:RiskPorts = @(21, 23, 135, 139, 445, 3389, 5985, 5986)
$script:SuspiciousProcessNames = @(
    'powershell.exe', 'pwsh.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
    'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe',
    'bitsadmin.exe', 'python.exe', 'pythonw.exe'
)
$script:SuspiciousPattern = '(?i)(-enc\b|encodedcommand|downloadstring|invoke-expression|\biex\b|-nop\b|noprofile|-w\s+hidden|windowstyle\s+hidden|executionpolicy\s+bypass|-ep\s+bypass|frombase64string|bitsadmin|certutil|mshta|regsvr32|rundll32)'
$script:Utf8NoBom = [Text.UTF8Encoding]::new($false)
$script:MaxLogBytes = $MaxLogBytes
$script:MaxEvidenceBytes = $MaxEvidenceBytes
$script:MaxChainCycles = $MaxChainCycles
$script:LegacyTaskName = 'AVA_NeuroTangle_60s_SAFE'

function Get-AVAStringHash {
    param([AllowNull()][object]$InputObject)

    $text = if ($null -eq $InputObject) {
        ''
    }
    elseif ($InputObject -is [string]) {
        [string]$InputObject
    }
    else {
        $InputObject | ConvertTo-Json -Depth 40 -Compress
    }

    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($text)
        return ([BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $algorithm.Dispose()
    }
}

function Resolve-AVALocalPath {
    param([Parameter(Mandatory)][string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw 'The AVA output directory cannot be empty.'
    }
    if ($Path.StartsWith('\\') -or $Path.StartsWith('//')) {
        throw 'UNC and network output paths are not permitted.'
    }

    $fullPath = [IO.Path]::GetFullPath($Path)
    $pathRoot = [IO.Path]::GetPathRoot($fullPath)
    if ([string]::IsNullOrWhiteSpace($pathRoot) -or $pathRoot.StartsWith('\\')) {
        throw 'The AVA output directory must be on a local file-system drive.'
    }

    if ($pathRoot -match '^[A-Za-z]:\\$') {
        $drive = Get-PSDrive -Name $pathRoot.Substring(0, 1) -ErrorAction SilentlyContinue
        if ($null -eq $drive -or $drive.Provider.Name -ne 'FileSystem') {
            throw 'The AVA output directory is not on a local file-system drive.'
        }
        $displayRoot = if ($drive.PSObject.Properties.Name -contains 'DisplayRoot') {
            [string]$drive.DisplayRoot
        }
        else {
            ''
        }
        if (-not [string]::IsNullOrWhiteSpace($displayRoot) -and $displayRoot -match '^[\\/]{2}') {
            throw 'Mapped network output paths are not permitted.'
        }
    }

    if ($fullPath.TrimEnd('\\', '/') -eq $pathRoot.TrimEnd('\\', '/')) {
        throw 'A volume root cannot be used as the AVA output directory.'
    }

    return $fullPath.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$script:IsAdministrator = $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

$defaultRoot = if ($script:IsAdministrator) {
    'C:\Windows\SecurityGuardian\AVA_NeuroTangle_SAFE'
}
else {
    Join-Path $env:LOCALAPPDATA 'AVA_NeuroTangle_SAFE'
}

$requestedRoot = if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $defaultRoot
}
else {
    $OutputDirectory
}

$script:Root = Resolve-AVALocalPath -Path $requestedRoot
$script:Logs = Join-Path $script:Root 'Logs'
$script:Branches = Join-Path $script:Logs 'branches.jsonl'
$script:Events = Join-Path $script:Logs 'events.jsonl'
$script:Alerts = Join-Path $script:Logs 'alerts.jsonl'
$script:Tangle = Join-Path $script:Logs 'tangle.jsonl'
$script:State = Join-Path $script:Root 'State'
$script:Baseline = Join-Path $script:State 'baseline.json'
$script:TangleState = Join-Path $script:State 'tangle_state.json'
$script:Reports = Join-Path $script:Root 'Reports'
$script:SnapshotArchive = Join-Path $script:Reports 'Snapshots'
$script:AnalysisArchive = Join-Path $script:Reports 'Analyses'
$script:LatestSnapshot = Join-Path $script:Reports 'latest_snapshot.json'
$script:LatestAnalysis = Join-Path $script:Reports 'latest_analysis.json'
$script:Manifest = Join-Path $script:Reports 'sha256_manifest.json'
$script:Portal = Join-Path $script:Root 'Portal'
$script:PortalFile = Join-Path $script:Portal 'ava_neuro_tangle_portal.html'
$script:MutexName = 'Local\AVA_NeuroTangle_' + (Get-AVAStringHash -InputObject $script:Root).Substring(0, 24)

function Test-AVAContainedPath {
    param([Parameter(Mandatory)][string]$Path)

    $fullPath = [IO.Path]::GetFullPath($Path)
    $prefix = $script:Root.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    return $fullPath.Equals($script:Root, [StringComparison]::OrdinalIgnoreCase) -or
        $fullPath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
}

function Initialize-AVAStorage {
    foreach ($directory in @(
            $script:Root,
            $script:Logs,
            $script:State,
            $script:Reports,
            $script:SnapshotArchive,
            $script:AnalysisArchive,
            $script:Portal
        )) {
        if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
            New-Item -ItemType Directory -Path $directory -Force | Out-Null
        }
    }
}

function Get-AVAUtc {
    return (Get-Date).ToUniversalTime().ToString('o')
}

function Write-AVAAtomicText {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Text
    )

    if (-not (Test-AVAContainedPath -Path $Path)) {
        throw "Refusing to write outside the AVA root: $Path"
    }

    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw "Destination directory does not exist: $parent"
    }

    $temporary = $Path + '.pending'
    if (Test-Path -LiteralPath $temporary) {
        throw "A prior atomic write did not finish; preserve and inspect: $temporary"
    }
    [IO.File]::WriteAllText($temporary, $Text, $script:Utf8NoBom)
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        [IO.File]::Replace($temporary, $Path, $null)
    }
    else {
        [IO.File]::Move($temporary, $Path)
    }
}

function Write-AVAJson {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowNull()][object]$Data
    )

    $json = $Data | ConvertTo-Json -Depth 40
    Write-AVAAtomicText -Path $Path -Text ($json + [Environment]::NewLine)
}

function Test-AVAEvidenceCapacity {
    param([ValidateRange(0, 10737418240)][long]$AdditionalBytes = 0)

    $currentBytes = 0L
    $measurement = Get-ChildItem -LiteralPath $script:Root -File -Recurse -ErrorAction Stop |
        Measure-Object -Property Length -Sum
    if ($null -ne $measurement.Sum) {
        $currentBytes = [long]$measurement.Sum
    }
    if (($currentBytes + $AdditionalBytes) -gt $script:MaxEvidenceBytes) {
        throw 'AVA evidence size cap would be exceeded. Preserve the directory and start a separately reviewed archive.'
    }
}

function Test-AVAPendingWrite {
    $pending = @(Get-ChildItem -LiteralPath $script:Root -File -Recurse -Filter '*.pending' -ErrorAction Stop)
    if ($pending.Count -gt 0) {
        throw "A prior atomic write did not finish; preserve and inspect: $($pending[0].FullName)"
    }
}

function Get-AVAJsonFile {
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$AllowMissing
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        if ($AllowMissing) {
            return $null
        }
        throw "Required AVA JSON file is missing: $Path"
    }

    try {
        $raw = [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8)
        if ([string]::IsNullOrWhiteSpace($raw)) {
            throw 'The file is empty.'
        }
        return $raw | ConvertFrom-Json
    }
    catch {
        throw "AVA JSON validation failed for '$Path': $($_.Exception.Message)"
    }
}

function Get-AVAJsonlRecord {
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$AllowMissing
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        if ($AllowMissing) {
            return @()
        }
        throw "Required AVA JSONL file is missing: $Path"
    }

    $lines = @(Get-Content -LiteralPath $Path -Encoding utf8)
    if ($lines.Count -eq 0) {
        throw "AVA JSONL validation failed because the file is empty: $Path"
    }

    $items = [Collections.Generic.List[object]]::new()
    for ($index = 0; $index -lt $lines.Count; $index++) {
        if ([string]::IsNullOrWhiteSpace([string]$lines[$index])) {
            throw "AVA JSONL validation failed at line $($index + 1) in '$Path': blank line."
        }
        try {
            [void]$items.Add(($lines[$index] | ConvertFrom-Json))
        }
        catch {
            throw "AVA JSONL validation failed at line $($index + 1) in '$Path': $($_.Exception.Message)"
        }
    }
    return @($items)
}

function Add-AVAJsonLine {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][object]$Data
    )

    if (-not (Test-AVAContainedPath -Path $Path)) {
        throw "Refusing to append outside the AVA root: $Path"
    }

    $line = ($Data | ConvertTo-Json -Depth 40 -Compress) + [Environment]::NewLine
    $bytes = $script:Utf8NoBom.GetBytes($line)
    $existingLength = if (Test-Path -LiteralPath $Path -PathType Leaf) {
        (Get-Item -LiteralPath $Path).Length
    }
    else {
        0
    }
    if (($existingLength + $bytes.Length) -gt $script:MaxLogBytes) {
        throw "AVA log size cap would be exceeded: $Path"
    }

    $stream = [IO.FileStream]::new(
        $Path,
        [IO.FileMode]::Append,
        [IO.FileAccess]::Write,
        [IO.FileShare]::Read
    )
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
}

function Get-AVAProperty {
    param(
        [AllowNull()][object]$Object,
        [Parameter(Mandatory)][string]$Name,
        [AllowNull()][object]$DefaultValue = $null
    )

    if ($null -ne $Object -and $Object.PSObject.Properties.Name -contains $Name) {
        return $Object.$Name
    }
    return $DefaultValue
}

function Test-AVACollectorUnavailable {
    param([AllowNull()][object]$Value)

    return $null -ne $Value -and
        $Value.PSObject.Properties.Name -contains 'Available' -and
        (Get-AVAProperty -Object $Value -Name 'Available' -DefaultValue $true) -eq $false
}

function ConvertTo-AVAItemArray {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value -or (Test-AVACollectorUnavailable -Value $Value)) {
        return @()
    }
    return @($Value)
}

function Invoke-AVASafeCollect {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock
    )

    try {
        return & $ScriptBlock
    }
    catch {
        return [pscustomobject][ordered]@{
            Available = $false
            Collector = $Name
            Error = $_.Exception.Message
        }
    }
}

function Get-AVAWlanNetwork {
    $output = @(& netsh.exe wlan show networks mode=bssid 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw "netsh.exe returned exit code $LASTEXITCODE."
    }

    $networks = [Collections.Generic.List[object]]::new()
    $currentSsid = ''
    foreach ($line in $output) {
        $text = [string]$line
        if ($text -match '^\s*SSID\s+\d+\s*:\s*(.*)$' -and $text -notmatch '^\s*BSSID') {
            $currentSsid = $Matches[1].Trim()
        }
        elseif ($text -match '^\s*BSSID\s+\d+\s*:\s*(.+)$') {
            [void]$networks.Add([pscustomobject][ordered]@{
                SSID = $currentSsid
                BSSID = $Matches[1].Trim().ToLowerInvariant()
            })
        }
    }
    return @($networks)
}

function Get-AVARecentEvent {
    $eventRows = [Collections.Generic.List[object]]::new()
    $logNames = @(
        'Microsoft-Windows-Windows Defender/Operational',
        'Microsoft-Windows-PowerShell/Operational',
        'System'
    )

    foreach ($logName in $logNames) {
        try {
            Get-WinEvent -LogName $logName -MaxEvents 25 -ErrorAction Stop | ForEach-Object {
                [void]$eventRows.Add([pscustomobject][ordered]@{
                    Available = $true
                    LogName = $logName
                    TimeCreated = $_.TimeCreated
                    Id = $_.Id
                    LevelDisplay = $_.LevelDisplayName
                    Provider = $_.ProviderName
                    Message = ([string]$_.Message -replace '\s+', ' ').Trim()
                })
            }
        }
        catch {
            [void]$eventRows.Add([pscustomobject][ordered]@{
                Available = $false
                LogName = $logName
                Error = $_.Exception.Message
            })
        }
    }
    return @($eventRows)
}

function Get-AVASnapshot {
    return [pscustomobject][ordered]@{
        AVA = 'NEURO_TANGLE_GUARDIAN_SAFE'
        Marker = $script:Marker
        Version = $script:Version
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
                AMServiceEnabled = $status.AMServiceEnabled
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
            }
            else {
                @(Get-LocalGroupMember -Group $group.Name | Select-Object Name, ObjectClass, SID)
            }
        }
        Processes = Invoke-AVASafeCollect -Name 'Processes' -ScriptBlock {
            @(Get-CimInstance Win32_Process | ForEach-Object {
                [pscustomobject][ordered]@{
                    PID = [int]$_.ProcessId
                    Name = $_.Name
                    Path = $_.ExecutablePath
                    CommandLine = $_.CommandLine
                }
            })
        }
        Connections = Invoke-AVASafeCollect -Name 'Connections' -ScriptBlock {
            @(Get-NetTCPConnection | Where-Object {
                $_.State -in @('Listen', 'Established', 'SynSent')
            } | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess)
        }
        ScheduledTasks = Invoke-AVASafeCollect -Name 'ScheduledTasks' -ScriptBlock {
            @(Get-ScheduledTask | Where-Object {
                $_.TaskPath -notlike '\Microsoft\*' -and $_.TaskName -ne $script:LegacyTaskName
            } | ForEach-Object {
                [pscustomobject][ordered]@{
                    TaskPath = $_.TaskPath
                    TaskName = $_.TaskName
                    State = $_.State
                    Actions = (@($_.Actions | ForEach-Object {
                                "$($_.Execute) $($_.Arguments)".Trim()
                            }) -join ' | ')
                }
            })
        }
        Services = Invoke-AVASafeCollect -Name 'Services' -ScriptBlock {
            @(Get-CimInstance Win32_Service | Where-Object { $_.State -eq 'Running' } |
                Select-Object Name, DisplayName, StartMode, StartName, PathName)
        }
        Neighbors = Invoke-AVASafeCollect -Name 'Neighbors' -ScriptBlock {
            @(Get-NetNeighbor -AddressFamily IPv4 | Where-Object { $_.State -ne 'Unreachable' } |
                Select-Object IPAddress, LinkLayerAddress, State, InterfaceIndex)
        }
        NetAdapters = Invoke-AVASafeCollect -Name 'NetAdapters' -ScriptBlock {
            @(Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, MacAddress, LinkSpeed, InterfaceIndex)
        }
        WLAN = Invoke-AVASafeCollect -Name 'WLAN' -ScriptBlock {
            @(Get-AVAWlanNetwork)
        }
        RecentEvents = Invoke-AVASafeCollect -Name 'RecentEvents' -ScriptBlock {
            @(Get-AVARecentEvent)
        }
    }
}

function ConvertTo-AVABaselineSet {
    param(
        [AllowNull()][object]$Value,
        [Parameter(Mandatory)][scriptblock]$Projection
    )

    if (Test-AVACollectorUnavailable -Value $Value) {
        return @()
    }
    return @(ConvertTo-AVAItemArray -Value $Value | ForEach-Object $Projection | Where-Object {
            -not [string]::IsNullOrWhiteSpace([string]$_)
        } | Sort-Object -Unique)
}

function Get-AVABaselineShape {
    param([Parameter(Mandatory)][object]$Snapshot)

    return [pscustomobject][ordered]@{
        CreatedUtc = Get-AVAUtc
        Administrators = @(ConvertTo-AVABaselineSet -Value $Snapshot.Administrators -Projection {
                "$($_.Name)|$($_.SID)"
            })
        Neighbors = @(ConvertTo-AVABaselineSet -Value $Snapshot.Neighbors -Projection {
                "$($_.IPAddress)|$($_.LinkLayerAddress)"
            })
        WlanBssids = @(ConvertTo-AVABaselineSet -Value $Snapshot.WLAN -Projection {
                "$($_.SSID)|$($_.BSSID)"
            })
        ScheduledTasks = @(ConvertTo-AVABaselineSet -Value $Snapshot.ScheduledTasks -Projection {
                "$($_.TaskPath)$($_.TaskName)|$($_.Actions)"
            })
        Services = @(ConvertTo-AVABaselineSet -Value $Snapshot.Services -Projection {
                "$($_.Name)|$($_.PathName)"
            })
        NetAdapters = @(ConvertTo-AVABaselineSet -Value $Snapshot.NetAdapters -Projection {
                "$($_.Name)|$($_.MacAddress)|$($_.InterfaceDescription)"
            })
    }
}

function Test-AVABaselineShape {
    param([Parameter(Mandatory)][object]$Baseline)

    $required = @(
        'CreatedUtc', 'Administrators', 'Neighbors', 'WlanBssids',
        'ScheduledTasks', 'Services', 'NetAdapters'
    )
    foreach ($name in $required) {
        if ($Baseline.PSObject.Properties.Name -notcontains $name) {
            throw "Baseline schema validation failed: missing '$name'."
        }
    }
}

function Get-AVABaseline {
    param([Parameter(Mandatory)][object]$Snapshot)

    if (-not (Test-Path -LiteralPath $script:Baseline -PathType Leaf)) {
        $baseline = Get-AVABaselineShape -Snapshot $Snapshot
        Write-AVAJson -Path $script:Baseline -Data $baseline
        return $baseline
    }

    $baseline = Get-AVAJsonFile -Path $script:Baseline
    Test-AVABaselineShape -Baseline $baseline
    return $baseline
}

function Compare-AVAStringSet {
    param(
        [AllowNull()][object[]]$Current,
        [AllowNull()][object[]]$Baseline
    )

    $currentSet = @{}
    $baselineSet = @{}
    foreach ($item in @($Current)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$item)) {
            $currentSet[[string]$item] = $true
        }
    }
    foreach ($item in @($Baseline)) {
        if (-not [string]::IsNullOrWhiteSpace([string]$item)) {
            $baselineSet[[string]$item] = $true
        }
    }

    return [pscustomobject][ordered]@{
        Added = @($currentSet.Keys | Where-Object { -not $baselineSet.ContainsKey($_) } | Sort-Object)
        Removed = @($baselineSet.Keys | Where-Object { -not $currentSet.ContainsKey($_) } | Sort-Object)
    }
}

function Add-AVAFinding {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[object]]$List,
        [Parameter(Mandatory)][ValidateRange(0, 100)][int]$Severity,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$Description,
        [AllowNull()][object]$Evidence
    )

    $evidenceText = if ($Evidence -is [string]) {
        [string]$Evidence
    }
    elseif ($null -eq $Evidence) {
        ''
    }
    else {
        $Evidence | ConvertTo-Json -Depth 8 -Compress
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

function Get-AVAAnalysis {
    param(
        [Parameter(Mandatory)][object]$Snapshot,
        [Parameter(Mandatory)][object]$Baseline
    )

    $findings = [Collections.Generic.List[object]]::new()
    $bits = [ordered]@{
        DefenderOff = 0
        FirewallOff = 0
        RiskPort = 0
        SuspiciousCmd = 0
        NewAdmin = 0
        NewNeighbor = 0
        NewWlan = 0
        NewTask = 0
        NewService = 0
        NewAdapter = 0
        RemovedBaseline = 0
        CollectorError = 0
    }

    foreach ($collectorName in @(
            'Computer', 'Defender', 'Firewall', 'Administrators', 'Processes',
            'Connections', 'ScheduledTasks', 'Services', 'Neighbors', 'NetAdapters',
            'WLAN', 'RecentEvents'
        )) {
        $collectorValue = Get-AVAProperty -Object $Snapshot -Name $collectorName
        if (Test-AVACollectorUnavailable -Value $collectorValue) {
            $bits.CollectorError = 1
            Add-AVAFinding -List $findings -Severity 15 -Category 'COLLECTOR' -Key ("UNAVAILABLE_$collectorName".ToUpperInvariant()) `
                -Description "The $collectorName collector was unavailable; analysis is incomplete." `
                -Evidence (Get-AVAProperty -Object $collectorValue -Name 'Error' -DefaultValue 'Unknown collector error.')
        }
    }

    foreach ($eventError in @(ConvertTo-AVAItemArray -Value $Snapshot.RecentEvents | Where-Object {
                (Get-AVAProperty -Object $_ -Name 'Available' -DefaultValue $true) -eq $false
            })) {
        $bits.CollectorError = 1
        $logName = [string](Get-AVAProperty -Object $eventError -Name 'LogName' -DefaultValue 'Unknown')
        $logKey = (Get-AVAStringHash -InputObject $logName).Substring(0, 12).ToUpperInvariant()
        Add-AVAFinding -List $findings -Severity 15 -Category 'COLLECTOR' -Key "EVENT_LOG_UNAVAILABLE_$logKey" `
            -Description "The event log '$logName' was unavailable; event analysis is incomplete." `
            -Evidence (Get-AVAProperty -Object $eventError -Name 'Error' -DefaultValue 'Unknown event-log error.')
    }

    if (-not (Test-AVACollectorUnavailable -Value $Snapshot.Defender)) {
        $realTime = Get-AVAProperty -Object $Snapshot.Defender -Name 'RealTimeProtectionEnabled'
        $antivirus = Get-AVAProperty -Object $Snapshot.Defender -Name 'AntivirusEnabled'
        $service = Get-AVAProperty -Object $Snapshot.Defender -Name 'AMServiceEnabled'
        if ($realTime -eq $false -or $antivirus -eq $false -or $service -eq $false) {
            $bits.DefenderOff = 1
            Add-AVAFinding -List $findings -Severity 70 -Category 'DEFENDER' -Key 'PROTECTION_OFF' `
                -Description 'Defender protection appears disabled or incomplete.' -Evidence $Snapshot.Defender
        }
    }

    $disabledFirewall = @(ConvertTo-AVAItemArray -Value $Snapshot.Firewall | Where-Object { $_.Enabled -eq $false })
    if ($disabledFirewall.Count -gt 0) {
        $bits.FirewallOff = 1
        Add-AVAFinding -List $findings -Severity 65 -Category 'FIREWALL' -Key 'PROFILE_OFF' `
            -Description 'At least one firewall profile is disabled.' -Evidence $disabledFirewall
    }

    $riskConnections = @(ConvertTo-AVAItemArray -Value $Snapshot.Connections | Where-Object {
            ($script:RiskPorts -contains [int]$_.LocalPort) -or
            ($script:RiskPorts -contains [int]$_.RemotePort)
        })
    if ($riskConnections.Count -gt 0) {
        $bits.RiskPort = 1
        Add-AVAFinding -List $findings -Severity 25 -Category 'NETWORK' -Key 'RISK_PORT_PRESENT' `
            -Description 'A monitored port is present. This is an indicator, not attribution.' `
            -Evidence ($riskConnections | Select-Object -First 20)
    }

    $suspiciousProcesses = @(ConvertTo-AVAItemArray -Value $Snapshot.Processes | Where-Object {
            $processName = ([string]$_.Name).ToLowerInvariant()
            $script:SuspiciousProcessNames -contains $processName -and
            [string]$_.CommandLine -match $script:SuspiciousPattern
        })
    if ($suspiciousProcesses.Count -gt 0) {
        $bits.SuspiciousCmd = 1
        Add-AVAFinding -List $findings -Severity 90 -Category 'PROCESS' -Key 'SUSPICIOUS_COMMAND_LINE' `
            -Description 'A monitored process command line matches a suspicious pattern.' `
            -Evidence ($suspiciousProcesses | Select-Object -First 20)
    }

    $current = Get-AVABaselineShape -Snapshot $Snapshot
    $deltaDefinitions = @(
        [pscustomobject]@{ Name = 'Administrators'; Key = 'ADMINISTRATOR'; Bit = 'NewAdmin'; Severity = 95 },
        [pscustomobject]@{ Name = 'Neighbors'; Key = 'NEIGHBOR'; Bit = 'NewNeighbor'; Severity = 35 },
        [pscustomobject]@{ Name = 'WlanBssids'; Key = 'WLAN_BSSID'; Bit = 'NewWlan'; Severity = 30 },
        [pscustomobject]@{ Name = 'ScheduledTasks'; Key = 'SCHEDULED_TASK'; Bit = 'NewTask'; Severity = 65 },
        [pscustomobject]@{ Name = 'Services'; Key = 'SERVICE'; Bit = 'NewService'; Severity = 60 },
        [pscustomobject]@{ Name = 'NetAdapters'; Key = 'NET_ADAPTER'; Bit = 'NewAdapter'; Severity = 45 }
    )
    foreach ($definition in $deltaDefinitions) {
        $currentValues = @(Get-AVAProperty -Object $current -Name $definition.Name -DefaultValue @())
        $baselineValues = @(Get-AVAProperty -Object $Baseline -Name $definition.Name -DefaultValue @())
        $delta = Compare-AVAStringSet -Current $currentValues -Baseline $baselineValues
        if (@($delta.Added).Count -gt 0) {
            $bits[$definition.Bit] = 1
            Add-AVAFinding -List $findings -Severity $definition.Severity -Category 'BASELINE' `
                -Key ("NEW_$($definition.Key)") -Description "New $($definition.Key) item compared with the local baseline." `
                -Evidence (@($delta.Added) | Select-Object -First 30)
        }
        if (@($delta.Removed).Count -gt 0) {
            $bits.RemovedBaseline = 1
            Add-AVAFinding -List $findings -Severity 30 -Category 'BASELINE' `
                -Key ("REMOVED_$($definition.Key)") -Description "Removed $($definition.Key) item compared with the local baseline." `
                -Evidence (@($delta.Removed) | Select-Object -First 30)
        }
    }

    $highest = @($findings | Sort-Object Severity -Descending | Select-Object -First 1)
    $score = if ($highest.Count -eq 0) { 0 } else { [int]$highest[0].Severity }
    $status = if ($score -ge 85) { 'CRITICAL' }
    elseif ($score -ge 60) { 'ALERT' }
    elseif ($score -ge 25) { 'NOTICE' }
    elseif ($bits.CollectorError -eq 1) { 'INCOMPLETE' }
    else { 'CALM' }

    $decision = if ($score -ge 85) { 'PRESERVE_EVIDENCE_AND_INVESTIGATE' }
    elseif ($score -ge 60) { 'REVIEW_AND_PRESERVE' }
    elseif ($score -ge 25) { 'OBSERVE_AND_COMPARE' }
    elseif ($bits.CollectorError -eq 1) { 'REVIEW_COLLECTION_GAPS' }
    else { 'CONTINUE_NORMALLY' }

    return [pscustomobject][ordered]@{
        TimestampUtc = Get-AVAUtc
        Marker = $script:Marker
        RiskScore = $score
        Status = $status
        Decision = $decision
        DecisionBit = $(if (@($findings).Count -gt 0) { 1 } else { 0 })
        Bits = [pscustomobject]$bits
        FindingsCount = @($findings).Count
        Findings = @($findings | Sort-Object -Property @(
                @{ Expression = 'Severity'; Descending = $true },
                @{ Expression = 'Category'; Descending = $false },
                @{ Expression = 'Key'; Descending = $false }
            ))
        ScoreMethod = 'Maximum finding severity; findings are not added together.'
        Rule = 'Facts before fear. Indicators require verification. No attribution without evidence.'
    }
}

function Get-AVAMainHash {
    param([Parameter(Mandatory)][object]$Block)

    $canonical = [ordered]@{
        Type = [string]$Block.Type
        Marker = [string]$Block.Marker
        Cycle = [int]$Block.Cycle
        TimestampUtc = [string]$Block.TimestampUtc
        PreviousHash = [string]$Block.PreviousHash
        SnapshotPath = [string]$Block.SnapshotPath
        SnapshotHash = [string]$Block.SnapshotHash
        AnalysisPath = [string]$Block.AnalysisPath
        AnalysisHash = [string]$Block.AnalysisHash
        RiskScore = [int]$Block.RiskScore
        Status = [string]$Block.Status
    }
    return Get-AVAStringHash -InputObject $canonical
}

function Get-AVABranchHash {
    param([Parameter(Mandatory)][object]$Block)

    $canonical = [ordered]@{
        Type = [string]$Block.Type
        Marker = [string]$Block.Marker
        BranchId = [string]$Block.BranchId
        Sequence = [int]$Block.Sequence
        TimestampUtc = [string]$Block.TimestampUtc
        PreviousHash = [string]$Block.PreviousHash
        MainHash = [string]$Block.MainHash
        FindingHash = [string]$Block.FindingHash
        Category = [string]$Block.Category
        Key = [string]$Block.Key
        Severity = [int]$Block.Severity
    }
    return Get-AVAStringHash -InputObject $canonical
}

function Resolve-AVAReferencePath {
    param([Parameter(Mandatory)][string]$RelativePath)

    if ([IO.Path]::IsPathRooted($RelativePath)) {
        throw "Tangle reference must be relative: $RelativePath"
    }
    $nativeRelative = $RelativePath.Replace('/', [IO.Path]::DirectorySeparatorChar)
    $fullPath = [IO.Path]::GetFullPath((Join-Path $script:Root $nativeRelative))
    if (-not (Test-AVAContainedPath -Path $fullPath)) {
        throw "Tangle reference escapes the AVA root: $RelativePath"
    }
    return $fullPath
}

function Test-AVATangleChain {
    $hasTangle = Test-Path -LiteralPath $script:Tangle -PathType Leaf
    $hasState = Test-Path -LiteralPath $script:TangleState -PathType Leaf
    if (-not $hasTangle -and -not $hasState) {
        return [pscustomobject][ordered]@{ Cycle = 0; LastHash = ''; Entries = @() }
    }
    if ($hasTangle -ne $hasState) {
        throw 'AVA chain validation failed: tangle log and state must either both exist or both be absent.'
    }

    $entries = @(Get-AVAJsonlRecord -Path $script:Tangle)
    $previousHash = ''
    $expectedCycle = 1
    foreach ($entry in $entries) {
        if ([string]$entry.Type -ne 'MAIN' -or [string]$entry.Marker -ne $script:Marker) {
            throw "AVA chain validation failed at cycle $expectedCycle: invalid type or marker."
        }
        if ([int]$entry.Cycle -ne $expectedCycle -or [string]$entry.PreviousHash -ne $previousHash) {
            throw "AVA chain validation failed at cycle $expectedCycle: sequence or previous hash mismatch."
        }
        if ([string]$entry.CurrentHash -ne (Get-AVAMainHash -Block $entry)) {
            throw "AVA chain validation failed at cycle $expectedCycle: block hash mismatch."
        }

        foreach ($reference in @(
                [pscustomobject]@{ Path = [string]$entry.SnapshotPath; Hash = [string]$entry.SnapshotHash },
                [pscustomobject]@{ Path = [string]$entry.AnalysisPath; Hash = [string]$entry.AnalysisHash }
            )) {
            $filePath = Resolve-AVAReferencePath -RelativePath $reference.Path
            if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
                throw "AVA chain validation failed: referenced evidence is missing: $($reference.Path)"
            }
            $actualHash = (Get-FileHash -LiteralPath $filePath -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actualHash -ne $reference.Hash) {
                throw "AVA chain validation failed: evidence hash mismatch: $($reference.Path)"
            }
        }

        $previousHash = [string]$entry.CurrentHash
        $expectedCycle++
    }

    $state = Get-AVAJsonFile -Path $script:TangleState
    if ($state.PSObject.Properties.Name -notcontains 'Cycle' -or
        $state.PSObject.Properties.Name -notcontains 'LastHash') {
        throw 'AVA chain validation failed: invalid state schema.'
    }
    if ([int]$state.Cycle -ne $entries.Count -or [string]$state.LastHash -ne $previousHash) {
        throw 'AVA chain validation failed: state does not match the verified chain head.'
    }

    return [pscustomobject][ordered]@{
        Cycle = [int]$state.Cycle
        LastHash = [string]$state.LastHash
        Entries = $entries
    }
}

function Test-AVABranchChain {
    param([AllowNull()][object[]]$MainEntries = @())

    $branchEntries = @(Get-AVAJsonlRecord -Path $script:Branches -AllowMissing)
    $heads = @{}
    $mainHashes = @{}
    foreach ($mainEntry in @($MainEntries)) {
        $mainHashes[[string]$mainEntry.CurrentHash] = $true
    }

    foreach ($entry in $branchEntries) {
        $branchId = [string]$entry.BranchId
        $prior = if ($heads.ContainsKey($branchId)) {
            $heads[$branchId]
        }
        else {
            [pscustomobject]@{ Sequence = 0; LastHash = '' }
        }
        if ([string]$entry.Type -ne 'BRANCH' -or [string]$entry.Marker -ne $script:Marker -or
            [int]$entry.Sequence -ne ([int]$prior.Sequence + 1) -or
            [string]$entry.PreviousHash -ne [string]$prior.LastHash -or
            [string]$entry.CurrentHash -ne (Get-AVABranchHash -Block $entry)) {
            throw "AVA branch-chain validation failed for '$branchId'."
        }
        if (-not $mainHashes.ContainsKey([string]$entry.MainHash)) {
            throw "AVA branch-chain validation failed: unknown main hash for '$branchId'."
        }
        $heads[$branchId] = [pscustomobject]@{
            Sequence = [int]$entry.Sequence
            LastHash = [string]$entry.CurrentHash
        }
    }

    return [pscustomobject][ordered]@{
        Entries = $branchEntries
        Heads = $heads
    }
}

function Add-AVAMainBlock {
    param(
        [Parameter(Mandatory)][object]$VerifiedChain,
        [Parameter(Mandatory)][object]$Analysis,
        [Parameter(Mandatory)][string]$SnapshotRelativePath,
        [Parameter(Mandatory)][string]$SnapshotHash,
        [Parameter(Mandatory)][string]$AnalysisRelativePath,
        [Parameter(Mandatory)][string]$AnalysisHash
    )

    $block = [pscustomobject][ordered]@{
        Type = 'MAIN'
        Marker = $script:Marker
        Cycle = [int]$VerifiedChain.Cycle + 1
        TimestampUtc = Get-AVAUtc
        PreviousHash = [string]$VerifiedChain.LastHash
        SnapshotPath = $SnapshotRelativePath
        SnapshotHash = $SnapshotHash
        AnalysisPath = $AnalysisRelativePath
        AnalysisHash = $AnalysisHash
        RiskScore = [int]$Analysis.RiskScore
        Status = [string]$Analysis.Status
        CurrentHash = ''
    }
    $block.CurrentHash = Get-AVAMainHash -Block $block
    Add-AVAJsonLine -Path $script:Tangle -Data $block
    Write-AVAJson -Path $script:TangleState -Data ([pscustomobject][ordered]@{
        Cycle = $block.Cycle
        LastHash = $block.CurrentHash
    })
    return $block
}

function Add-AVABranchBlock {
    param(
        [Parameter(Mandatory)][object]$VerifiedBranches,
        [Parameter(Mandatory)][object]$MainBlock,
        [AllowNull()][object[]]$Findings
    )

    $heads = $VerifiedBranches.Heads
    foreach ($finding in @($Findings)) {
        $branchId = 'BR_' + (Get-AVAStringHash -InputObject ("$($finding.Category)|$($finding.Key)")).Substring(0, 16)
        $prior = if ($heads.ContainsKey($branchId)) {
            $heads[$branchId]
        }
        else {
            [pscustomobject]@{ Sequence = 0; LastHash = '' }
        }
        $findingCanonical = [ordered]@{
            Severity = [int]$finding.Severity
            Category = [string]$finding.Category
            Key = [string]$finding.Key
            Description = [string]$finding.Description
            Evidence = [string]$finding.Evidence
        }
        $block = [pscustomobject][ordered]@{
            Type = 'BRANCH'
            Marker = $script:Marker
            BranchId = $branchId
            Sequence = [int]$prior.Sequence + 1
            TimestampUtc = Get-AVAUtc
            PreviousHash = [string]$prior.LastHash
            MainHash = [string]$MainBlock.CurrentHash
            FindingHash = Get-AVAStringHash -InputObject $findingCanonical
            Category = [string]$finding.Category
            Key = [string]$finding.Key
            Severity = [int]$finding.Severity
            CurrentHash = ''
        }
        $block.CurrentHash = Get-AVABranchHash -Block $block
        Add-AVAJsonLine -Path $script:Branches -Data $block
        $heads[$branchId] = [pscustomobject]@{
            Sequence = $block.Sequence
            LastHash = $block.CurrentHash
        }
    }
}

function Add-AVAAlert {
    param(
        [Parameter(Mandatory)][object]$MainBlock,
        [AllowNull()][object[]]$Findings
    )

    $known = @{}
    foreach ($alert in @(Get-AVAJsonlRecord -Path $script:Alerts -AllowMissing)) {
        if ($alert.PSObject.Properties.Name -notcontains 'Fingerprint') {
            throw 'AVA alert validation failed: missing fingerprint.'
        }
        $known[[string]$alert.Fingerprint] = $true
    }

    foreach ($finding in @($Findings)) {
        $fingerprint = Get-AVAStringHash -InputObject ("$($finding.Category)|$($finding.Key)|$($finding.Evidence)")
        if (-not $known.ContainsKey($fingerprint)) {
            Add-AVAJsonLine -Path $script:Alerts -Data ([pscustomobject][ordered]@{
                Type = 'ALERT'
                Marker = $script:Marker
                TimestampUtc = Get-AVAUtc
                Cycle = [int]$MainBlock.Cycle
                MainHash = [string]$MainBlock.CurrentHash
                Fingerprint = $fingerprint
                Severity = [int]$finding.Severity
                Category = [string]$finding.Category
                Key = [string]$finding.Key
                Description = [string]$finding.Description
                Evidence = [string]$finding.Evidence
            })
            $known[$fingerprint] = $true
        }
    }
}

function ConvertTo-AVAHtmlText {
    param([AllowNull()][object]$Value)

    return [Net.WebUtility]::HtmlEncode([string]$Value)
}

function ConvertTo-AVAHtmlTable {
    param(
        [AllowNull()][object[]]$Items,
        [Parameter(Mandatory)][string[]]$Properties,
        [ValidateRange(1, 500)][int]$Maximum = 80
    )

    $selected = @($Items | Select-Object -First $Maximum)
    if ($selected.Count -eq 0) {
        return '<p>No entries.</p>'
    }

    $builder = [Text.StringBuilder]::new()
    [void]$builder.Append('<table><thead><tr>')
    foreach ($propertyName in $Properties) {
        [void]$builder.Append('<th>')
        [void]$builder.Append((ConvertTo-AVAHtmlText -Value $propertyName))
        [void]$builder.Append('</th>')
    }
    [void]$builder.Append('</tr></thead><tbody>')
    foreach ($item in $selected) {
        [void]$builder.Append('<tr>')
        foreach ($propertyName in $Properties) {
            $value = Get-AVAProperty -Object $item -Name $propertyName -DefaultValue ''
            if ($value -is [array]) {
                $value = @($value) -join ', '
            }
            [void]$builder.Append('<td>')
            [void]$builder.Append((ConvertTo-AVAHtmlText -Value $value))
            [void]$builder.Append('</td>')
        }
        [void]$builder.Append('</tr>')
    }
    [void]$builder.Append('</tbody></table>')
    return $builder.ToString()
}

function Get-AVAManifest {
    param(
        [Parameter(Mandatory)][string]$SnapshotPath,
        [Parameter(Mandatory)][string]$AnalysisPath
    )

    $paths = @(
        $script:Baseline,
        $script:TangleState,
        $SnapshotPath,
        $AnalysisPath,
        $script:LatestSnapshot,
        $script:LatestAnalysis,
        $script:Events,
        $script:Alerts,
        $script:Tangle,
        $script:Branches
    ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Sort-Object -Unique

    return @($paths | ForEach-Object {
        $hash = Get-FileHash -LiteralPath $_ -Algorithm SHA256
        [pscustomobject][ordered]@{
            Path = [IO.Path]::GetFullPath($_).Substring($script:Root.Length).TrimStart('\', '/').Replace('\', '/')
            Algorithm = 'SHA256'
            Hash = $hash.Hash.ToLowerInvariant()
            Length = (Get-Item -LiteralPath $_).Length
        }
    })
}

function Write-AVAPortal {
    param(
        [Parameter(Mandatory)][object]$Snapshot,
        [Parameter(Mandatory)][object]$Analysis,
        [Parameter(Mandatory)][object]$MainBlock,
        [Parameter(Mandatory)][object[]]$Manifest
    )

    $findingsHtml = ConvertTo-AVAHtmlTable -Items $Analysis.Findings `
        -Properties @('Severity', 'Category', 'Key', 'Description', 'Evidence') -Maximum 100
    $administratorsHtml = ConvertTo-AVAHtmlTable -Items (ConvertTo-AVAItemArray -Value $Snapshot.Administrators) `
        -Properties @('Name', 'ObjectClass', 'SID')
    $connectionsHtml = ConvertTo-AVAHtmlTable -Items (ConvertTo-AVAItemArray -Value $Snapshot.Connections) `
        -Properties @('State', 'LocalAddress', 'LocalPort', 'RemoteAddress', 'RemotePort', 'OwningProcess')
    $wlanHtml = ConvertTo-AVAHtmlTable -Items (ConvertTo-AVAItemArray -Value $Snapshot.WLAN) `
        -Properties @('SSID', 'BSSID')
    $adaptersHtml = ConvertTo-AVAHtmlTable -Items (ConvertTo-AVAItemArray -Value $Snapshot.NetAdapters) `
        -Properties @('Name', 'Status', 'MacAddress', 'LinkSpeed', 'InterfaceDescription')
    $eventsHtml = ConvertTo-AVAHtmlTable -Items (ConvertTo-AVAItemArray -Value $Snapshot.RecentEvents) `
        -Properties @('Available', 'LogName', 'TimeCreated', 'Id', 'LevelDisplay', 'Provider', 'Message', 'Error') -Maximum 75
    $manifestHtml = ConvertTo-AVAHtmlTable -Items $Manifest -Properties @('Algorithm', 'Hash', 'Length', 'Path')

    $computerValue = Get-AVAProperty -Object $Snapshot.Computer -Name 'ComputerName' -DefaultValue 'Unavailable'
    $userValue = Get-AVAProperty -Object $Snapshot.Computer -Name 'UserName' -DefaultValue 'Unavailable'
    $status = ConvertTo-AVAHtmlText -Value $Analysis.Status
    $riskScore = ConvertTo-AVAHtmlText -Value $Analysis.RiskScore
    $cycle = ConvertTo-AVAHtmlText -Value $MainBlock.Cycle
    $findingCount = ConvertTo-AVAHtmlText -Value $Analysis.FindingsCount
    $computer = ConvertTo-AVAHtmlText -Value $computerValue
    $user = ConvertTo-AVAHtmlText -Value $userValue
    $timestamp = ConvertTo-AVAHtmlText -Value $Snapshot.TimestampUtc
    $mainHash = ConvertTo-AVAHtmlText -Value $MainBlock.CurrentHash
    $refresh = ConvertTo-AVAHtmlText -Value $IntervalSeconds

    $html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="$refresh">
<title>AVA Neuro Tangle Guardian SAFE</title>
<style>
body{font-family:Segoe UI,Arial;background:#0b0f14;color:#e7edf5;margin:0}
header,section{padding:20px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;padding:20px}
.card{background:#111827;border:1px solid #263241;border-radius:12px;padding:14px}.big{font-size:28px;font-weight:700}
table{border-collapse:collapse;width:100%;font-size:12px}th,td{border:1px solid #263241;padding:6px;word-break:break-word}th{background:#172033}
</style>
</head>
<body>
<header><h1>AVA Neuro Tangle Guardian SAFE - AVA 01610 1</h1><p>Local evidence and triage. No remote action.</p></header>
<div class="grid">
<div class="card"><div>Status</div><div class="big">$status</div></div>
<div class="card"><div>Risk score</div><div class="big">$riskScore/100</div></div>
<div class="card"><div>Cycle</div><div class="big">$cycle</div></div>
<div class="card"><div>Findings</div><div class="big">$findingCount</div></div>
</div>
<section><p>Computer: $computer | User: $user | UTC: $timestamp</p><p>Main hash: $mainHash</p></section>
<section><h2>Findings</h2>$findingsHtml</section>
<section><h2>Administrators</h2>$administratorsHtml</section>
<section><h2>Connections</h2>$connectionsHtml</section>
<section><h2>WLAN BSSIDs</h2>$wlanHtml</section>
<section><h2>Network adapters</h2>$adaptersHtml</section>
<section><h2>Recent events</h2>$eventsHtml</section>
<section><h2>SHA256 manifest</h2>$manifestHtml</section>
<section><pre>Preserve evidence. Verify context. Do not attribute without proof. Do not attack.</pre></section>
</body>
</html>
"@

    Write-AVAAtomicText -Path $script:PortalFile -Text $html
}

function Invoke-AVACycle {
    Initialize-AVAStorage
    $mutex = [Threading.Mutex]::new($false, $script:MutexName)
    $lockAcquired = $false
    try {
        try {
            $lockAcquired = $mutex.WaitOne([TimeSpan]::FromSeconds(30))
        }
        catch [Threading.AbandonedMutexException] {
            $lockAcquired = $true
        }
        if (-not $lockAcquired) {
            throw 'Another AVA cycle holds the output-directory mutex.'
        }

        $verifiedChain = Test-AVATangleChain
        if ([int]$verifiedChain.Cycle -ge $script:MaxChainCycles) {
            throw "AVA chain cycle cap reached: $($script:MaxChainCycles)."
        }
        $verifiedBranches = Test-AVABranchChain -MainEntries $verifiedChain.Entries
        Test-AVAPendingWrite
        Get-AVAJsonlRecord -Path $script:Events -AllowMissing | Out-Null
        Get-AVAJsonlRecord -Path $script:Alerts -AllowMissing | Out-Null
        $snapshot = Get-AVASnapshot
        $baseline = Get-AVABaseline -Snapshot $snapshot
        $analysis = Get-AVAAnalysis -Snapshot $snapshot -Baseline $baseline
        $cycle = [int]$verifiedChain.Cycle + 1
        $snapshotRelative = 'Reports/Snapshots/snapshot_{0:d10}.json' -f $cycle
        $analysisRelative = 'Reports/Analyses/analysis_{0:d10}.json' -f $cycle
        $snapshotPath = Resolve-AVAReferencePath -RelativePath $snapshotRelative
        $analysisPath = Resolve-AVAReferencePath -RelativePath $analysisRelative
        if ((Test-Path -LiteralPath $snapshotPath) -or (Test-Path -LiteralPath $analysisPath)) {
            throw 'AVA evidence archive collision detected; preserve the directory and investigate the incomplete prior cycle.'
        }

        $capacityEstimate = $script:Utf8NoBom.GetByteCount(($snapshot | ConvertTo-Json -Depth 40)) * 2L
        $capacityEstimate += $script:Utf8NoBom.GetByteCount(($analysis | ConvertTo-Json -Depth 40)) * 2L
        Test-AVAEvidenceCapacity -AdditionalBytes $capacityEstimate

        Write-AVAJson -Path $snapshotPath -Data $snapshot
        Write-AVAJson -Path $analysisPath -Data $analysis
        Write-AVAJson -Path $script:LatestSnapshot -Data $snapshot
        Write-AVAJson -Path $script:LatestAnalysis -Data $analysis
        $snapshotHash = (Get-FileHash -LiteralPath $snapshotPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $analysisHash = (Get-FileHash -LiteralPath $analysisPath -Algorithm SHA256).Hash.ToLowerInvariant()

        $mainBlock = Add-AVAMainBlock -VerifiedChain $verifiedChain -Analysis $analysis `
            -SnapshotRelativePath $snapshotRelative -SnapshotHash $snapshotHash `
            -AnalysisRelativePath $analysisRelative -AnalysisHash $analysisHash

        $verifiedEntriesWithNewBlock = @($verifiedChain.Entries) + @($mainBlock)
        Add-AVABranchBlock -VerifiedBranches $verifiedBranches -MainBlock $mainBlock -Findings $analysis.Findings
        Test-AVABranchChain -MainEntries $verifiedEntriesWithNewBlock | Out-Null
        Add-AVAAlert -MainBlock $mainBlock -Findings $analysis.Findings
        Add-AVAJsonLine -Path $script:Events -Data ([pscustomobject][ordered]@{
            Type = 'CYCLE'
            Marker = $script:Marker
            TimestampUtc = Get-AVAUtc
            Cycle = $mainBlock.Cycle
            RiskScore = $analysis.RiskScore
            Status = $analysis.Status
            MainHash = $mainBlock.CurrentHash
        })

        $manifest = @(Get-AVAManifest -SnapshotPath $snapshotPath -AnalysisPath $analysisPath)
        Write-AVAJson -Path $script:Manifest -Data $manifest
        Write-AVAPortal -Snapshot $snapshot -Analysis $analysis -MainBlock $mainBlock -Manifest $manifest

        Write-Host "$($script:Marker) cycle $($mainBlock.Cycle): $($analysis.Status), score $($analysis.RiskScore)/100"
        return [pscustomobject][ordered]@{
            Cycle = $mainBlock.Cycle
            MainHash = $mainBlock.CurrentHash
            Status = $analysis.Status
            RiskScore = $analysis.RiskScore
        }
    }
    finally {
        if ($lockAcquired) {
            $mutex.ReleaseMutex()
        }
        $mutex.Dispose()
    }
}

function Invoke-AVAEntryPoint {
    Initialize-AVAStorage
    switch ($Mode) {
        'OpenPortal' {
            if (-not (Test-Path -LiteralPath $script:PortalFile -PathType Leaf)) {
                throw "Portal not found: $($script:PortalFile)"
            }
            Start-Process -FilePath $script:PortalFile
        }
        'Once' {
            Invoke-AVACycle | Out-Null
            if ($OpenPortal) {
                Start-Process -FilePath $script:PortalFile
            }
        }
        'Loop' {
            for ($cycleIndex = 0; $cycleIndex -lt $MaxCycles; $cycleIndex++) {
                Invoke-AVACycle | Out-Null
                if ($OpenPortal -and $cycleIndex -eq 0) {
                    Start-Process -FilePath $script:PortalFile
                }
                if (($cycleIndex + 1) -lt $MaxCycles) {
                    Start-Sleep -Seconds $IntervalSeconds
                }
            }
        }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-AVAEntryPoint
}
