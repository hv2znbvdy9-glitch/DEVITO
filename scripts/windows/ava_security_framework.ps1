[CmdletBinding()]
param(
    [switch]$AllowSystemChanges
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$BasePath = Join-Path $env:ProgramData 'AVA'
$LogDir = Join-Path $BasePath 'Logs'
$EvidenceDir = Join-Path $BasePath 'Evidence'
$ReportDir = Join-Path $BasePath 'Reports'
$LogFile = Join-Path $LogDir 'ava_security_audit.log'
$ReportFile = Join-Path $ReportDir 'security_audit_report.json'

New-Item -ItemType Directory -Path $BasePath, $LogDir, $EvidenceDir, $ReportDir -Force | Out-Null

function Write-Log {
    param([string]$Text)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$ts | $Text" | Out-File -FilePath $LogFile -Append -Encoding UTF8
}

function Get-OptionalValue {
    param(
        [object]$Value,
        [string]$Fallback = 'Unknown'
    )

    if ($null -eq $Value) {
        return $Fallback
    }

    return [string]$Value
}

function Get-BooleanText {
    param([object]$Value)

    if ($null -eq $Value) {
        return 'Unknown'
    }

    if ([bool]$Value) {
        return 'Enabled'
    }

    return 'Disabled'
}

function Get-ReadOnlySystemSummary {
    $os = $null
    $computerSystem = $null
    $mpStatus = $null

    try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop } catch { $os = $null }
    try { $computerSystem = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop } catch { $computerSystem = $null }
    try { $mpStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue } catch { $mpStatus = $null }

    $firewallProfiles = @()
    try {
        $firewallProfiles = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction)
    } catch {
        $firewallProfiles = @()
    }

    $remoteRegistry = $null
    try { $remoteRegistry = Get-CimInstance Win32_Service -Filter "Name='RemoteRegistry'" -ErrorAction Stop } catch { $remoteRegistry = $null }

    $winRm = $null
    try { $winRm = Get-CimInstance Win32_Service -Filter "Name='WinRM'" -ErrorAction Stop } catch { $winRm = $null }

    $termService = $null
    try { $termService = Get-CimInstance Win32_Service -Filter "Name='TermService'" -ErrorAction Stop } catch { $termService = $null }

    $localUsers = @()
    try { $localUsers = @(Get-LocalUser -ErrorAction SilentlyContinue | Select-Object Name, Enabled, LastLogon) } catch { $localUsers = @() }

    $localAdministrators = @()
    try { $localAdministrators = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | Select-Object Name, PrincipalSource, ObjectClass) } catch { $localAdministrators = @() }

    $scheduledTasks = @()
    try { $scheduledTasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike '\Microsoft*' } | Select-Object TaskName, TaskPath, State) } catch { $scheduledTasks = @() }

    $networkAdapters = @()
    try { $networkAdapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object Name, Status, LinkSpeed, MacAddress) } catch { $networkAdapters = @() }

    [pscustomobject]@{
        Timestamp = (Get-Date).ToString('o')
        Mode = 'ReadOnly'
        Hostname = $env:COMPUTERNAME
        User = $env:USERNAME
        OS = Get-OptionalValue -Value $os.Caption
        OSVersion = Get-OptionalValue -Value $os.Version
        ComputerManufacturer = Get-OptionalValue -Value $computerSystem.Manufacturer
        ComputerModel = Get-OptionalValue -Value $computerSystem.Model
        DefenderRealtimeProtection = Get-BooleanText -Value $mpStatus.RealTimeProtectionEnabled
        DefenderAntivirusEnabled = Get-BooleanText -Value $mpStatus.AntivirusEnabled
        FirewallProfiles = $firewallProfiles
        RemoteRegistryService = if ($null -ne $remoteRegistry) { [pscustomobject]@{ Name = $remoteRegistry.Name; State = $remoteRegistry.State; StartMode = $remoteRegistry.StartMode } } else { [pscustomobject]@{ Name = 'RemoteRegistry'; State = 'Unknown'; StartMode = 'Unknown' } }
        WinRMService = if ($null -ne $winRm) { [pscustomobject]@{ Name = $winRm.Name; State = $winRm.State; StartMode = $winRm.StartMode } } else { [pscustomobject]@{ Name = 'WinRM'; State = 'Unknown'; StartMode = 'Unknown' } }
        TermService = if ($null -ne $termService) { [pscustomobject]@{ Name = $termService.Name; State = $termService.State; StartMode = $termService.StartMode } } else { [pscustomobject]@{ Name = 'TermService'; State = 'Unknown'; StartMode = 'Unknown' } }
        LocalUsers = $localUsers
        LocalAdministrators = $localAdministrators
        ScheduledTasks = $scheduledTasks
        NetworkAdapters = $networkAdapters
        Notes = 'No system changes were performed. This script is a read-only audit helper.'
    }
}

if ($AllowSystemChanges) {
    Write-Host 'The safe AVA security framework does not support system changes. Running in read-only mode instead.' -ForegroundColor Yellow
}

Write-Log '=== AVA SECURITY AUDIT START ==='
$summary = Get-ReadOnlySystemSummary
$summary | ConvertTo-Json -Depth 8 | Set-Content -Path $ReportFile -Encoding UTF8
Write-Log '=== AVA SECURITY AUDIT END ==='

Write-Host ''
Write-Host 'AVA security framework completed in read-only mode.' -ForegroundColor Green
Write-Host "Report: $ReportFile" -ForegroundColor Cyan
