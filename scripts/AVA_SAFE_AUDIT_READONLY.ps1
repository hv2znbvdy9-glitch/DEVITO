<#
.SYNOPSIS
    Read-only AVA repository audit.

.DESCRIPTION
    Inventories regular files, calculates SHA-256 hashes, statically parses
    PowerShell files, and reports selected high-risk command names.

    The script writes only to the success output stream. It does not create,
    modify, or delete files; it does not access the network; it does not alter
    the registry, firewall, services, scheduled tasks, users, or permissions;
    and it refuses to run as NT AUTHORITY\SYSTEM on Windows.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$Path = (Get-Location).Path,

    [Parameter()]
    [ValidateRange(1, 100000)]
    [int]$MaximumFiles = 10000
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$PlatformProperty = $PSVersionTable.PSObject.Properties['Platform']
if ($null -ne $PlatformProperty -and $PlatformProperty.Value -eq 'Win32NT') {
    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ($Identity.Name -ceq 'NT AUTHORITY\SYSTEM') {
        throw 'STOP: This read-only audit must not run as SYSTEM.'
    }
}

if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
    throw "STOP: Audit path is not an existing directory: $Path"
}

$ResolvedPath = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
$ExcludedDirectoryPattern = '[\\/](?:\.git|node_modules|\.venv|venv)(?:[\\/]|$)'

$ForbiddenCommands = [System.Collections.Generic.HashSet[string]]::new(
    [StringComparer]::OrdinalIgnoreCase
)

@(
    'Add-LocalGroupMember',
    'Disable-NetAdapter',
    'Disable-ScheduledTask',
    'Enable-ScheduledTask',
    'Enter-PSSession',
    'Invoke-Command',
    'Invoke-RestMethod',
    'Invoke-WebRequest',
    'New-NetFirewallRule',
    'New-PSSession',
    'New-ScheduledTaskAction',
    'Register-ScheduledTask',
    'Remove-Item',
    'Remove-LocalGroupMember',
    'Remove-NetFirewallRule',
    'Restart-Service',
    'Set-Acl',
    'Set-ItemProperty',
    'Set-NetFirewallProfile',
    'Set-Service',
    'Start-BitsTransfer',
    'Start-Process',
    'Start-Service',
    'Stop-Service',
    'Unregister-ScheduledTask'
) | ForEach-Object {
    [void]$ForbiddenCommands.Add($_)
}

$Files = @(
    Get-ChildItem -LiteralPath $ResolvedPath -File -Recurse -Force -ErrorAction Stop |
        Where-Object {
            $_.FullName -notmatch $ExcludedDirectoryPattern -and
            -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint)
        } |
        Sort-Object -Property FullName |
        Select-Object -First $MaximumFiles
)

$Inventory = foreach ($File in $Files) {
    $ParseErrorDetails = @()
    $MatchedCommands = @()

    if ($File.Extension -ieq '.ps1') {
        $Tokens = $null
        $ParseErrors = $null
        $Ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $File.FullName,
            [ref]$Tokens,
            [ref]$ParseErrors
        )

        $ParseErrorDetails = @(
            $ParseErrors | ForEach-Object {
                [pscustomobject][ordered]@{
                    Message = $_.Message
                    Line = $_.Extent.StartLineNumber
                    Column = $_.Extent.StartColumnNumber
                }
            }
        )

        $MatchedCommands = @(
            $Ast.FindAll(
                {
                    param($Node)
                    $Node -is [System.Management.Automation.Language.CommandAst]
                },
                $true
            ) |
                ForEach-Object { $_.GetCommandName() } |
                Where-Object {
                    -not [string]::IsNullOrWhiteSpace($_) -and
                    $ForbiddenCommands.Contains($_)
                } |
                Sort-Object -Unique
        )
    }

    $Hash = Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256

    [pscustomobject][ordered]@{
        Path = [IO.Path]::GetRelativePath($ResolvedPath, $File.FullName)
        Length = $File.Length
        SHA256 = $Hash.Hash
        Extension = $File.Extension
        PowerShellParseErrorCount = $ParseErrorDetails.Count
        PowerShellParseErrors = $ParseErrorDetails
        ReportedHighRiskCommands = $MatchedCommands
    }
}

$PowerShellFiles = @($Inventory | Where-Object { $_.Extension -ieq '.ps1' })
$FilesWithParseErrors = @(
    $PowerShellFiles | Where-Object { $_.PowerShellParseErrorCount -gt 0 }
)
$FilesWithReportedCommands = @(
    $PowerShellFiles | Where-Object { $_.ReportedHighRiskCommands.Count -gt 0 }
)

[pscustomobject][ordered]@{
    Audit = 'AVA_SAFE_AUDIT_READONLY'
    Root = $ResolvedPath
    TimestampUtc = [DateTime]::UtcNow.ToString('o')
    CurrentIdentity = [Environment]::UserName
    RunningAsSystem = $false
    NetworkCommandsExecuted = 0
    FilesModified = 0
    FilesInventoried = $Inventory.Count
    PowerShellFilesParsed = $PowerShellFiles.Count
    PowerShellFilesWithParseErrors = $FilesWithParseErrors.Count
    PowerShellFilesWithReportedHighRiskCommands = $FilesWithReportedCommands.Count
    Inventory = $Inventory
} | ConvertTo-Json -Depth 8