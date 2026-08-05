#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Path = (Join-Path $PSScriptRoot 'AVA_NeuroTangle_Guardian_v1_SAFE.ps1')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "Script not found: $Path"
}

$token = $null
$parseError = $null
[System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$token, [ref]$parseError) | Out-Null

if (@($parseError).Count -gt 0) {
    $message = @($parseError | ForEach-Object {
            "Line $($_.Extent.StartLineNumber): $($_.Message)"
        }) -join [Environment]::NewLine
    throw "PowerShell parser reported errors:$([Environment]::NewLine)$message"
}

$content = Get-Content -LiteralPath $Path -Raw -Encoding utf8
$forbiddenCommand = @(
    'Invoke-WebRequest',
    'Invoke-RestMethod',
    'Enter-PSSession',
    'New-PSSession',
    'Invoke-Command',
    'New-NetFirewallRule',
    'Remove-NetFirewallRule',
    'Set-NetFirewallProfile',
    'Restart-Computer',
    'Stop-Computer',
    'Clear-Disk',
    'Format-Volume'
)

foreach ($command in $forbiddenCommand) {
    if ($content -match [regex]::Escape($command)) {
        throw "Forbidden command found in safe script: $command"
    }
}

$requiredText = @(
    'local authorized Windows host only',
    'No remote scanning',
    'No remote scanning or counterattack',
    "[ValidateSet('Once', 'Loop', 'OpenPortal', 'InstallTask', 'UninstallTask')]"
)

foreach ($text in $requiredText) {
    if (-not $content.Contains($text)) {
        throw "Required safety marker is missing: $text"
    }
}

Write-Host "SAFE validation passed: $Path" -ForegroundColor Green
