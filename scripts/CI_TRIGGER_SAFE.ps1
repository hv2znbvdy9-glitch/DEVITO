#requires -Version 5.1
<#
Purpose: harmless CI trigger for repository-owned GitHub Actions checks.
No firewall, registry, service, task, network, or external-system changes.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Write-Output '[AVA][CI] Safe workflow trigger only.'

# Safe trigger marker: 2026-07-18
