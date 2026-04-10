#requires -Version 5.1
<#
.SYNOPSIS
    AVA Monitor – Scheduled task entrypoint for unattended scans.
.DESCRIPTION
    Runs a full AVA scan cycle (TCP, UDP, listeners, integrity, process risk),
    exports reports (JSON, CSV, HTML), and logs results.
    Designed to be called by the Windows Task Scheduler via Start-ScheduledMonitoring.
.NOTES
    Author : Danny Nico Hildebrand
    Version: 2.0
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# Load main module
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
. (Join-Path $scriptDir 'AVA.ps1')

# Initialise
Initialize-AvaEnvironment
Write-AvaLog -Level 'INFO' -Message '=== Scheduled Monitor-Lauf gestartet ==='

# Run scans
$tcpResult      = Invoke-AvaConnectionScan
$udpResult      = Invoke-AvaUdpScan
$listenerResult = Invoke-AvaListenerAudit
$processRisk    = Get-AvaProcessRisk

# Integrity check
$integrityChanged = Test-AvaIntegrity

# Export reports
Export-AvaCsv | Out-Null
Export-AvaHtmlReport | Out-Null

Write-AvaLog -Level 'INFO' -Message '=== Scheduled Monitor-Lauf abgeschlossen ==='
