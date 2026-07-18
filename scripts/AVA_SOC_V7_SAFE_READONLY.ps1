<#
AVA SAFE AUDIT DERIVATIVE

Source reviewed:
  scripts/AVA_SOC_V7_SAFE.ps1

Removed capabilities:
  - scheduled-task creation and registration
  - recurring execution
  - execution-policy override
  - elevated run level

This script performs no filesystem, registry, service, firewall, task,
credential, process-launch, or network operations. It only emits a
small deterministic JSON status object to the current output stream.
#>

#requires -Version 5.1

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$result = [ordered]@{
    Name                       = 'AVA_SOC_V7_SAFE_READONLY'
    Mode                       = 'IsolatedReadOnly'
    Source                     = 'scripts/AVA_SOC_V7_SAFE.ps1'
    ScheduledTaskRemoved       = $true
    RecurringExecutionRemoved  = $true
    ExecutionPolicyBypass      = $false
    ElevatedContextRequested   = $false
    SecretsPresent             = $false
    WriteOperationsRequested   = $false
    NetworkOperationsRequested = $false
}

[pscustomobject]$result | ConvertTo-Json -Depth 3 -Compress
