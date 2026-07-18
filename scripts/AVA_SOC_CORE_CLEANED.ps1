#requires -Version 5.1
<#+
AVA SOC CORE — CLEANED / ISOLATED TEST TARGET

Derived as a safe replacement for scripts/AVA_SOC_CORE.ps1.
Removed capabilities:
- administrator requirement and SYSTEM/scheduled-task context
- filesystem creation, modification, logging, baselines and canaries
- firewall, registry, service and process modification
- local account and Defender inspection
- network, WLAN and socket inspection
- external commands, dynamic evaluation and secret/environment access

This script performs only deterministic in-memory transformations and writes
its result to the standard output stream. It does not read or write files.
+#>

[CmdletBinding()]
param(
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-AvaSafeAuditSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Checks
    )

    $NormalizedChecks = @(
        $Checks |
            ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
            Sort-Object -Unique
    )

    [pscustomobject]@{
        schema             = 'ava-safe-audit/v1'
        mode               = 'ISOLATED_PURE_IN_MEMORY'
        checks             = $NormalizedChecks
        check_count        = $NormalizedChecks.Count
        secrets_used       = $false
        filesystem_reads   = $false
        filesystem_writes  = $false
        network_access     = $false
        elevated_context   = $false
        system_changes     = $false
    }
}

$Result = Get-AvaSafeAuditSummary -Checks @(
    'inventory'
    'powershell-parse'
    'sha256'
    'sanitization'
)

if ($SelfTest) {
    if ($Result.schema -ne 'ava-safe-audit/v1') {
        throw 'Self-test failed: schema mismatch.'
    }
    if ($Result.check_count -ne 4) {
        throw 'Self-test failed: unexpected check count.'
    }
    if ($Result.secrets_used -or
        $Result.filesystem_reads -or
        $Result.filesystem_writes -or
        $Result.network_access -or
        $Result.elevated_context -or
        $Result.system_changes) {
        throw 'Self-test failed: a prohibited capability is enabled.'
    }

    Write-Output '[AVA][PASS] isolated, in-memory, non-elevated self-test passed.'
    return
}

Write-Output $Result
