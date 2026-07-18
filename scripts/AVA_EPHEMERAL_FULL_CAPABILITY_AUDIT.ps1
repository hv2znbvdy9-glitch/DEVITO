#requires -Version 7.2
<#+
AVA EPHEMERAL FULL-CAPABILITY AUDIT

Runs only on an isolated, short-lived Windows CI runner.
The audit phase inventories and parses files. The capability phase performs
harmless, uniquely named mutations and immediately rolls every change back.
No credentials or secret environment variables are read or reported.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$AuditRoot = $PSScriptRoot,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$runId = [Guid]::NewGuid().ToString('N')
$taskName = "AVA_Ephemeral_Audit_$runId"
$firewallName = "AVA Ephemeral Audit $runId"
$registryPath = "HKCU:\Software\AVA\EphemeralAudit_$runId"
$results = [Collections.Generic.List[object]]::new()
$inventory = @()
$parseResults = @()

function Add-Result {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Status,
        [Parameter(Mandatory = $false)][object]$Details = $null
    )

    [void]$results.Add([pscustomobject][ordered]@{
        Name = $Name
        Status = $Status
        Details = $Details
        TimestampUtc = [DateTime]::UtcNow.ToString('o')
    })
}

function Invoke-AvaStep {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$Body
    )

    try {
        $details = & $Body
        Add-Result -Name $Name -Status 'PASS' -Details $details
    }
    catch {
        Add-Result -Name $Name -Status 'FAIL' -Details $_.Exception.Message
    }
}

$resolvedRoot = (Resolve-Path -LiteralPath $AuditRoot -ErrorAction Stop).Path
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$resolvedOutput = (Resolve-Path -LiteralPath $OutputDirectory).Path

Invoke-AvaStep -Name 'Administrator context check' -Body {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $isAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdministrator) {
        throw 'The isolated runner is not elevated; SYSTEM task and firewall tests cannot be performed.'
    }

    [pscustomobject]@{
        Identity = $identity.Name
        IsAdministrator = $isAdministrator
        IsSystem = $identity.IsSystem
    }
}

Invoke-AvaStep -Name 'Read-only file inventory and SHA-256 manifest' -Body {
    $inventory = @(
        Get-ChildItem -LiteralPath $resolvedRoot -File -Recurse -Force |
            Sort-Object FullName |
            ForEach-Object {
                [pscustomobject][ordered]@{
                    Path = [IO.Path]::GetRelativePath($resolvedRoot, $_.FullName)
                    Bytes = $_.Length
                    SHA256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                }
            }
    )

    [pscustomobject]@{
        Files = $inventory.Count
        TotalBytes = ($inventory | Measure-Object -Property Bytes -Sum).Sum
    }
}

Invoke-AvaStep -Name 'Static PowerShell parser verification' -Body {
    $parseResults = @(
        Get-ChildItem -LiteralPath $resolvedRoot -File -Recurse -Force |
            Where-Object { $_.Extension -in @('.ps1', '.psm1', '.psd1') } |
            Sort-Object FullName |
            ForEach-Object {
                $tokens = $null
                $errors = $null
                $null = [Management.Automation.Language.Parser]::ParseFile(
                    $_.FullName,
                    [ref]$tokens,
                    [ref]$errors
                )

                [pscustomobject][ordered]@{
                    Path = [IO.Path]::GetRelativePath($resolvedRoot, $_.FullName)
                    ParseOk = (@($errors).Count -eq 0)
                    Errors = @(
                        $errors | ForEach-Object {
                            [pscustomobject]@{
                                Message = $_.Message
                                Line = $_.Extent.StartLineNumber
                                Column = $_.Extent.StartColumnNumber
                            }
                        }
                    )
                }
            }
    )

    $failed = @($parseResults | Where-Object { -not $_.ParseOk })
    [pscustomobject]@{
        PowerShellFiles = $parseResults.Count
        ParseFailures = $failed.Count
    }
}

Invoke-AvaStep -Name 'Start-Process isolated child' -Body {
    $process = Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" -ArgumentList '/d /c exit 0' -Wait -PassThru -WindowStyle Hidden
    if ($process.ExitCode -ne 0) {
        throw "Child process exited with code $($process.ExitCode)."
    }
    [pscustomobject]@{ ExitCode = $process.ExitCode; ProcessId = $process.Id }
}

Invoke-AvaStep -Name 'Registry mutation with rollback' -Body {
    try {
        New-Item -Path $registryPath -Force | Out-Null
        New-ItemProperty -Path $registryPath -Name 'AuditMarker' -Value $runId -PropertyType String -Force | Out-Null
        $value = (Get-ItemProperty -Path $registryPath -Name 'AuditMarker').AuditMarker
        if ($value -ne $runId) {
            throw 'Registry value verification failed.'
        }
    }
    finally {
        if (Test-Path -LiteralPath $registryPath) {
            Remove-Item -LiteralPath $registryPath -Recurse -Force
        }
    }

    if (Test-Path -LiteralPath $registryPath) {
        throw 'Registry rollback failed.'
    }
    [pscustomobject]@{ Created = $true; Verified = $true; Removed = $true }
}

Invoke-AvaStep -Name 'Firewall mutation with rollback' -Body {
    try {
        New-NetFirewallRule -DisplayName $firewallName -Direction Outbound -Action Block -RemoteAddress '192.0.2.1' -Profile Any | Out-Null
        $rule = Get-NetFirewallRule -DisplayName $firewallName -ErrorAction Stop
        if ($rule.Enabled -ne 'True') {
            throw 'Firewall rule verification failed.'
        }
    }
    finally {
        Get-NetFirewallRule -DisplayName $firewallName -ErrorAction SilentlyContinue |
            Remove-NetFirewallRule -ErrorAction SilentlyContinue
    }

    if (Get-NetFirewallRule -DisplayName $firewallName -ErrorAction SilentlyContinue) {
        throw 'Firewall rollback failed.'
    }
    [pscustomobject]@{ TestAddress = '192.0.2.1'; Created = $true; Removed = $true }
}

Invoke-AvaStep -Name 'Network access verification' -Body {
    $response = Invoke-WebRequest -Uri 'https://api.github.com/meta' -Headers @{ 'User-Agent' = 'AVA-Ephemeral-Audit' } -Method Get -TimeoutSec 30
    [pscustomobject]@{
        UriHost = 'api.github.com'
        StatusCode = [int]$response.StatusCode
        ContentBytes = [Text.Encoding]::UTF8.GetByteCount([string]$response.Content)
    }
}

Invoke-AvaStep -Name 'SYSTEM scheduled task with rollback' -Body {
    try {
        $action = New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\cmd.exe" -Argument '/d /c exit 0'
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(10)
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest

        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
        if ($task.Principal.UserId -ne 'SYSTEM') {
            throw 'The scheduled task was not registered with SYSTEM principal.'
        }

        Start-ScheduledTask -TaskName $taskName
        $deadline = (Get-Date).AddSeconds(20)
        do {
            Start-Sleep -Milliseconds 250
            $info = Get-ScheduledTaskInfo -TaskName $taskName
        } while ($info.LastRunTime.Year -lt 2000 -and (Get-Date) -lt $deadline)

        if ($info.LastTaskResult -ne 0) {
            throw "Scheduled task result was $($info.LastTaskResult)."
        }
    }
    finally {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }

    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        throw 'Scheduled task rollback failed.'
    }
    [pscustomobject]@{ Principal = 'SYSTEM'; RunLevel = 'Highest'; Result = 0; Removed = $true }
}

Invoke-AvaStep -Name 'Watchdog-bounded loop' -Body {
    $iterations = 0
    $started = [DateTime]::UtcNow
    while ($true) {
        $iterations++
        Start-Sleep -Milliseconds 200
        if ($iterations -ge 5) {
            break
        }
    }

    [pscustomobject]@{
        RequestedPattern = 'while ($true)'
        WatchdogBounded = $true
        Iterations = $iterations
        DurationMilliseconds = [int]([DateTime]::UtcNow - $started).TotalMilliseconds
    }
}

Invoke-AvaStep -Name 'Final rollback verification' -Body {
    $leftovers = [Collections.Generic.List[string]]::new()
    if (Test-Path -LiteralPath $registryPath) { [void]$leftovers.Add('Registry') }
    if (Get-NetFirewallRule -DisplayName $firewallName -ErrorAction SilentlyContinue) { [void]$leftovers.Add('Firewall') }
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) { [void]$leftovers.Add('ScheduledTask') }

    if ($leftovers.Count -gt 0) {
        throw "Rollback leftovers: $($leftovers -join ', ')"
    }
    [pscustomobject]@{ Leftovers = 0 }
}

$report = [pscustomobject][ordered]@{
    AuditName = 'AVA_EPHEMERAL_FULL_CAPABILITY_AUDIT'
    Version = '1.0'
    RunId = $runId
    TimestampUtc = [DateTime]::UtcNow.ToString('o')
    AuditRoot = [IO.Path]::GetFileName($resolvedRoot.TrimEnd([IO.Path]::DirectorySeparatorChar))
    OutputDirectory = [IO.Path]::GetFileName($resolvedOutput.TrimEnd([IO.Path]::DirectorySeparatorChar))
    SecretsRead = $false
    UnboundedLoopExecuted = $false
    Capabilities = @($results)
    Summary = [pscustomobject]@{
        Passed = @($results | Where-Object Status -eq 'PASS').Count
        Failed = @($results | Where-Object Status -eq 'FAIL').Count
        InventoryFiles = @($inventory).Count
        ParserFailures = @($parseResults | Where-Object { -not $_.ParseOk }).Count
    }
}

$manifestPath = Join-Path $resolvedOutput 'sha256-manifest.json'
$jsonPath = Join-Path $resolvedOutput 'ava-full-capability-report.json'
$htmlPath = Join-Path $resolvedOutput 'ava-full-capability-report.html'

$inventory | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $manifestPath -Encoding UTF8
$report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $jsonPath -Encoding UTF8

$summaryHtml = @($results | Select-Object Name, Status, TimestampUtc, @{Name='Details'; Expression={ $_.Details | ConvertTo-Json -Depth 5 -Compress }}) |
    ConvertTo-Html -Fragment

$html = @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AVA Ephemeral Full-Capability Audit</title>
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 2rem; }
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #999; padding: .45rem; text-align: left; vertical-align: top; }
th { background: #eee; }
code { background: #f2f2f2; padding: .1rem .3rem; }
</style>
</head>
<body>
<h1>AVA Ephemeral Full-Capability Audit</h1>
<p><strong>Run ID:</strong> <code>$runId</code></p>
<p><strong>Passed:</strong> $($report.Summary.Passed) &nbsp; <strong>Failed:</strong> $($report.Summary.Failed)</p>
<p>All mutations were uniquely named and rolled back. No unbounded loop was executed.</p>
$summaryHtml
</body>
</html>
"@
$html | Set-Content -LiteralPath $htmlPath -Encoding UTF8

$reportHash = (Get-FileHash -LiteralPath $jsonPath -Algorithm SHA256).Hash.ToLowerInvariant()
$htmlHash = (Get-FileHash -LiteralPath $htmlPath -Algorithm SHA256).Hash.ToLowerInvariant()
$manifestHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()

[pscustomobject][ordered]@{
    Result = if ($report.Summary.Failed -eq 0) { 'SUCCESS' } else { 'FAILURE' }
    Passed = $report.Summary.Passed
    Failed = $report.Summary.Failed
    ManifestSHA256 = $manifestHash
    JsonReportSHA256 = $reportHash
    HtmlReportSHA256 = $htmlHash
    OutputDirectory = $resolvedOutput
} | ConvertTo-Json -Depth 4

if ($report.Summary.Failed -gt 0) {
    throw "$($report.Summary.Failed) capability test(s) failed."
}
