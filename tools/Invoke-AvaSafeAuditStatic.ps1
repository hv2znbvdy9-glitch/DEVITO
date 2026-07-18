#requires -Version 7.4
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-AstData {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $Tokens = $null
    $Errors = $null
    $Ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $Path,
        [ref]$Tokens,
        [ref]$Errors
    )

    [pscustomobject]@{
        Ast = $Ast
        Tokens = @($Tokens)
        Errors = @($Errors)
        Commands = @(
            $Ast.FindAll({
                param($Node)
                $Node -is [System.Management.Automation.Language.CommandAst]
            }, $true) |
                ForEach-Object { $_.GetCommandName() } |
                Where-Object { $_ } |
                Sort-Object -Unique
        )
        Functions = @(
            $Ast.FindAll({
                param($Node)
                $Node -is [System.Management.Automation.Language.FunctionDefinitionAst]
            }, $true) |
                ForEach-Object { $_.Name } |
                Sort-Object -Unique
        )
    }
}

try {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

    $Inventory = @(
        foreach ($RelativePath in @(git ls-files | Sort-Object)) {
            $FullPath = Join-Path $PWD $RelativePath
            if (Test-Path -LiteralPath $FullPath -PathType Leaf) {
                $Item = Get-Item -LiteralPath $FullPath
                [pscustomobject]@{
                    path = $RelativePath
                    size_bytes = $Item.Length
                    sha256 = (Get-FileHash -LiteralPath $FullPath -Algorithm SHA256).Hash.ToLowerInvariant()
                }
            }
        }
    )

    $Inventory |
        ConvertTo-Json -Depth 4 |
        Set-Content -LiteralPath (Join-Path $OutputDirectory 'inventory.sha256.json') -Encoding UTF8

    $Inventory |
        Export-Csv -LiteralPath (Join-Path $OutputDirectory 'inventory.sha256.csv') -NoTypeInformation -Encoding UTF8

    $PowerShellFiles = @(
        Get-ChildItem -LiteralPath $PWD -Recurse -File -Filter '*.ps1' |
            Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' } |
            Sort-Object FullName
    )

    $ParseResults = @(
        foreach ($File in $PowerShellFiles) {
            $Data = Get-AstData -Path $File.FullName
            [pscustomobject]@{
                path = [IO.Path]::GetRelativePath($PWD.Path, $File.FullName)
                parsed = ($Data.Errors.Count -eq 0)
                token_count = $Data.Tokens.Count
                function_count = $Data.Functions.Count
                errors = @(
                    $Data.Errors | ForEach-Object {
                        [pscustomobject]@{
                            message = $_.Message
                            line = $_.Extent.StartLineNumber
                            column = $_.Extent.StartColumnNumber
                        }
                    }
                )
            }
        }
    )

    $ParseResults |
        ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath (Join-Path $OutputDirectory 'powershell-parse-results.json') -Encoding UTF8

    $SourcePath = Join-Path $PWD 'scripts/AVA_SOC_CORE.ps1'
    $CleanPath = Join-Path $PWD 'scripts/AVA_SOC_CORE_CLEANED.ps1'
    $SourceText = Get-Content -LiteralPath $SourcePath -Raw
    $CleanText = Get-Content -LiteralPath $CleanPath -Raw
    $SourceData = Get-AstData -Path $SourcePath
    $CleanData = Get-AstData -Path $CleanPath

    if ($CleanData.Errors.Count -gt 0) {
        foreach ($ErrorRecord in $CleanData.Errors) {
            Write-Host "[AVA][CLEAN-PARSE] line=$($ErrorRecord.Extent.StartLineNumber) column=$($ErrorRecord.Extent.StartColumnNumber) message=$($ErrorRecord.Message)"
        }
        throw 'Cleaned script does not parse.'
    }

    $ForbiddenCommands = @(
        'Add-Content', 'Clear-Content', 'Copy-Item', 'Invoke-Command',
        'Invoke-Expression', 'Invoke-RestMethod', 'Invoke-WebRequest',
        'New-Item', 'New-NetFirewallRule', 'Register-ScheduledTask',
        'Remove-Item', 'Remove-NetFirewallRule', 'Remove-ItemProperty',
        'Restart-Service', 'Set-Content', 'Set-Item', 'Set-ItemProperty',
        'Set-NetFirewallRule', 'Set-Service', 'Start-BitsTransfer',
        'Start-Process', 'Start-Service', 'Stop-Process', 'Stop-Service',
        'Unregister-ScheduledTask'
    )

    $Violations = [System.Collections.Generic.List[string]]::new()
    foreach ($Command in $CleanData.Commands) {
        if ($Command -in $ForbiddenCommands) {
            $Violations.Add("command:$Command")
        }
    }

    $ForbiddenTextPatterns = [ordered]@{
        env_access = '\$env:'
        admin_requirement = '(?im)^\s*#requires\s+-RunAsAdministrator'
        network_types = '(?i)System\.Net|Net\.WebClient|HttpClient|TcpClient|UdpClient'
        registry_paths = '(?i)HKLM:|HKCU:|Registry::'
        encoded_or_dynamic = '(?i)EncodedCommand|FromBase64String|DownloadString|Invoke-Expression|\biex\b'
        assigned_secret = '(?i)(password|passwd|secret|token|api[_-]?key)\s*='
    }

    foreach ($Entry in $ForbiddenTextPatterns.GetEnumerator()) {
        if ($CleanText -match $Entry.Value) {
            $Violations.Add("text:$($Entry.Key)")
        }
    }

    if ($Violations.Count -gt 0) {
        throw "Cleaned script contains prohibited capability: $($Violations -join ', ')"
    }

    if ($CleanData.Functions.Count -ne 1 -or
        $CleanData.Functions[0] -ne 'Get-AvaSafeAuditSummary') {
        throw "Cleaned function allowlist failed: $($CleanData.Functions -join ', ')"
    }

    $SourceFunctions = if ($SourceData.Errors.Count -eq 0) {
        $SourceData.Functions
    }
    else {
        @(
            [regex]::Matches($SourceText, '(?im)^\s*function\s+([A-Za-z0-9_-]+)') |
                ForEach-Object { $_.Groups[1].Value } |
                Sort-Object -Unique
        )
    }

    $ParseFailures = @($ParseResults | Where-Object { -not $_.parsed })
    $RemovedFunctions = @($SourceFunctions | Where-Object { $_ -notin $CleanData.Functions })
    $SourceDangerousCommands = @($SourceData.Commands | Where-Object { $_ -in $ForbiddenCommands })

    $Summary = [pscustomobject]@{
        inventory_count = $Inventory.Count
        powershell_file_count = $ParseResults.Count
        parse_failure_count = $ParseFailures.Count
        parse_failures = @($ParseFailures | Select-Object path, errors)
        source_parse_error_count = $SourceData.Errors.Count
        source_function_count = @($SourceFunctions).Count
        removed_source_functions = $RemovedFunctions
        source_dangerous_commands = $SourceDangerousCommands
        cleaned_sha256 = (Get-FileHash -LiteralPath $CleanPath -Algorithm SHA256).Hash.ToLowerInvariant()
        cleaned_functions = $CleanData.Functions
        cleaned_violations = @($Violations)
    }

    $Summary |
        ConvertTo-Json -Depth 8 |
        Set-Content -LiteralPath (Join-Path $OutputDirectory 'summary.json') -Encoding UTF8

    Write-Host "[AVA] inventory_count=$($Summary.inventory_count)"
    Write-Host "[AVA] powershell_file_count=$($Summary.powershell_file_count) parse_failure_count=$($Summary.parse_failure_count)"
    Write-Host "[AVA] removed_source_function_count=$($RemovedFunctions.Count)"
    Write-Host "[AVA] cleaned_sha256=$($Summary.cleaned_sha256)"
    Write-Host '[AVA][STATIC-PASS] cleaned derivative has no prohibited capability.'
}
catch {
    Write-Host "[AVA][AUDIT-ERROR] $($_.Exception.Message)"
    throw
}
