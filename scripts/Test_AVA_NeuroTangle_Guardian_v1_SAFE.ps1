#requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Path = (Join-Path $PSScriptRoot 'AVA_NeuroTangle_Guardian_v1_SAFE.ps1')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-AVAParsedAst {
    param(
        [Parameter(Mandatory)][string]$Text,
        [Parameter(Mandatory)][string]$SourceName
    )

    $tokens = $null
    $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput(
        $Text,
        $SourceName,
        [ref]$tokens,
        [ref]$parseErrors
    )
    if (@($parseErrors).Count -gt 0) {
        $message = @($parseErrors | ForEach-Object {
                "Line $($_.Extent.StartLineNumber): $($_.Message)"
            }) -join [Environment]::NewLine
        throw "PowerShell parser reported errors in '$SourceName':$([Environment]::NewLine)$message"
    }
    return $ast
}

function Test-AVAAstPolicy {
    param(
        [Parameter(Mandatory)][Management.Automation.Language.Ast]$Ast,
        [Parameter(Mandatory)][string]$SourceName
    )

    $deniedCommands = @(
        'Invoke-WebRequest', 'iwr', 'wget', 'curl',
        'Invoke-RestMethod', 'irm', 'Start-BitsTransfer',
        'Enter-PSSession', 'New-PSSession', 'Invoke-Command',
        'Test-NetConnection', 'Resolve-DnsName',
        'New-NetFirewallRule', 'Set-NetFirewallRule', 'Remove-NetFirewallRule',
        'Enable-NetFirewallRule', 'Disable-NetFirewallRule', 'Set-NetFirewallProfile',
        'New-ItemProperty', 'Set-ItemProperty', 'Remove-ItemProperty',
        'New-PSDrive', 'Set-ExecutionPolicy',
        'Register-ScheduledTask', 'Unregister-ScheduledTask', 'Set-ScheduledTask',
        'Start-ScheduledTask', 'Stop-ScheduledTask', 'Disable-ScheduledTask', 'Enable-ScheduledTask',
        'New-ScheduledTaskAction', 'New-ScheduledTaskTrigger', 'New-ScheduledTaskPrincipal',
        'New-LocalUser', 'Set-LocalUser', 'Remove-LocalUser',
        'Add-LocalGroupMember', 'Remove-LocalGroupMember',
        'Start-Service', 'Stop-Service', 'Restart-Service', 'Set-Service', 'New-Service',
        'Stop-Process', 'Restart-Computer', 'Stop-Computer',
        'Clear-Disk', 'Initialize-Disk', 'Format-Volume',
        'Remove-Item', 'ri', 'rm', 'rmdir', 'del', 'erase',
        'Clear-Content', 'Set-Content', 'Add-Content', 'Out-File',
        'Start-Job', 'Invoke-Expression', 'iex', 'Add-Type', 'New-Object'
    )
    $deniedLookup = @{}
    foreach ($commandName in $deniedCommands) {
        $deniedLookup[$commandName.ToLowerInvariant()] = $true
    }

    $allowedCommands = @(
        'Set-StrictMode', 'Test-Path', 'Join-Path', 'Split-Path',
        'New-Item', 'Get-Item', 'Get-ChildItem', 'Get-Content', 'Get-Date',
        'Get-PSDrive', 'Measure-Object', 'ConvertTo-Json', 'ConvertFrom-Json',
        'Get-CimInstance', 'Get-MpComputerStatus', 'Get-NetFirewallProfile',
        'Get-LocalGroup', 'Get-LocalGroupMember', 'Get-NetTCPConnection',
        'Get-ScheduledTask', 'Get-NetNeighbor', 'Get-NetAdapter', 'Get-WinEvent',
        'Where-Object', 'ForEach-Object', 'Select-Object', 'Sort-Object',
        'Get-FileHash', 'Out-Null', 'Write-Host', 'Start-Process', 'Start-Sleep',
        'netsh.exe'
    )
    $allowedLookup = @{}
    foreach ($commandName in $allowedCommands) {
        $allowedLookup[$commandName.ToLowerInvariant()] = $true
    }

    $commandAsts = @($Ast.FindAll({
                param($node)
                $node -is [Management.Automation.Language.CommandAst]
            }, $true))
    foreach ($commandAst in $commandAsts) {
        $commandName = $commandAst.GetCommandName()
        if ([string]::IsNullOrWhiteSpace($commandName)) {
            if ($commandAst.Extent.Text.Trim() -cne '& $ScriptBlock') {
                throw "Dynamic command invocation is denied in '$SourceName': $($commandAst.Extent.Text)"
            }
            continue
        }

        $lowerName = $commandName.ToLowerInvariant()
        if ($deniedLookup.ContainsKey($lowerName)) {
            throw "Denied command in '$SourceName': $commandName"
        }
        if (-not $allowedLookup.ContainsKey($lowerName) -and $commandName -notmatch '^[A-Za-z]+-AVA[A-Za-z0-9]+$') {
            throw "Unknown command is denied by default in '$SourceName': $commandName"
        }
        if ($lowerName.EndsWith('.exe') -and $lowerName -ne 'netsh.exe') {
            throw "External executable is denied in '$SourceName': $commandName"
        }
        if ($lowerName -eq 'netsh.exe' -and
            $commandAst.Extent.Text.Trim() -notmatch '^&\s+netsh\.exe\s+wlan\s+show\s+networks\s+mode=bssid\s+2>&1$') {
            throw "Only read-only WLAN enumeration is allowed for netsh.exe in '$SourceName'."
        }
        if ($lowerName -eq 'start-process' -and
            $commandAst.Extent.Text.Trim() -notmatch '^Start-Process\s+-FilePath\s+\$script:PortalFile$') {
            throw "Start-Process is limited to the generated local portal in '$SourceName'."
        }
        if ($lowerName -eq 'new-item' -and
            $commandAst.Extent.Text -notmatch '(?i)-ItemType\s+Directory') {
            throw "New-Item is limited to AVA directory creation in '$SourceName'."
        }
    }

    $typeAsts = @($Ast.FindAll({
                param($node)
                $node -is [Management.Automation.Language.TypeExpressionAst]
            }, $true))
    foreach ($typeAst in $typeAsts) {
        $typeName = [string]$typeAst.TypeName.FullName
        if ($typeName -match '(?i)(WebClient|HttpClient|WebRequest|TcpClient|UdpClient|Sockets?\.Socket|Microsoft\.Win32\.Registry|RegistryKey)') {
            throw "Denied .NET type in '$SourceName': $typeName"
        }
    }

    $memberAsts = @($Ast.FindAll({
                param($node)
                $node -is [Management.Automation.Language.InvokeMemberExpressionAst]
            }, $true))
    foreach ($memberAst in $memberAsts) {
        $memberName = if ($memberAst.Member -is [Management.Automation.Language.StringConstantExpressionAst]) {
            [string]$memberAst.Member.Value
        }
        else {
            ''
        }
        if ([string]::IsNullOrWhiteSpace($memberName)) {
            throw "Dynamic .NET member invocation is denied in '$SourceName': $($memberAst.Extent.Text)"
        }
        if ($memberName -match '^(?i:Download|DownloadString|Upload|Connect|CreateSubKey|SetValue|DeleteSubKey|Kill|Delete)$') {
            throw "Denied .NET member in '$SourceName': $memberName"
        }
    }
}

if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    throw "Script not found: $Path"
}

$content = Get-Content -LiteralPath $Path -Raw -Encoding utf8
$productionAst = Get-AVAParsedAst -Text $content -SourceName $Path
Test-AVAAstPolicy -Ast $productionAst -SourceName $Path

$requiredText = @(
    'local authorized Windows host only',
    'No remote scanning',
    'No remote scanning or counterattack',
    'AVA 01610 1',
    "[ValidateSet('Once', 'Loop', 'OpenPortal')]",
    '[ValidateRange(1, 10080)]',
    '$MaxLogBytes',
    '$MaxEvidenceBytes',
    '$MaxChainCycles',
    'Test-AVATangleChain',
    'Test-AVABranchChain',
    '[Net.WebUtility]::HtmlEncode'
)
foreach ($required in $requiredText) {
    if (-not $content.Contains($required)) {
        throw "Required safety control is missing: $required"
    }
}

foreach ($forbiddenText in @('InstallTask', 'UninstallTask', 'Register-ScheduledTask', 'while ($true)')) {
    if ($content.Contains($forbiddenText)) {
        throw "Removed or unbounded mode is present: $forbiddenText"
    }
}

$negativeFixtures = [ordered]@{
    'web alias' = 'iwr https://example.invalid/payload'
    'REST alias' = 'irm https://example.invalid/api'
    'BITS transfer' = 'Start-BitsTransfer https://example.invalid/a C:\a'
    '.NET web client' = '[Net.WebClient]::new().DownloadString("https://example.invalid")'
    'dynamic command' = '$name = "Get-Date"; & $name'
    'firewall mutation' = 'Disable-NetFirewallRule -DisplayName "x"'
    'registry mutation' = 'Set-ItemProperty HKCU:\Software\x -Name y -Value z'
    'scheduled task' = 'Register-ScheduledTask -TaskName x -Action $a'
    'destructive delete' = 'Remove-Item C:\evidence -Recurse -Force'
    'external network tool' = '& ping.exe 192.0.2.1'
    'unsafe netsh' = '& netsh.exe advfirewall set allprofiles state off'
    'arbitrary process start' = 'Start-Process -FilePath calc.exe'
    'unknown action' = 'Get-Random'
}

foreach ($fixture in $negativeFixtures.GetEnumerator()) {
    $fixtureAst = Get-AVAParsedAst -Text $fixture.Value -SourceName $fixture.Key
    $wasDenied = $false
    try {
        Test-AVAAstPolicy -Ast $fixtureAst -SourceName $fixture.Key
    }
    catch {
        $wasDenied = $true
    }
    if (-not $wasDenied) {
        throw "Negative AST fixture was not denied: $($fixture.Key)"
    }
}

$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('ava-policy-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
try {
    . $Path -Mode Once -OutputDirectory $testRoot
    Initialize-AVAStorage

    $payload = '<script>alert("x")</script>'
    $table = ConvertTo-AVAHtmlTable -Items @([pscustomobject]@{ Evidence = $payload }) -Properties @('Evidence')
    if ($table.Contains($payload) -or -not $table.Contains('&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;')) {
        throw 'HTML encoding test failed.'
    }

    $uncDenied = $false
    try {
        Resolve-AVALocalPath -Path '\\server\share\ava' | Out-Null
    }
    catch {
        $uncDenied = $true
    }
    if (-not $uncDenied) {
        throw 'UNC output path was not denied.'
    }

    $collectorError = [pscustomobject][ordered]@{
        Available = $false
        Collector = 'Defender'
        Error = 'Synthetic unavailable collector.'
    }
    $syntheticSnapshot = [pscustomobject][ordered]@{
        Computer = [pscustomobject]@{ ComputerName = 'TEST'; UserName = 'TEST\User' }
        Defender = $collectorError
        Firewall = @()
        Administrators = @()
        Processes = @()
        Connections = @()
        ScheduledTasks = @()
        Services = @()
        Neighbors = @()
        NetAdapters = @()
        WLAN = @()
        RecentEvents = @()
    }
    $syntheticBaseline = Get-AVABaselineShape -Snapshot $syntheticSnapshot
    $syntheticAnalysis = Get-AVAAnalysis -Snapshot $syntheticSnapshot -Baseline $syntheticBaseline
    if ([int]$syntheticAnalysis.Bits.CollectorError -ne 1 -or $syntheticAnalysis.Status -ne 'INCOMPLETE') {
        throw 'Structured collector-error analysis test failed.'
    }

    $removedBaseline = Get-AVABaselineShape -Snapshot $syntheticSnapshot
    $removedBaseline.Services = @('OldService|C:\OldService.exe')
    $removedAnalysis = Get-AVAAnalysis -Snapshot $syntheticSnapshot -Baseline $removedBaseline
    if ([int]$removedAnalysis.Bits.RemovedBaseline -ne 1) {
        throw 'Removed baseline-item test failed.'
    }

    $mainBlock = [pscustomobject]@{ Cycle = 1; CurrentHash = (('a' * 64) -join '') }
    $finding = [pscustomobject][ordered]@{
        Severity = 25
        Category = 'TEST'
        Key = 'BRANCH_TEST'
        Description = 'Synthetic branch evidence.'
        Evidence = 'local-only'
    }
    $branchState = [pscustomobject]@{ Entries = @(); Heads = @{} }
    Add-AVABranchBlock -VerifiedBranches $branchState -MainBlock $mainBlock -Findings @($finding)
    $verifiedBranch = Test-AVABranchChain -MainEntries @($mainBlock)
    if (@($verifiedBranch.Entries).Count -ne 1) {
        throw 'Per-finding branch-chain test failed.'
    }

    Add-AVAAlert -MainBlock $mainBlock -Findings @($finding)
    Add-AVAAlert -MainBlock $mainBlock -Findings @($finding)
    if (@(Get-AVAJsonlRecord -Path $script:Alerts).Count -ne 1) {
        throw 'Alert fingerprint deduplication test failed.'
    }

    $badJsonPath = Join-Path $testRoot 'bad.json'
    [IO.File]::WriteAllText($badJsonPath, '{not-json', [Text.Encoding]::UTF8)
    $corruptionDenied = $false
    try {
        Get-AVAJsonFile -Path $badJsonPath | Out-Null
    }
    catch {
        $corruptionDenied = $true
    }
    if (-not $corruptionDenied) {
        throw 'Corrupt JSON did not fail closed.'
    }
}
finally {
    [IO.Directory]::Delete($testRoot, $true)
}

Write-Host "SAFE AST and negative validation passed: $Path" -ForegroundColor Green
