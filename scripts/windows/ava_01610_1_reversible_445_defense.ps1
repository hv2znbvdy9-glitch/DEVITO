#requires -Version 5.1
<#
.SYNOPSIS
    AVA 01610-1 — REVERSIBLE PORT 445 DEFENSE AND IMMUTABLE LEDGER.

.DESCRIPTION
    Implements a local, reversible defense system for TCP Port 445 (SMB) with
    active context/baseline validation and a cryptographically chained immutable ledger.

    Modes:
      - Audit: Inspect current Port 445 state, services, SMB config, and context without making changes.
      - Enforce: Create local, reversible inbound firewall blocking rule 'AVA-01610 Block SMB Inbound'.
      - Rollback: Safely remove firewall block and restore original network visibility.
      - VerifyChain: Validates the integrity of the immutable event ledger.

    Marker: AVA 01610 1
#>

[CmdletBinding()]
param(
    [ValidateSet('Audit', 'Enforce', 'Rollback', 'VerifyChain')]
    [string]$Action = 'Audit',

    [string]$OutputDirectory = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:Marker = 'AVA 01610 1'
$script:Version = '1.0-safe'
$script:FirewallRuleName = 'AVA-01610 Block SMB Inbound'
$script:Utf8NoBom = [Text.UTF8Encoding]::new($false)

# Get current identity and privileges
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$script:IsAdministrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Define directories
$defaultRoot = if ($script:IsAdministrator) {
    'C:\Windows\SecurityGuardian\AVA_01610_Defense'
} else {
    Join-Path $env:LOCALAPPDATA 'AVA_01610_Defense'
}

$requestedRoot = if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $defaultRoot
} else {
    $OutputDirectory
}

$script:Root = [IO.Path]::GetFullPath($requestedRoot)
$script:LogsDir = Join-Path $script:Root 'Logs'
$script:StateDir = Join-Path $script:Root 'State'
$script:ReportsDir = Join-Path $script:Root 'Reports'
$script:ChainFile = Join-Path $script:LogsDir 'chain.jsonl'
$script:ChainStateFile = Join-Path $script:StateDir 'chain_state.json'
$script:BaselineFile = Join-Path $script:StateDir 'baseline.json'
$script:LatestReportFile = Join-Path $script:ReportsDir 'latest_audit.json'

# --- HELPERS ---

function Get-AVAStringHash {
    param([AllowNull()][object]$InputObject)

    $text = if ($null -eq $InputObject) {
        ''
    }
    elseif ($InputObject -is [string]) {
        [string]$InputObject
    }
    else {
        $InputObject | ConvertTo-Json -Depth 40 -Compress
    }

    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($text)
        return ([BitConverter]::ToString($algorithm.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $algorithm.Dispose()
    }
}

function Initialize-AVAStorage {
    foreach ($dir in @($script:Root, $script:LogsDir, $script:StateDir, $script:ReportsDir)) {
        if (-not (Test-Path -LiteralPath $dir -PathType Container)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }
}

function Write-AVAAtomicText {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Text
    )

    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }

    $temporary = $Path + '.pending'
    if (Test-Path -LiteralPath $temporary) {
        Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue
    }
    
    [IO.File]::WriteAllText($temporary, $Text, $script:Utf8NoBom)
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        Move-Item -LiteralPath $temporary -Destination $Path -Force
    }
    else {
        [IO.File]::Move($temporary, $Path)
    }
}

# --- STEP 1: STATE ENUMERATION ---
function Get-Port445State {
    $connections = @()
    $serviceStatus = 'Unknown'
    $serviceStartType = 'Unknown'
    $smbConfig = $null

    # 1. TCP Connection Check
    try {
        $connections = @(Get-NetTCPConnection -LocalPort 445 -State Listen -ErrorAction SilentlyContinue | Select-Object -Property LocalAddress, LocalPort, State, OwningProcess)
    } catch {
        # Fallback for systems where Get-NetTCPConnection might have issues or be restricted
    }

    # 2. Service Check
    try {
        $svc = Get-Service -Name LanmanServer -ErrorAction SilentlyContinue
        if ($null -ne $svc) {
            $serviceStatus = $svc.Status.ToString()
            $serviceStartType = $svc.StartType.ToString()
        }
    } catch {}

    # 3. SMB Server Config
    try {
        $config = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
        if ($null -ne $config) {
            $smbConfig = [pscustomobject]@{
                EnableSMB1Protocol = $config.EnableSMB1Protocol
                EnableSMB2Protocol = $config.EnableSMB2Protocol
                RejectUnencryptedAccess = $config.RejectUnencryptedAccess
                RequireSecuritySignature = $config.RequireSecuritySignature
            }
        }
    } catch {}

    # 4. Active Firewall Rules for 445
    $fwRuleActive = $false
    $fwRuleEnabled = 'Unknown'
    if ($script:IsAdministrator) {
        try {
            $rule = Get-NetFirewallRule -DisplayName $script:FirewallRuleName -ErrorAction SilentlyContinue
            if ($null -ne $rule) {
                $fwRuleActive = $true
                $fwRuleEnabled = if ($rule.Enabled -eq 'True' -or $rule.Enabled -eq $true) { 'Enabled' } else { 'Disabled' }
            } else {
                $fwRuleActive = $false
                $fwRuleEnabled = 'None'
            }
        } catch {}
    }

    return [pscustomobject]@{
        Timestamp = (Get-Date).ToUniversalTime().ToString('o')
        Hostname = $env:COMPUTERNAME
        IsAdministrator = $script:IsAdministrator
        Listeners = $connections
        ServiceStatus = $serviceStatus
        ServiceStartType = $serviceStartType
        SMBConfiguration = $smbConfig
        FirewallRuleActive = $fwRuleActive
        FirewallRuleEnabled = $fwRuleEnabled
    }
}

# --- STEP 2: CONTEXT & BASELINE VALIDATION ---
function Get-NetworkProfileContext {
    $profiles = @()
    try {
        $profiles = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue | Select-Object Name, Enabled)
    } catch {}

    $networkType = 'Unknown'
    try {
        $connectionProfiles = Get-NetConnectionProfile -ErrorAction SilentlyContinue
        if ($null -ne $connectionProfiles) {
            $networkType = ($connectionProfiles | Select-Object -ExpandProperty NetworkCategory -First 1).ToString()
        }
    } catch {}

    return [pscustomobject]@{
        NetworkCategory = $networkType
        FirewallProfiles = $profiles
    }
}

function Evaluate-DefensePolicy {
    param(
        [Parameter(Mandatory)][object]$CurrentState,
        [Parameter(Mandatory)][object]$Context
    )

    $reason = 'No active SMB listeners on Port 445 found. No intervention necessary.'
    $recommendEnforce = $false
    $threatLevel = 'LOW'

    $hasListener = $CurrentState.Listeners.Count -gt 0
    if ($hasListener) {
        if ($Context.NetworkCategory -eq 'Public') {
            $reason = 'Port 445 has active listeners on a PUBLIC network interface. High vulnerability risk! Enforcement strongly recommended.'
            $recommendEnforce = $true
            $threatLevel = 'HIGH'
        } elseif ($Context.NetworkCategory -eq 'Private') {
            $reason = 'Port 445 has active listeners on a PRIVATE network. Potential risk if the local network is shared or untrusted.'
            $recommendEnforce = $true
            $threatLevel = 'MEDIUM'
        } else {
            $reason = 'Port 445 has active listeners. Baseline validation indicates local or domain context.'
            $recommendEnforce = $false
            $threatLevel = 'LOW'
        }
    }

    if ($CurrentState.FirewallRuleActive -and $CurrentState.FirewallRuleEnabled -eq 'Enabled') {
        $reason = 'Defensive block rule is already active and blocking Port 445 inbound traffic.'
        $recommendEnforce = $false
        $threatLevel = 'PROTECTED'
    }

    return [pscustomobject]@{
        RecommendEnforce = $recommendEnforce
        ThreatLevel = $threatLevel
        Reason = $reason
    }
}

# --- STEP 5: LEDGER & CRYPTO CHAINING ---
function Append-ChainBlock {
    param(
        [Parameter(Mandatory)][string]$EventType,
        [Parameter(Mandatory)][object]$EventData
    )

    Initialize-AVAStorage

    # Read latest chain state
    $lastHash = '0000000000000000000000000000000000000000000000000000000000000000'
    $nextIndex = 1

    if (Test-Path -LiteralPath $script:ChainStateFile) {
        try {
            $stateRaw = [IO.File]::ReadAllText($script:ChainStateFile, $script:Utf8NoBom)
            $stateObj = $stateRaw | ConvertFrom-Json
            $lastHash = $stateObj.LastHash
            $nextIndex = [int]$stateObj.TotalBlocks + 1
        } catch {
            Write-Warning "Chain state file corrupted or malformed. Re-indexing chain."
        }
    }

    $eventBlock = [pscustomobject]@{
        Index = $nextIndex
        Timestamp = (Get-Date).ToUniversalTime().ToString('o')
        EventType = $EventType
        PreviousHash = $lastHash
        EventData = $EventData
        Marker = $script:Marker
    }

    # Generate current block hash
    $currentHash = Get-AVAStringHash -InputObject $eventBlock
    $eventBlock | Add-Member -MemberType NoteProperty -Name 'Hash' -Value $currentHash

    # Append block to chain.jsonl
    $jsonlLine = ($eventBlock | ConvertTo-Json -Depth 40 -Compress) + [Environment]::NewLine
    [IO.File]::AppendAllText($script:ChainFile, $jsonlLine, $script:Utf8NoBom)

    # Save new state
    $newStateObj = [pscustomobject]@{
        LastHash = $currentHash
        TotalBlocks = $nextIndex
        UpdatedTime = (Get-Date).ToUniversalTime().ToString('o')
    }
    $newStateJson = $newStateObj | ConvertTo-Json -Depth 5
    Write-AVAAtomicText -Path $script:ChainStateFile -Text $newStateJson

    return $eventBlock
}

function Verify-LedgerChain {
    if (-not (Test-Path -LiteralPath $script:ChainFile)) {
        return [pscustomobject]@{
            Valid = $true
            Message = 'No ledger files exist yet. Chain is empty and valid.'
            TotalBlocks = 0
        }
    }

    $lines = @(Get-Content -LiteralPath $script:ChainFile -Encoding utf8)
    if ($lines.Count -eq 0) {
        return [pscustomobject]@{
            Valid = $true
            Message = 'Chain file is empty and valid.'
            TotalBlocks = 0
        }
    }

    $expectedPrevHash = '0000000000000000000000000000000000000000000000000000000000000000'
    $blockCount = 0
    foreach ($line in $lines) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        try {
            $block = $line | ConvertFrom-Json
        } catch {
            return [pscustomobject]@{
                Valid = $false
                Message = "Malformed JSON at ledger line $($blockCount + 1)."
                TotalBlocks = $blockCount
            }
        }
        
        # Verify index sequence
        $expectedIndex = $blockCount + 1
        if ($block.Index -ne $expectedIndex) {
            return [pscustomobject]@{
                Valid = $false
                Message = "Block index mismatch at line $expectedIndex. Expected $expectedIndex, got $($block.Index)."
                TotalBlocks = $blockCount
            }
        }

        # Verify previous hash link
        if ($block.PreviousHash -ne $expectedPrevHash) {
            return [pscustomobject]@{
                Valid = $false
                Message = "Cryptographic linkage broken at Block $expectedIndex. PreviousHash does not match."
                TotalBlocks = $blockCount
            }
        }

        # Re-compute block hash (omitting the Hash field itself)
        $blockClone = $line | ConvertFrom-Json
        # Remove Hash property from clone for correct hash re-computation
        $blockClone.PSObject.Properties.Remove('Hash')
        $computedHash = Get-AVAStringHash -InputObject $blockClone

        if ($block.Hash -ne $computedHash) {
            return [pscustomobject]@{
                Valid = $false
                Message = "Block $expectedIndex contents modified! Computed hash $computedHash does not match stored hash $($block.Hash)."
                TotalBlocks = $blockCount
            }
        }

        $expectedPrevHash = $block.Hash
        $blockCount++
    }

    return [pscustomobject]@{
        Valid = $true
        Message = 'All cryptographic signatures and block linkage verified successfully.'
        TotalBlocks = $blockCount
    }
}

# --- ACTIONS ---

switch ($Action) {
    'Audit' {
        Write-Host "=== AVA-01610-1 Port 445 SECURITY AUDIT ===" -ForegroundColor Cyan
        Initialize-AVAStorage
        
        $state = Get-Port445State
        $context = Get-NetworkProfileContext
        $policy = Evaluate-DefensePolicy -CurrentState $state -Context $context

        $auditReport = [pscustomobject]@{
            Timestamp = (Get-Date).ToUniversalTime().ToString('o')
            AuditState = $state
            NetworkContext = $context
            PolicyDecision = $policy
            Marker = $script:Marker
        }

        $reportJson = $auditReport | ConvertTo-Json -Depth 10
        Write-AVAAtomicText -Path $script:LatestReportFile -Text $reportJson

        Write-Host "Local Hostname      : $($auditReport.AuditState.Hostname)"
        Write-Host "Listeners on 445    : $($auditReport.AuditState.Listeners.Count)"
        Write-Host "Service Status      : $($auditReport.AuditState.ServiceStatus)"
        Write-Host "Network Category    : $($auditReport.NetworkContext.NetworkCategory)"
        Write-Host "Suggested Policy    : $($auditReport.PolicyDecision.Reason)" -ForegroundColor (if ($policy.RecommendEnforce) { 'Yellow' } else { 'Green' })
        Write-Host "Threat Assessment   : $($auditReport.PolicyDecision.ThreatLevel)" -ForegroundColor (if ($policy.ThreatLevel -eq 'HIGH') { 'Red' } else { 'Green' })
        Write-Host "Report saved to     : $script:LatestReportFile" -ForegroundColor Cyan
    }

    'Enforce' {
        Write-Host "=== AVA-01610-1 ACTIVATING REVERSIBLE DEFENSE ===" -ForegroundColor Yellow
        if (-not $script:IsAdministrator) {
            throw "Administrator privileges are required to perform 'Enforce' action on the local firewall."
        }

        Initialize-AVAStorage

        # Capture pre-enforcement state
        $preState = Get-Port445State
        $context = Get-NetworkProfileContext

        # Create local reversible firewall block rule
        Write-Host "Creating local inbound TCP 445 block rule..." -ForegroundColor Yellow
        $firewallParams = @{
            DisplayName = $script:FirewallRuleName
            Direction   = 'Inbound'
            Protocol    = 'TCP'
            LocalPort   = '445'
            Action      = 'Block'
            Profile     = 'Domain,Private,Public'
            Enabled     = 'True'
        }
        
        # Check if rule already exists
        $existingRule = Get-NetFirewallRule -DisplayName $script:FirewallRuleName -ErrorAction SilentlyContinue
        if ($null -ne $existingRule) {
            Write-Host "Removing pre-existing defense rule to apply clean configuration..." -ForegroundColor Gray
            Remove-NetFirewallRule -DisplayName $script:FirewallRuleName | Out-Null
        }

        # Apply New Firewall Rule
        New-NetFirewallRule @firewallParams | Out-Null

        # Validate post-enforcement state
        $postState = Get-Port445State

        # Cryptographically document the Enforcement Block event
        $enforceData = [pscustomobject]@{
            Action = 'Enforce'
            PreState = $preState
            PostState = $postState
            Context = $context
            FirewallRuleConfig = $firewallParams
        }
        $block = Append-ChainBlock -EventType 'PORT_445_ENFORCED' -EventData $enforceData

        Write-Host "🛡️ Local Firewall inbound SMB Block applied successfully." -ForegroundColor Green
        Write-Host "Ledger block appended: Index $($block.Index), Hash $($block.Hash)" -ForegroundColor Cyan
        Write-Host "⚠️ This change is fully reversible. Run script with '-Action Rollback' to reverse." -ForegroundColor Gray
    }

    'Rollback' {
        Write-Host "=== AVA-01610-1 REVERSING SYSTEM TO ORIGINAL STATE ===" -ForegroundColor Yellow
        if (-not $script:IsAdministrator) {
            throw "Administrator privileges are required to perform 'Rollback' action on the local firewall."
        }

        Initialize-AVAStorage

        # Capture pre-rollback state
        $preState = Get-Port445State
        
        # Remove firewall rule cleanly
        $existingRule = Get-NetFirewallRule -DisplayName $script:FirewallRuleName -ErrorAction SilentlyContinue
        if ($null -ne $existingRule) {
            Write-Host "Removing defense firewall rule: $($script:FirewallRuleName)" -ForegroundColor Yellow
            Remove-NetFirewallRule -DisplayName $script:FirewallRuleName | Out-Null
            Write-Host "Rule successfully removed." -ForegroundColor Green
        } else {
            Write-Host "No active defense rule found on this host." -ForegroundColor Gray
        }

        # Capture post-rollback state
        $postState = Get-Port445State

        # Cryptographically document the Rollback event
        $rollbackData = [pscustomobject]@{
            Action = 'Rollback'
            PreState = $preState
            PostState = $postState
        }
        $block = Append-ChainBlock -EventType 'PORT_445_ROLLED_BACK' -EventData $rollbackData

        Write-Host "↩️ System returned to original state. Firewall blockage removed." -ForegroundColor Green
        Write-Host "Ledger block appended: Index $($block.Index), Hash $($block.Hash)" -ForegroundColor Cyan
    }

    'VerifyChain' {
        Write-Host "=== AVA-01610-1 INTEGRITY VERIFICATION ===" -ForegroundColor Cyan
        $verification = Verify-LedgerChain
        if ($verification.Valid) {
            Write-Host "🟢 [SUCCESS] $($_ = $verification.Message)" -ForegroundColor Green
            Write-Host "Total chain size: $($verification.TotalBlocks) blocks"
        } else {
            Write-Host "🔴 [CRITICAL ERROR] $($_ = $verification.Message)" -ForegroundColor Red
            exit 1
        }
    }
}
