# AVA CI sentinel — intentionally harmless.
# Its only purpose is to trigger the repository's PSScriptAnalyzer workflow.
# It performs no system, registry, firewall, service, task, or network changes.

[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

'AVA CI sentinel: static analysis only; no system changes.'
