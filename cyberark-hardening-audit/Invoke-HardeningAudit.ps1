#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only audit of CyberArk (Idira) PSM / CPM hardening: what was done, what was
    skipped, and what is still to be covered.

.DESCRIPTION
    Run on the PSM and/or CPM server (or Privilege Cloud Connector) from an elevated
    PowerShell session. It changes nothing. It writes HTML, CSV and JSON reports.

.PARAMETER Platform
    SelfHosted | PrivilegeCloudStandard | PrivilegeCloudISPSS

.PARAMETER DomainMode
    Auto (default, from Win32_ComputerSystem.PartOfDomain) | InDomain | OutOfDomain

.PARAMETER Component
    Auto (default, detected from installed services) | PSM | CPM | Both

.EXAMPLE
    .\Invoke-HardeningAudit.ps1 -ExportChecklist -OutputFolder .\checklist
    Writes the per-tool checklist (exact registry path / value / type, GPO setting path, expected value, verify command).
.EXAMPLE
    .\Invoke-HardeningAudit.ps1 -Platform PrivilegeCloudISPSS
.EXAMPLE
    .\Invoke-HardeningAudit.ps1 -Platform SelfHosted -DomainMode OutOfDomain -Component PSM -OutputFolder D:\Audit
#>
[CmdletBinding()]
param(
    [ValidateSet('SelfHosted', 'PrivilegeCloudStandard', 'PrivilegeCloudISPSS')][string]$Platform,
    [ValidateSet('Auto', 'InDomain', 'OutOfDomain')][string]$DomainMode = 'Auto',
    [ValidateSet('Auto', 'PSM', 'CPM', 'Both')][string]$Component = 'Auto',
    [string]$PSMPath,
    [string]$CPMPath,
    [string]$OutputFolder = (Join-Path $PSScriptRoot 'reports'),
    [switch]$ValidateCatalogOnly,
    [switch]$ExportChecklist
)

Import-Module (Join-Path $PSScriptRoot 'CyberArkHardeningAudit.psm1') -Force

if ($ValidateCatalogOnly) {
    $problems = Test-HardeningCatalog (Get-HardeningCatalog (Join-Path $PSScriptRoot 'HardeningCatalog.json'))
    if ($problems.Count) { $problems; exit 1 }
    'Catalog OK'; exit 0
}

if ($ExportChecklist) {
    # Offline: builds the per-tool checklist (registry paths, GPO settings, expected values) from the catalog
    Export-HardeningChecklist -CatalogPath (Join-Path $PSScriptRoot 'HardeningCatalog.json') -OutputFolder $OutputFolder
    exit 0
}
if (-not $Platform) { throw '-Platform is required for an audit run (SelfHosted | PrivilegeCloudStandard | PrivilegeCloudISPSS).' }

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Warning 'Not elevated: user rights (secedit), auditpol and some registry reads will be incomplete.' }

$report = Invoke-CyberArkHardeningAudit -Platform $Platform -DomainMode $DomainMode -Component $Component `
    -PSMPath $PSMPath -CPMPath $CPMPath -CatalogPath (Join-Path $PSScriptRoot 'HardeningCatalog.json')

$report.Results | Group-Object Status | Sort-Object Name | Format-Table @{ n = 'Status'; e = { $_.Name } }, Count -AutoSize
$report.Results | Where-Object { $_.Status -in 'NOT DONE', 'RISK', 'ERROR' } | Format-Table Id, Status, Title, Expected, Evidence -Wrap

$files = Export-HardeningReport -Report $report -OutputFolder $OutputFolder
"Reports:"; $files
