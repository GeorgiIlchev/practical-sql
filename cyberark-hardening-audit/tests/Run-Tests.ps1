# Offline tests: mock every Windows primitive and assert the status logic.
# Runs on any OS with PowerShell 7 (pwsh ./tests/Run-Tests.ps1).
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$mod = Import-Module (Join-Path $root 'CyberArkHardeningAudit.psm1') -Force -PassThru
$failures = 0
function Assert-Status($report, $id, $expected) {
    $r = $report.Results | Where-Object Id -eq $id
    if (-not $r) { Write-Host "FAIL $id missing"; $script:failures++; return }
    if ($r.Status -ne $expected) { Write-Host "FAIL $id expected '$expected' got '$($r.Status)' :: $($r.Evidence)"; $script:failures++ }
    else { Write-Host "ok   $id = $expected" }
}

# --- install mocks inside the module scope ---------------------------------
& $mod {
    function script:Get-RegValue($Path, $Name) { $global:Fake.Reg["$Path|$Name"] }
    function script:Get-RegValueNames($Path) { @($global:Fake.Reg.Keys | Where-Object { $_ -like "$Path|*" } | ForEach-Object { $_.Split('|')[1] }) }
    function script:Get-ServiceState($Name, $DisplayName) { $k = if ($Name) { $Name } else { $DisplayName }; $global:Fake.Services[$k] }
    function script:Find-ServicesByPattern($Pattern) { @($global:Fake.Services.Values | Where-Object { $_.Name -match $Pattern -or $_.DisplayName -match $Pattern }) }
    function script:Get-UserRightsMap { $global:Fake.Rights }
    function script:Get-LocalUserNames { $global:Fake.Users }
    function script:Get-LocalGroupNames { $global:Fake.Groups }
    function script:Get-LocalGroupMemberNames($Group) { $global:Fake.GroupMembers[$Group] }
    function script:Get-IsDomainJoined { $global:Fake.Domain }
    function script:Get-AppliedComputerGpos { $global:Fake.Gpos }
    function script:Get-AuditPolicyRows { $global:Fake.Audit }
    function script:Get-AppLockerState { $global:Fake.AppLocker }
    function script:Get-FirewallBlockRules($RemoteAddress, $Direction) { $global:Fake.Firewall }
    function script:Get-Smb1ServerEnabled { $global:Fake.Smb1 }
    function script:Get-InstalledFeatureNames { @('FileAndStorage-Services') }
    function script:Get-EventLogSizes($Logs) { @('Security=1024MB/Circular') }
    function script:Get-FolderAcl($Path) { $global:Fake.Acl }
    function script:Get-ComputerDistinguishedName { 'CN=CONN01,OU=Connectors,DC=corp,DC=local' }
    function script:Get-FileInfo($Path) { $Path = $Path -replace '\\', '/'; if ($global:Fake.Files.ContainsKey($Path)) { $global:Fake.Files[$Path] } }
    function script:Get-FilesInFolder($Folder, $Patterns) {
        $Folder = $Folder -replace '\\', '/'
        @($global:Fake.Files.Values | Where-Object { $f = $_; $f.FullName.StartsWith($Folder) -and @($Patterns | Where-Object { ($f.FullName | Split-Path -Leaf) -like $_ }).Count })
    }
    function script:Get-EntraJoinState { $global:Fake.Entra }
    function script:Test-WindowsFeatureInstalled($Name) { $global:Fake.Features -contains $Name }
    function script:Get-FileText($Path) { $global:Fake.Text[($Path -replace '\\', '/')] }
}

$psm = '/fake/PSM'; $cpm = '/fake/CPM'   # Linux-safe roots; mocks normalise \ to /
function New-FileEntry($p, $t) { @{ FullName = $p; LastWriteTime = [datetime]$t } }
$tsKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
$sch = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'

# --- Scenario A: fully hardened PSM, Privilege Cloud ISPSS, out of domain -----
$reg = @{
    'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp|MinEncryptionLevel' = 3
    'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp|SecurityLayer'      = 2
    'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10|Start' = 4
    'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation|DependOnService' = @('Bowser', 'MRxSmb20', 'NSI')
    "$tsKey|MaxIdleTime" = 172800000; "$tsKey|fDisableAutoReconnect" = 1; "$tsKey|MinEncryptionLevel" = 3
}
foreach ($p in 'SSL 2.0', 'SSL 3.0', 'TLS 1.0', 'TLS 1.1') { foreach ($r in 'Server', 'Client') { $reg["$sch\$p\$r|Enabled"] = 0; $reg["$sch\$p\$r|DisabledByDefault"] = 1 } }

$global:Fake = @{
    Entra = @{ AzureAdJoined = 'YES'; DomainJoined = 'NO'; AzureAdPrt = 'YES' }; Features = @('RDS-RD-Server')
    Reg = $reg; Domain = $false; Smb1 = $false; Gpos = @(); Firewall = @('CyberArk block WireServer')
    Services = @{
        'Cyber-Ark Privileged Session Manager' = @{ Name = 'Cyber-Ark Privileged Session Manager'; DisplayName = 'CyberArk Privileged Session Manager'; StartMode = 'Auto'; State = 'Running'; PathName = "`"$psm/CAPSM.exe`"" }
        'AppIDSvc' = @{ Name = 'AppIDSvc'; DisplayName = 'Application Identity'; StartMode = 'Auto'; State = 'Running' }
        'XblGameSave' = @{ Name = 'XblGameSave'; DisplayName = 'Xbox Live Game Save'; StartMode = 'Disabled'; State = 'Stopped' }
    }
    Rights = @{ SeInteractiveLogonRight = @('CONN01\PSMShadowUsers', 'BUILTIN\Administrators'); SeRemoteInteractiveLogonRight = @('CONN01\PSMConnect', 'CONN01\PSMAdminConnect') }
    Users = @('PSMConnect', 'PSMAdminConnect'); Groups = @('PSMShadowUsers', 'Remote Desktop Users')
    GroupMembers = @{ 'Remote Desktop Users' = @() }
    Audit = @([pscustomobject]@{ Subcategory = 'Logon'; 'Inclusion Setting' = 'Success and Failure' })
    AppLocker = @{ Service = @{ StartMode = 'Auto'; State = 'Running' }; ExeRuleCount = 1; EnforcementMode = 'Enabled' }
    Acl = @('CONN01\PSMConnect:Deny:Write', 'CONN01\PSMShadowUsers:Allow:ReadAndExecute')
    Files = @{
        "$psm/CAPSM.exe" = New-FileEntry "$psm/CAPSM.exe" '2026-01-01'
        "$psm/Hardening/PSMHardening.log" = New-FileEntry "$psm/Hardening/PSMHardening.log" '2026-02-01'
        "$psm/Hardening/PSMConfigureAppLocker.xml" = New-FileEntry "$psm/Hardening/PSMConfigureAppLocker.xml" '2026-01-01'
        "$psm/Hardening/PSMConfigureAppLocker.ps1" = New-FileEntry "$psm/Hardening/PSMConfigureAppLocker.ps1" '2026-01-01'
    }
    Text = @{
        "$psm/Hardening/PSMHardening.log" = "Step 1 completed`nStep 2 completed"
        "$psm/Hardening/PSMHardening.ps1" = "`$SUPPORT_WEB_APPLICATIONS = `$true`n`$ClearRemoteDesktopUsers = 'No'"
    }
}
Write-Host "`n== Scenario A: hardened PSM, ISPSS, out of domain =="
$a = Invoke-CyberArkHardeningAudit -Platform PrivilegeCloudISPSS -CatalogPath (Join-Path $root 'HardeningCatalog.json')
if ($a.DomainMode -ne 'OutOfDomain' -or ($a.Components -join ',') -ne 'PSM') { Write-Host "FAIL context $($a.DomainMode) $($a.Components)"; $failures++ }
'PSM-01', 'PSM-02', 'PSM-03', 'PSM-05', 'PSM-06', 'PSM-07', 'PSM-09', 'PSM-10', 'PSM-11', 'PSM-12', 'PSM-13', 'PSM-14', 'PSM-20', 'PSM-21', 'PSM-22', 'PSM-30', 'PSM-31' |
    ForEach-Object { Assert-Status $a $_ 'DONE' }
Assert-Status $a 'PSM-08' 'DONE'      # group empty
Assert-Status $a 'PSM-04' 'MANUAL'    # evidence-only
Assert-Status $a 'PSM-32' 'SKIPPED'   # optional redirection not disabled
Assert-Status $a 'PSM-40' 'N/A'       # self-hosted in-domain only
Assert-Status $a 'CON-01' 'N/A'       # in-domain only
Assert-Status $a 'CON-03' 'MANUAL'
Assert-Status $a 'CPM-05' 'N/A'
Assert-Status $a 'ENT-01' 'RISK'      # Entra joined + RDS Session Host role
Assert-Status $a 'ENT-02' 'RISK'      # PKU2U AllowOnlineID not set
$exp = ($a.Results | Where-Object Id -eq 'PSM-03').Expected
if ($exp -notmatch 'RDP-Tcp > MinEncryptionLevel \[REG_DWORD\] = 3') { Write-Host "FAIL PSM-03 Expected text: $exp"; $failures++ } else { Write-Host 'ok   PSM-03 Expected shows exact path/value/type' }
$global:Fake.Reg['HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u|AllowOnlineID'] = 1
$a2 = Invoke-CyberArkHardeningAudit -Platform PrivilegeCloudISPSS -CatalogPath (Join-Path $root 'HardeningCatalog.json')
Assert-Status $a2 'ENT-02' 'DONE'

# --- Scenario B: bare server, self-hosted, in domain, PSM + CPM -------------
$global:Fake.Reg = @{}
$global:Fake.Entra = @{ AzureAdJoined = 'NO'; DomainJoined = 'YES'; AzureAdPrt = 'NO' }
$global:Fake.Domain = $true; $global:Fake.Smb1 = $true; $global:Fake.Firewall = @(); $global:Fake.Gpos = @('Default Domain Policy')
$global:Fake.Services['CyberArk Password Manager'] = @{ Name = 'CyberArk Password Manager'; DisplayName = 'CyberArk Password Manager'; StartMode = 'Auto'; State = 'Running'; PathName = "$cpm/PMEngine.exe /service" }
$global:Fake.Services['Windows Error Reporting Service'] = @{ Name = 'WerSvc'; DisplayName = 'Windows Error Reporting Service'; StartMode = 'Manual'; State = 'Stopped' }
$global:Fake.Rights = @{}
$global:Fake.Users = @(); $global:Fake.Groups = @('Remote Desktop Users')
$global:Fake.GroupMembers = @{ 'Remote Desktop Users' = @('CORP\helpdesk') }
$global:Fake.AppLocker = @{ Service = @{ StartMode = 'Manual'; State = 'Stopped' }; ExeRuleCount = 0; EnforcementMode = 'NotConfigured' }
$global:Fake.Acl = @('BUILTIN\Administrators:Allow:FullControl')
$global:Fake.Files = @{
    "$psm/CAPSM.exe" = New-FileEntry "$psm/CAPSM.exe" '2026-06-01'
    "$psm/Hardening/PSMHardening.log" = New-FileEntry "$psm/Hardening/PSMHardening.log" '2026-02-01'
}
$global:Fake.Text = @{
    "$psm/Hardening/PSMHardening.log" = "Step 3 failed: access denied"
    "$cpm/InstallationAutomation/CPM_Hardening_Config.xml" = '<Config><Step Name="EnableFIPSCryptography" Enable="No"/><Step Name="ValidateServerRoles" Enable="No"/><Step Name="ImportINF" Enable="No"/><IsPSMInstalled>False</IsPSMInstalled></Config>'
}
Write-Host "`n== Scenario B: bare server, self-hosted, in domain, PSM+CPM =="
$b = Invoke-CyberArkHardeningAudit -Platform SelfHosted -CatalogPath (Join-Path $root 'HardeningCatalog.json')
Assert-Status $b 'PSM-01' 'MANUAL'     # log has error lines
Assert-Status $b 'PSM-02' 'MANUAL'     # failStatus MANUAL: binary newer than log
Assert-Status $b 'PSM-03' 'NOT DONE'
Assert-Status $b 'PSM-05' 'NOT DONE'
Assert-Status $b 'PSM-07' 'NOT DONE'
Assert-Status $b 'PSM-08' 'SKIPPED'    # optional, members present
Assert-Status $b 'PSM-09' 'NOT DONE'
Assert-Status $b 'PSM-10' 'NOT DONE'
Assert-Status $b 'PSM-13' 'N/A'        # Privilege Cloud only
Assert-Status $b 'PSM-20' 'N/A'        # out-of-domain only
Assert-Status $b 'PSM-40' 'NOT DONE'   # GPO not applied
Assert-Status $b 'CPM-01' 'NOT DONE'   # no CPM log
Assert-Status $b 'CPM-03' 'NOT DONE'   # PSM on box but IsPSMInstalled=False
Assert-Status $b 'CPM-04' 'NOT DONE'
Assert-Status $b 'CPM-07' 'NOT DONE'   # WER not disabled
Assert-Status $b 'CPM-11' 'SKIPPED'    # FIPS disabled in config
Assert-Status $b 'CPM-12' 'SKIPPED'    # ValidateServerRoles=No in config
Assert-Status $b 'CFG-ImportINF' 'SKIPPED'  # unmodelled switch surfaced
Assert-Status $b 'CPM-16' 'NOT DONE'
Assert-Status $b 'ENT-01' 'N/A'       # not Entra joined
Assert-Status $b 'ENT-02' 'N/A'

# --- catalog + HTML -----------------------------------------------------------
$problems = Test-HardeningCatalog (Get-HardeningCatalog (Join-Path $root 'HardeningCatalog.json'))
if ($problems.Count) { Write-Host "FAIL catalog: $($problems -join '; ')"; $failures++ } else { Write-Host 'ok   catalog valid' }
$out = Join-Path ([IO.Path]::GetTempPath()) 'ca-hardening-test'
$files = Export-HardeningReport -Report $b -OutputFolder $out
if (@($files | Where-Object { -not (Test-Path $_) }).Count) { Write-Host 'FAIL export'; $failures++ } else { Write-Host "ok   export -> $($files -join ', ')" }

$cl = Export-HardeningChecklist -CatalogPath (Join-Path $root 'HardeningCatalog.json') -OutputFolder (Join-Path $out 'checklist')
$rows = Get-HardeningChecklistRows (Get-HardeningCatalog (Join-Path $root 'HardeningCatalog.json')) 'SelfHosted' 'OutOfDomain'
if (@($cl).Count -ne 8) { Write-Host "FAIL checklist file count $(@($cl).Count)"; $failures++ } else { Write-Host 'ok   checklist exported (html, csv, 6 md)' }
if (@($rows | Where-Object CheckId -in 'PSM-40', 'PSM-13', 'CON-01').Count) { Write-Host 'FAIL checklist filter leaked in-domain / PCloud-only rows'; $failures++ } else { Write-Host 'ok   checklist filter by platform/domain' }
if (-not @($rows | Where-Object { $_.Tool -eq 'Registry' -and $_.Location -like '*RDP-Tcp' -and $_.Item -eq 'MinEncryptionLevel' -and $_.Expected -like '3*' }).Count) { Write-Host 'FAIL registry row'; $failures++ } else { Write-Host 'ok   registry row has exact key/value/expected' }

Write-Host "`n$failures failure(s)"
exit $failures
