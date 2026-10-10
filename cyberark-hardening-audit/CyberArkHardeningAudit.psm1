#Requires -Version 5.1
<#
    CyberArk (Idira) PSM / CPM hardening audit engine.
    READ-ONLY: never changes the system. Every Windows lookup goes through the
    primitive functions in the "Primitives" region so it can be mocked in tests.
#>
Set-StrictMode -Version 2.0

$script:Platforms   = 'SelfHosted', 'PrivilegeCloudStandard', 'PrivilegeCloudISPSS'
$script:DomainModes = 'InDomain', 'OutOfDomain'

#region Primitives (Windows-specific; mocked in tests)

function Get-RegValue {
    param([string]$Path, [string]$Name)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $null }
    return $item.$Name
}

function Get-RegValueNames {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return @() }
    $props = (Get-Item -LiteralPath $Path).Property
    if ($null -eq $props) { return @() }
    return @($props)
}

function Get-ServiceState {
    # Returns @{Name; DisplayName; StartMode; State; PathName} or $null
    param([string]$Name, [string]$DisplayName)
    $filter = if ($Name) { "Name='$($Name -replace "'", "''")'" } else { "DisplayName='$($DisplayName -replace "'", "''")'" }
    $svc = Get-CimInstance -ClassName Win32_Service -Filter $filter -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $svc) { return $null }
    return @{ Name = $svc.Name; DisplayName = $svc.DisplayName; StartMode = $svc.StartMode; State = $svc.State; PathName = $svc.PathName }
}

function Find-ServicesByPattern {
    param([string]$Pattern)
    @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match $Pattern -or $_.DisplayName -match $Pattern } |
        ForEach-Object { @{ Name = $_.Name; DisplayName = $_.DisplayName; StartMode = $_.StartMode; State = $_.State; PathName = $_.PathName } })
}

function Get-UserRightsMap {
    # Returns hashtable: right -> array of resolved principal names
    $tmp = Join-Path $env:TEMP ("ur_{0}.inf" -f [guid]::NewGuid())
    try {
        $null = & secedit.exe /export /areas USER_RIGHTS /cfg $tmp /quiet
        $map = @{}
        foreach ($line in (Get-Content -LiteralPath $tmp -ErrorAction Stop)) {
            if ($line -match '^\s*(Se\w+)\s*=\s*(.*)$') {
                $map[$Matches[1]] = @($Matches[2].Split(',') | ForEach-Object { Resolve-Principal $_.Trim() })
            }
        }
        return $map
    }
    finally { Remove-Item -LiteralPath $tmp -ErrorAction SilentlyContinue }
}

function Resolve-Principal {
    param([string]$Value)
    if ($Value -notmatch '^\*S-') { return $Value }
    try { return ([System.Security.Principal.SecurityIdentifier]$Value.TrimStart('*')).Translate([System.Security.Principal.NTAccount]).Value }
    catch { return $Value }
}

function Get-LocalUserNames  { @(Get-LocalUser -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }) }
function Get-LocalGroupNames { @(Get-LocalGroup -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }) }
function Get-LocalGroupMemberNames {
    param([string]$Group)
    @(Get-LocalGroupMember -Group $Group -ErrorAction Stop | ForEach-Object { $_.Name })
}

function Get-IsDomainJoined { [bool](Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain }

function Get-AppliedComputerGpos {
    $out = & gpresult.exe /scope computer /r 2>$null
    $names = New-Object System.Collections.Generic.List[string]
    $inApplied = $false
    foreach ($line in $out) {
        if ($line -match 'Applied Group Policy Objects') { $inApplied = $true; continue }
        if ($inApplied) {
            if ($line -match '^\s*-{3,}') { continue }
            if ($line -match '^\s*$') { if ($names.Count) { break } else { continue } }
            if ($line -match '^\s{4,}(.+?)\s*$') { $names.Add($Matches[1]) } else { break }
        }
    }
    return @($names)
}

function Get-AuditPolicyRows {
    @(& auditpol.exe /get /category:* /r 2>$null | Where-Object { $_ } | ConvertFrom-Csv)
}

function Get-AppLockerState {
    $svc = Get-ServiceState -Name 'AppIDSvc'
    $exeRules = 0; $mode = 'NotConfigured'
    try {
        $pol = Get-AppLockerPolicy -Effective -ErrorAction Stop
        $exe = $pol.RuleCollections | Where-Object { $_.RuleCollectionType -eq 'Exe' }
        if ($exe) { $exeRules = @($exe).Count; $mode = [string]$exe.EnforcementMode }
    } catch { $mode = "Unavailable: $($_.Exception.Message)" }
    return @{ Service = $svc; ExeRuleCount = $exeRules; EnforcementMode = $mode }
}

function Get-FirewallBlockRules {
    param([string]$RemoteAddress, [string]$Direction)
    @(Get-NetFirewallRule -Direction $Direction -Action Block -Enabled True -ErrorAction SilentlyContinue |
        Where-Object { ($_ | Get-NetFirewallAddressFilter).RemoteAddress -contains $RemoteAddress } |
        ForEach-Object { $_.DisplayName })
}

function Get-Smb1ServerEnabled {
    try { return [bool](Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol }
    catch {
        $v = Get-RegValue 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' 'SMB1'
        if ($null -eq $v) { return $null }
        return ($v -ne 0)
    }
}

function Get-InstalledFeatureNames {
    if (-not (Get-Command Get-WindowsFeature -ErrorAction SilentlyContinue)) { return $null }
    @(Get-WindowsFeature | Where-Object { $_.Installed -and $_.FeatureType -eq 'Role' } | ForEach-Object { $_.Name })
}

function Get-EventLogSizes {
    param([string[]]$Logs)
    @($Logs | ForEach-Object {
        $l = Get-WinEvent -ListLog $_ -ErrorAction SilentlyContinue
        if ($l) { '{0}={1}MB/{2}' -f $l.LogName, [math]::Round($l.MaximumSizeInBytes / 1MB), $l.LogMode }
    })
}

function Get-FolderAcl {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    @((Get-Acl -LiteralPath $Path).Access | ForEach-Object { '{0}:{1}:{2}' -f $_.IdentityReference, $_.AccessControlType, $_.FileSystemRights })
}

function Get-ComputerDistinguishedName {
    Get-RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine' 'Distinguished-Name'
}

function Get-FileInfo {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $i = Get-Item -LiteralPath $Path
    @{ FullName = $i.FullName; LastWriteTime = $i.LastWriteTime }
}

function Get-FilesInFolder {
    param([string]$Folder, [string[]]$Patterns)
    if (-not $Folder -or -not (Test-Path -LiteralPath $Folder)) { return @() }
    @(foreach ($p in $Patterns) {
        Get-ChildItem -LiteralPath $Folder -Filter $p -File -Recurse -ErrorAction SilentlyContinue |
            ForEach-Object { @{ FullName = $_.FullName; LastWriteTime = $_.LastWriteTime } }
    })
}

function Get-FileText { param([string]$Path) Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue }

#endregion

#region Context

function Get-ComponentRoot {
    # Derive install root from the service binary path
    param([string]$Pattern)
    $svc = Find-ServicesByPattern $Pattern | Select-Object -First 1
    if ($null -eq $svc -or -not $svc.PathName) { return $null }
    # Handles quoted and unquoted PathName, with or without arguments (e.g. "...\PMEngine.exe" /SERVICE)
    $exe = $svc.PathName -replace '^\s*"?(.+?\.exe)"?.*$', '$1'
    $dir = Split-Path -Path $exe -Parent
    # CPM binaries live in <root>\ or <root>\bin depending on version
    if ((Split-Path $dir -Leaf) -eq 'bin') { $dir = Split-Path $dir -Parent }
    return $dir
}

function Read-HardeningConfig {
    <#
        Generic parser: collects every Yes/No/True/False switch from
        CPM_Hardening_Config.xml and PSMHardening.ps1 so disabled steps
        can be reported as SKIPPED. Element names differ across versions,
        so nothing here depends on a specific schema.
    #>
    param([string]$PSMRoot, [string]$CPMRoot)
    $cfg = @{}
    if ($CPMRoot) {
        $xmlPath = Join-Path $CPMRoot 'InstallationAutomation\CPM_Hardening_Config.xml'
        $text = Get-FileText $xmlPath
        if ($text) {
            try {
                $xml = [xml]$text
                foreach ($node in $xml.SelectNodes('//*')) {
                    foreach ($attr in $node.Attributes) {
                        if ($attr.Value -match '^(?i)(yes|no|true|false)$') {
                            $key = if ($attr.Name -match '^(?i)(enable|value|run|execute)$') { $node.LocalName } else { $attr.Name }
                            if ($node.Attributes['Name']) { $key = $node.Attributes['Name'].Value }
                            $cfg[$key] = @{ Value = $attr.Value; Source = $xmlPath }
                        }
                    }
                    if (-not $node.HasChildNodes -or ($node.ChildNodes.Count -eq 1 -and $node.FirstChild.NodeType -eq 'Text')) {
                        if ($node.InnerText -match '^(?i)\s*(yes|no|true|false)\s*$') {
                            $cfg[$node.LocalName] = @{ Value = $Matches[1]; Source = $xmlPath }
                        }
                    }
                }
            } catch { $cfg['__cpmConfigError'] = @{ Value = $_.Exception.Message; Source = $xmlPath } }
        }
    }
    if ($PSMRoot) {
        $ps1 = Join-Path $PSMRoot 'Hardening\PSMHardening.ps1'
        $text = Get-FileText $ps1
        if ($text) {
            foreach ($m in [regex]::Matches($text, '(?im)^\s*\$(\w+)\s*=\s*["'']?\$?(yes|no|true|false)["'']?\s*(#.*)?$')) {
                $cfg[$m.Groups[1].Value] = @{ Value = $m.Groups[2].Value; Source = $ps1 }
            }
        }
    }
    return $cfg
}

function Get-ConfigSwitch {
    # Looks a key up ignoring case and underscores (SupportWebApplications == SUPPORT_WEB_APPLICATIONS)
    param([hashtable]$Config, [string]$Key)
    $norm = ($Key -replace '_', '').ToLowerInvariant()
    foreach ($k in $Config.Keys) {
        if (($k -replace '_', '').ToLowerInvariant() -eq $norm) { return $Config[$k] }
    }
    return $null
}

function New-HardeningContext {
    param(
        [Parameter(Mandatory)][ValidateSet('SelfHosted', 'PrivilegeCloudStandard', 'PrivilegeCloudISPSS')][string]$Platform,
        [ValidateSet('Auto', 'InDomain', 'OutOfDomain')][string]$DomainMode = 'Auto',
        [ValidateSet('Auto', 'PSM', 'CPM', 'Both')][string]$Component = 'Auto',
        [string]$PSMPath, [string]$CPMPath
    )
    if (-not $PSMPath) { $PSMPath = Get-ComponentRoot 'Privileged Session Manager' }
    if (-not $CPMPath) { $CPMPath = Get-ComponentRoot '^(CyberArk Password Manager|Cyber-Ark Password Manager)$' }

    $components = switch ($Component) {
        'PSM'  { @('PSM') }
        'CPM'  { @('CPM') }
        'Both' { @('PSM', 'CPM') }
        default {
            $c = @()
            if ($PSMPath) { $c += 'PSM' }
            if ($CPMPath) { $c += 'CPM' }
            $c
        }
    }
    $mode = $DomainMode
    if ($mode -eq 'Auto') { $mode = if (Get-IsDomainJoined) { 'InDomain' } else { 'OutOfDomain' } }

    return @{
        Platform   = $Platform
        DomainMode = $mode
        Components = @($components)
        PSMPath    = $PSMPath
        CPMPath    = $CPMPath
        Config     = Read-HardeningConfig -PSMRoot $PSMPath -CPMRoot $CPMPath
        Cache      = @{}
    }
}

#endregion

#region Probes  (each returns @{ Result = Pass|Fail|Manual|NotApplicable; Evidence = string })

function New-ProbeResult { param([string]$Result, [string]$Evidence) @{ Result = $Result; Evidence = $Evidence } }

function Test-RegistryItem {
    param($Item)
    $v = Get-RegValue $Item.path $Item.name
    $label = '{0}\{1}' -f $Item.path, $Item.name
    $missingIs = if ($Item.PSObject.Properties['missingIs']) { $Item.missingIs } else { 'fail' }
    if ($Item.operator -eq 'evidence') {
        $shown = if ($null -eq $v) { '<not set>' } else { $v }
        return New-ProbeResult 'Manual' "$label = $shown"
    }
    if ($null -eq $v) {
        $r = if ($missingIs -eq 'pass') { 'Pass' } else { 'Fail' }
        return New-ProbeResult $r "$label not present"
    }
    $vals = @($v)
    $ok = switch ($Item.operator) {
        'eq'          { $vals.Count -eq 1 -and "$($vals[0])" -eq "$($Item.expected)" }
        'gt'          { $vals.Count -eq 1 -and [double]$vals[0] -gt [double]$Item.expected }
        'contains'    { $vals -contains $Item.expected }
        'notcontains' { $vals -notcontains $Item.expected }
        default       { throw "Unknown operator '$($Item.operator)'" }
    }
    $r = if ($ok) { 'Pass' } else { 'Fail' }
    New-ProbeResult $r ("{0} = {1} (expected {2} {3})" -f $label, ($vals -join ';'), $Item.operator, $Item.expected)
}

function Get-CachedUserRights {
    param($Ctx)
    if (-not $Ctx.Cache.ContainsKey('UserRights')) { $Ctx.Cache['UserRights'] = Get-UserRightsMap }
    $Ctx.Cache['UserRights']
}

function Test-PrincipalListed {
    param([string[]]$Holders, [string]$Principal)
    foreach ($h in $Holders) { if ($h -ieq $Principal -or $h -like "*\$Principal") { return $true } }
    return $false
}

function Get-ComponentFolder {
    param($Ctx, [string]$Component, [string]$Sub)
    $root = if ($Component -eq 'PSM') { $Ctx.PSMPath } else { $Ctx.CPMPath }
    if (-not $root) { return $null }
    if ($Sub) { return Join-Path $root $Sub }
    return $root
}

function Get-SchannelValue {
    param([string]$Protocol, [string]$Role, [string]$Name)
    Get-RegValue ("HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\{0}\{1}" -f $Protocol, $Role) $Name
}

function Invoke-Probe {
    param($Probe, $Ctx)
    switch ($Probe.type) {

        'Registry'    { return Test-RegistryItem $Probe }

        'RegistrySet' {
            $parts = @($Probe.items | ForEach-Object { Test-RegistryItem $_ })
            $r = if (@($parts | Where-Object { $_.Result -ne 'Pass' }).Count) { 'Fail' } else { 'Pass' }
            return New-ProbeResult $r (($parts | ForEach-Object { $_.Evidence }) -join ' | ')
        }

        'SchannelLegacyDisabled' {
            $bad = @(); $ev = @()
            foreach ($p in $Probe.protocols) {
                foreach ($role in $Probe.roles) {
                    $en = Get-SchannelValue $p $role 'Enabled'
                    $dd = Get-SchannelValue $p $role 'DisabledByDefault'
                    $ev += '{0}/{1}: Enabled={2} DisabledByDefault={3}' -f $p, $role, $(if ($null -eq $en) { '<unset>' } else { $en }), $(if ($null -eq $dd) { '<unset>' } else { $dd })
                    if (-not ("$en" -eq '0' -and "$dd" -eq '1')) { $bad += "$p/$role" }
                }
            }
            $r = if ($bad.Count) { 'Fail' } else { 'Pass' }
            return New-ProbeResult $r ($ev -join '; ')
        }

        'SchannelEvidence' {
            $ev = foreach ($p in $Probe.protocols) {
                foreach ($role in 'Server', 'Client') {
                    '{0}/{1}: Enabled={2}' -f $p, $role, $(Get-SchannelValue $p $role 'Enabled')
                }
            }
            return New-ProbeResult 'Manual' (($ev -join '; ') + ' (blank = OS default)')
        }

        'Smb1Server' {
            $on = Get-Smb1ServerEnabled
            if ($null -eq $on) { return New-ProbeResult 'Pass' 'SMB1 server setting not present (OS default: disabled on Server 2019+)' }
            $r = if ($on) { 'Fail' } else { 'Pass' }
            return New-ProbeResult $r "EnableSMB1Protocol=$on"
        }

        'ServicesDisabled' {
            $ev = @(); $bad = 0
            $targets = @()
            if ($Probe.PSObject.Properties['names'])        { $targets += @($Probe.names        | ForEach-Object { @{ Name = $_ } }) }
            if ($Probe.PSObject.Properties['displayNames']) { $targets += @($Probe.displayNames | ForEach-Object { @{ DisplayName = $_ } }) }
            foreach ($t in $targets) {
                $s = Get-ServiceState @t
                $label = if ($t.ContainsKey('Name')) { $t['Name'] } else { $t['DisplayName'] }
                if ($null -eq $s) { $ev += "${label}: not installed"; continue }
                $ev += '{0}: {1}/{2}' -f $label, $s.StartMode, $s.State
                if ($s.StartMode -ne 'Disabled') { $bad++ }
            }
            $r = if ($bad) { 'Fail' } else { 'Pass' }
            return New-ProbeResult $r ($ev -join '; ')
        }

        'UserRight' {
            $map = Get-CachedUserRights $Ctx
            $holders = if ($map.ContainsKey($Probe.right)) { @($map[$Probe.right]) } else { @() }
            $missing = @($Probe.principals | Where-Object { -not (Test-PrincipalListed $holders $_) })
            $ev = '{0} holders: {1}' -f $Probe.right, $(if ($holders.Count) { $holders -join ', ' } else { '<none>' })
            if ($missing.Count) { $ev += " | missing: $($missing -join ', ')" }
            if ($Probe.PSObject.Properties['reportOthers'] -and $Probe.reportOthers) {
                $others = @($holders | Where-Object { $h = $_; -not @($Probe.principals | Where-Object { Test-PrincipalListed @($h) $_ }).Count })
                if ($others.Count) { $ev += " | REVIEW other holders: $($others -join ', ')" }
            }
            $r = if ($missing.Count) { 'Fail' } else { 'Pass' }
            return New-ProbeResult $r $ev
        }

        'LocalUsers' {
            $have = Get-LocalUserNames
            $missing = @($Probe.names | Where-Object { $have -notcontains $_ })
            $r = if ($missing.Count) { 'Fail' } else { 'Pass' }
            $ev = if ($missing.Count) { "missing: $($missing -join ', ') (may be domain accounts; verify)" } else { "present: $($Probe.names -join ', ')" }
            return New-ProbeResult $r $ev
        }

        'LocalGroupExists' {
            $r = if ((Get-LocalGroupNames) -contains $Probe.group) { 'Pass' } else { 'Fail' }
            return New-ProbeResult $r "group '$($Probe.group)' $(if ($r -eq 'Pass') { 'exists' } else { 'not found' })"
        }

        'LocalGroupEmpty' {
            $m = @(Get-LocalGroupMemberNames $Probe.group)
            $r = if ($m.Count) { 'Fail' } else { 'Pass' }
            return New-ProbeResult $r ("'{0}' members: {1}" -f $Probe.group, $(if ($m.Count) { $m -join ', ' } else { '<empty>' }))
        }

        'AppLocker' {
            $s = Get-AppLockerState
            $svcOk = $s.Service -and $s.Service.State -eq 'Running'
            $ok = $svcOk -and $s.ExeRuleCount -gt 0 -and $s.EnforcementMode -eq 'Enabled'
            $svcTxt = if ($s.Service) { "$($s.Service.StartMode)/$($s.Service.State)" } else { 'missing' }
            $r = if ($ok) { 'Pass' } else { 'Fail' }
            return New-ProbeResult $r ("AppIDSvc={0}; Exe collection rules={1}; EnforcementMode={2}" -f $svcTxt, $s.ExeRuleCount, $s.EnforcementMode)
        }

        'FirewallBlock' {
            $rules = @(Get-FirewallBlockRules $Probe.remoteAddress $Probe.direction)
            $r = if ($rules.Count) { 'Pass' } else { 'Fail' }
            return New-ProbeResult $r ("{0} block rules to {1}: {2}" -f $Probe.direction, $Probe.remoteAddress, $(if ($rules.Count) { $rules -join ', ' } else { '<none>' }))
        }

        'GpoApplied' {
            $gpos = @(Get-AppliedComputerGpos)
            $hits = @($gpos | Where-Object { $g = $_; @($Probe.patterns | Where-Object { $g -match [regex]::Escape($_) }).Count })
            $r = if ($hits.Count) { 'Pass' } else { 'Fail' }
            return New-ProbeResult $r ("applied computer GPOs: {0}; matched: {1}" -f $(if ($gpos.Count) { $gpos -join ', ' } else { '<none>' }), $(if ($hits.Count) { $hits -join ', ' } else { '<none>' }))
        }

        'ComputerOU' {
            $dn = Get-ComputerDistinguishedName
            return New-ProbeResult 'Manual' ("computer DN: {0}" -f $(if ($dn) { $dn } else { '<unknown>' }))
        }

        'FilePresent' {
            $root = Get-ComponentFolder $Ctx $Probe.component
            if (-not $root) { return New-ProbeResult 'Fail' "$($Probe.component) install folder not found" }
            $missing = @($Probe.relativePaths | Where-Object { -not (Get-FileInfo (Join-Path $root $_)) })
            $r = if ($missing.Count) { 'Fail' } else { 'Pass' }
            $ev = if ($missing.Count) { "missing: $($missing -join ', ')" } else { "present under $root" }
            return New-ProbeResult $r $ev
        }

        'HardeningLog' {
            $folder = Get-ComponentFolder $Ctx $Probe.component $Probe.folder
            $logs = @(Get-FilesInFolder $folder $Probe.patterns | Sort-Object { $_.LastWriteTime } -Descending)
            if (-not $logs.Count) { return New-ProbeResult 'Fail' "no hardening log found in $folder (script likely never run, or logs removed)" }
            $latest = $logs[0]
            $text = Get-FileText $latest.FullName
            $errs = @()
            if ($text) { $errs = @([regex]::Matches($text, '(?im)^.*\b(error|failed|exception)\b.*$') | Select-Object -First 5 | ForEach-Object { $_.Value.Trim() }) }
            $ev = "latest log: $($latest.FullName) ($($latest.LastWriteTime))"
            if ($errs.Count) { return New-ProbeResult 'Manual' "$ev | error lines: $($errs -join ' || ')" }
            return New-ProbeResult 'Pass' "$ev | no error lines"
        }

        'ReappliedAfterUpgrade' {
            $folder = Get-ComponentFolder $Ctx $Probe.component $Probe.folder
            $root = Get-ComponentFolder $Ctx $Probe.component
            $logs = @(Get-FilesInFolder $folder $Probe.patterns | Sort-Object { $_.LastWriteTime } -Descending)
            $bins = @(Get-FilesInFolder $root @('*.exe') | Sort-Object { $_.LastWriteTime } -Descending)
            if (-not $logs.Count -or -not $bins.Count) { return New-ProbeResult 'Manual' 'cannot compare: hardening log or component binaries not found' }
            $r = if ($logs[0].LastWriteTime -ge $bins[0].LastWriteTime) { 'Pass' } else { 'Fail' }
            return New-ProbeResult $r ("newest hardening log {0:u} vs newest binary {1:u} ({2})" -f $logs[0].LastWriteTime, $bins[0].LastWriteTime, (Split-Path $bins[0].FullName -Leaf))
        }

        'PsmCoexistence' {
            if (-not $Ctx.PSMPath) { return New-ProbeResult 'NotApplicable' 'PSM not installed on this server' }
            $sw = Get-ConfigSwitch $Ctx.Config $Probe.key
            if ($null -eq $sw) { return New-ProbeResult 'Manual' "PSM present; '$($Probe.key)' not found in CPM_Hardening_Config.xml" }
            $r = if ($sw.Value -match '^(?i)(true|yes)$') { 'Pass' } else { 'Fail' }
            return New-ProbeResult $r "PSM present; $($Probe.key)=$($sw.Value) ($($sw.Source))"
        }

        'ConfigEvidence' {
            $found = @($Probe.keys | ForEach-Object { $s = Get-ConfigSwitch $Ctx.Config $_; if ($s) { "$_=$($s.Value) ($($s.Source))" } })
            return New-ProbeResult 'Manual' $(if ($found.Count) { $found -join '; ' } else { 'setting not found in hardening files (default applies)' })
        }

        'DepExclusion' {
            $path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers'
            $names = Get-RegValueNames $path
            $missing = @(); $ev = @()
            foreach ($exe in $Probe.executables) {
                $hit = @($names | Where-Object { $_ -like "*\$exe" })
                $flagged = @($hit | Where-Object { "$(Get-RegValue $path $_)" -match 'DisableNXShowUI' })
                if ($flagged.Count) { $ev += "${exe}: DEP opt-out set" } else { $missing += $exe; $ev += "${exe}: no DEP opt-out found" }
            }
            $r = if ($missing.Count) { 'Fail' } else { 'Pass' }
            return New-ProbeResult $r ($ev -join '; ')
        }

        'AclEvidence' {
            $root = Get-ComponentFolder $Ctx $Probe.component
            $acl = if ($root) { Get-FolderAcl $root } else { $null }
            if ($null -eq $acl) { return New-ProbeResult 'Manual' "$($Probe.component) folder not found" }
            $rel = @($acl | Where-Object { $a = $_; @($Probe.principals | Where-Object { $a -match [regex]::Escape($_) }).Count })
            $r = if ($rel.Count) { 'Pass' } else { 'Fail' }
            return New-ProbeResult $r ("ACEs for PSM users on {0}: {1}" -f $root, $(if ($rel.Count) { $rel -join '; ' } else { '<none>' }))
        }

        'AuditPolicy' {
            $rows = @(Get-AuditPolicyRows)
            if (-not $rows.Count) { return New-ProbeResult 'Manual' 'auditpol returned no data (run elevated)' }
            $both = @($rows | Where-Object { $_.'Inclusion Setting' -eq 'Success and Failure' }).Count
            $none = @($rows | Where-Object { $_.'Inclusion Setting' -eq 'No Auditing' }).Count
            return New-ProbeResult 'Manual' ("{0} subcategories: {1} Success+Failure, {2} No Auditing. Compare with the doc audit table." -f $rows.Count, $both, $none)
        }

        'EventLogEvidence' { return New-ProbeResult 'Manual' ((Get-EventLogSizes $Probe.logs) -join '; ') }

        'WindowsFeatures' {
            $f = Get-InstalledFeatureNames
            if ($null -eq $f) { return New-ProbeResult 'Manual' 'Get-WindowsFeature unavailable (client OS?)' }
            return New-ProbeResult 'Manual' ("installed roles: {0}" -f $(if (@($f).Count) { $f -join ', ' } else { '<none>' }))
        }

        'Manual' { return New-ProbeResult 'Manual' 'No reliable automatic signal. Verify by hand (see remediation).' }

        default { throw "Unknown probe type '$($Probe.type)'" }
    }
}

#endregion

#region Engine

function Get-HardeningCatalog {
    param([string]$Path = (Join-Path $PSScriptRoot 'HardeningCatalog.json'))
    Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Test-HardeningCatalog {
    # Static validation of the catalog; returns a list of problems (empty = OK)
    param($Catalog)
    $problems = New-Object System.Collections.Generic.List[string]
    $known = 'Registry', 'RegistrySet', 'SchannelLegacyDisabled', 'SchannelEvidence', 'Smb1Server', 'ServicesDisabled', 'UserRight', 'LocalUsers',
             'LocalGroupExists', 'LocalGroupEmpty', 'AppLocker', 'FirewallBlock', 'GpoApplied', 'ComputerOU', 'FilePresent', 'HardeningLog',
             'ReappliedAfterUpgrade', 'PsmCoexistence', 'ConfigEvidence', 'DepExclusion', 'AclEvidence', 'AuditPolicy', 'EventLogEvidence',
             'WindowsFeatures', 'Manual'
    $ids = @{}
    foreach ($c in $Catalog.checks) {
        if ($ids.ContainsKey($c.id)) { $problems.Add("duplicate id $($c.id)") }
        $ids[$c.id] = $true
        if ($known -notcontains $c.probe.type) { $problems.Add("$($c.id): unknown probe type $($c.probe.type)") }
        foreach ($p in $c.platforms) { if ($script:Platforms -notcontains $p) { $problems.Add("$($c.id): bad platform $p") } }
        if (@('Any') + $script:DomainModes -notcontains $c.domainMode) { $problems.Add("$($c.id): bad domainMode $($c.domainMode)") }
        if (@('PSM', 'CPM', 'Any') -notcontains $c.component) { $problems.Add("$($c.id): bad component $($c.component)") }
        if (-not @($c.refs).Count) { $problems.Add("$($c.id): no source reference") }
        foreach ($r in $c.refs) {
            if (-not $Catalog.sources.PSObject.Properties[$r.src]) { $problems.Add("$($c.id): unknown source $($r.src)") }
        }
        if (@('NOT DONE', 'MANUAL') -notcontains $c.failStatus) { $problems.Add("$($c.id): bad failStatus $($c.failStatus)") }
    }
    return , $problems
}

function Resolve-CheckStatus {
    <#
        Status model:
          DONE      hardened state confirmed
          NOT DONE  mandatory step not applied (yet to be covered)
          SKIPPED   optional/default-off step not applied, or step switched off in the hardening config file
          MANUAL    needs a human to confirm (evidence attached)
          N/A       not applicable to this platform / component / domain mode
          ERROR     the probe itself failed
    #>
    param($Check, $Ctx)
    $applicable = $true; $why = ''
    if ($Check.platforms -notcontains $Ctx.Platform) { $applicable = $false; $why = "not documented for $($Ctx.Platform)" }
    elseif ($Check.domainMode -ne 'Any' -and $Check.domainMode -ne $Ctx.DomainMode) { $applicable = $false; $why = "applies to $($Check.domainMode) only" }
    elseif ($Check.component -ne 'Any' -and $Ctx.Components -notcontains $Check.component) { $applicable = $false; $why = "$($Check.component) not on this server" }
    elseif ($Check.component -eq 'Any' -and -not $Ctx.Components.Count) { $applicable = $false; $why = 'no CyberArk component detected' }
    if (-not $applicable) { return @{ Status = 'N/A'; Evidence = $why } }

    try { $p = Invoke-Probe $Check.probe $Ctx }
    catch { return @{ Status = 'ERROR'; Evidence = $_.Exception.Message } }

    $optional = $Check.PSObject.Properties['optional'] -and $Check.optional
    $cfgNote = ''
    if ($Check.PSObject.Properties['configKey'] -and $Check.configKey) {
        $sw = Get-ConfigSwitch $Ctx.Config $Check.configKey
        if ($sw) {
            $cfgNote = " | config $($Check.configKey)=$($sw.Value)"
            if ($sw.Value -match '^(?i)(no|false)$' -and $p.Result -ne 'Pass') {
                return @{ Status = 'SKIPPED'; Evidence = "Step disabled in $($sw.Source): $($Check.configKey)=$($sw.Value) | $($p.Evidence)" }
            }
        }
    }
    switch ($p.Result) {
        'Pass'          { return @{ Status = 'DONE'; Evidence = $p.Evidence + $cfgNote } }
        'Manual'        { return @{ Status = 'MANUAL'; Evidence = $p.Evidence + $cfgNote } }
        'NotApplicable' { return @{ Status = 'N/A'; Evidence = $p.Evidence } }
        default {
            if ($optional) { return @{ Status = 'SKIPPED'; Evidence = "Optional step (off by default) not applied | $($p.Evidence)$cfgNote" } }
            return @{ Status = $Check.failStatus; Evidence = $p.Evidence + $cfgNote }
        }
    }
}

function Invoke-CyberArkHardeningAudit {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('SelfHosted', 'PrivilegeCloudStandard', 'PrivilegeCloudISPSS')][string]$Platform,
        [ValidateSet('Auto', 'InDomain', 'OutOfDomain')][string]$DomainMode = 'Auto',
        [ValidateSet('Auto', 'PSM', 'CPM', 'Both')][string]$Component = 'Auto',
        [string]$PSMPath, [string]$CPMPath,
        [string]$CatalogPath = (Join-Path $PSScriptRoot 'HardeningCatalog.json')
    )
    $catalog = Get-HardeningCatalog $CatalogPath
    $problems = Test-HardeningCatalog $catalog
    if ($problems.Count) { throw "Catalog invalid:`n$($problems -join "`n")" }

    $ctx = New-HardeningContext -Platform $Platform -DomainMode $DomainMode -Component $Component -PSMPath $PSMPath -CPMPath $CPMPath

    $results = foreach ($c in $catalog.checks) {
        $s = Resolve-CheckStatus $c $ctx
        $refs = @($c.refs | ForEach-Object {
            $src = $catalog.sources.($_.src)
            [pscustomobject]@{ Platform = $src.platform; Title = $src.title; Url = $src.url; Find = $_.find }
        })
        [pscustomobject]@{
            Id          = $c.id
            Component   = $c.component
            Stage       = $c.stage
            Title       = $c.title
            Status      = $s.Status
            Evidence    = $s.Evidence
            Confidence  = $c.confidence
            Remediation = $c.remediation
            Sources     = $refs
        }
    }

    # Every switch found in the hardening files that was turned off becomes its own SKIPPED row,
    # so steps not modelled in the catalog are still visible.
    $modelled = @($catalog.checks | Where-Object { $_.PSObject.Properties['configKey'] } | ForEach-Object { ($_.configKey -replace '_', '').ToLowerInvariant() })
    $extra = foreach ($k in ($ctx.Config.Keys | Sort-Object)) {
        if ($k -like '__*') { continue }
        $v = $ctx.Config[$k]
        if ($v.Value -notmatch '^(?i)(no|false)$') { continue }
        if ($modelled -contains ($k -replace '_', '').ToLowerInvariant()) { continue }
        [pscustomobject]@{
            Id = "CFG-$k"; Component = $(if ($v.Source -match 'PSMHardening') { 'PSM' } else { 'CPM' }); Stage = 'Hardening config switch'
            Title = "Step/switch '$k' turned off in hardening file"; Status = 'SKIPPED'; Evidence = "$k=$($v.Value) in $($v.Source)"
            Confidence = 'Observed'; Remediation = 'Confirm this exclusion is approved and documented.'; Sources = @()
        }
    }

    [pscustomobject]@{
        GeneratedUtc = (Get-Date).ToUniversalTime().ToString('u')
        Computer     = [Environment]::MachineName
        Platform     = $ctx.Platform
        DomainMode   = $ctx.DomainMode
        Components   = $ctx.Components
        PSMPath      = $ctx.PSMPath
        CPMPath      = $ctx.CPMPath
        CatalogVersion = $catalog.catalogVersion
        Results      = @($results) + @($extra)
    }
}

function Export-HardeningReport {
    param([Parameter(Mandatory)]$Report, [Parameter(Mandatory)][string]$OutputFolder)
    if (-not (Test-Path -LiteralPath $OutputFolder)) { $null = New-Item -ItemType Directory -Path $OutputFolder }
    $stamp = '{0}_{1}' -f $Report.Computer, (Get-Date -Format 'yyyyMMdd-HHmmss')
    $base = Join-Path $OutputFolder "CyberArkHardening_$stamp"

    $Report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath "$base.json" -Encoding UTF8
    $Report.Results | Select-Object Id, Component, Stage, Title, Status, Confidence, Evidence, Remediation,
        @{ n = 'SourceUrls'; e = { ($_.Sources | ForEach-Object { $_.Url }) -join ' ' } },
        @{ n = 'FindText';   e = { ($_.Sources | ForEach-Object { $_.Find }) -join ' || ' } } |
        Export-Csv -LiteralPath "$base.csv" -NoTypeInformation -Encoding UTF8
    ConvertTo-HardeningHtml $Report | Set-Content -LiteralPath "$base.html" -Encoding UTF8
    return @("$base.html", "$base.csv", "$base.json")
}

function ConvertTo-HardeningHtml {
    param($Report)
    Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue
    $enc = { param($s) [System.Net.WebUtility]::HtmlEncode([string]$s) }
    $order = 'NOT DONE', 'ERROR', 'MANUAL', 'SKIPPED', 'DONE', 'N/A'
    $counts = foreach ($st in $order) { '<span class="pill s{0}">{1}: {2}</span>' -f ($st -replace '[^A-Z]', ''), $st, @($Report.Results | Where-Object Status -eq $st).Count }
    $rows = foreach ($r in ($Report.Results | Sort-Object { [array]::IndexOf($order, $_.Status) }, Id)) {
        $src = ($r.Sources | ForEach-Object { '<a href="{0}">{1}</a> <small>[{2}] find: &ldquo;{3}&rdquo;</small>' -f (& $enc $_.Url), (& $enc $_.Title), (& $enc $_.Platform), (& $enc $_.Find) }) -join '<br>'
        '<tr data-status="{0}"><td>{1}</td><td>{2}</td><td>{3}</td><td><b>{4}</b></td><td class="st s{5}">{0}</td><td>{6}</td><td>{7}</td><td>{8}</td><td>{9}</td></tr>' -f `
            (& $enc $r.Status), (& $enc $r.Id), (& $enc $r.Component), (& $enc $r.Stage), (& $enc $r.Title), ($r.Status -replace '[^A-Z]', ''),
            (& $enc $r.Evidence), (& $enc $r.Confidence), (& $enc $r.Remediation), $src
    }
@"
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CyberArk Hardening Audit</title>
<style>
:root{--bg:#fff;--fg:#1b1f24;--mut:#59636e;--bd:#d1d9e0;--done:#1a7f37;--nd:#cf222e;--man:#9a6700;--sk:#8250df;--na:#6e7781}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--mut:#9198a1;--bd:#30363d;--done:#3fb950;--nd:#f85149;--man:#d29922;--sk:#a371f7;--na:#8b949e}}
body{background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,Segoe UI,sans-serif;margin:0;padding:16px}
table{border-collapse:collapse;width:100%}th,td{border-bottom:1px solid var(--bd);padding:6px;text-align:left;vertical-align:top}
th{position:sticky;top:0;background:var(--bg)}small{color:var(--mut)}a{color:inherit}
.pill{display:inline-block;margin:0 8px 8px 0;padding:2px 10px;border:1px solid var(--bd);border-radius:12px;cursor:pointer}
.sDONE{color:var(--done)}.sNOTDONE{color:var(--nd)}.sERROR{color:var(--nd)}.sMANUAL{color:var(--man)}.sSKIPPED{color:var(--sk)}.sNA{color:var(--na)}
.wrap{overflow-x:auto}
</style></head><body>
<h1>CyberArk Hardening Audit</h1>
<p>$(& $enc $Report.Computer) &middot; Platform <b>$(& $enc $Report.Platform)</b> &middot; $(& $enc $Report.DomainMode) &middot; Components: $(& $enc ($Report.Components -join ', ')) &middot; $(& $enc $Report.GeneratedUtc) &middot; catalog $(& $enc $Report.CatalogVersion)</p>
<p>$($counts -join '') <span class="pill" data-all="1">show all</span></p>
<div class="wrap"><table><thead><tr><th>Id</th><th>Comp</th><th>Stage</th><th>Step</th><th>Status</th><th>Evidence</th><th>Confidence</th><th>Remediation</th><th>Official source</th></tr></thead>
<tbody>
$($rows -join "`n")
</tbody></table></div>
<p><small>Read-only audit. MANUAL items need human confirmation. Catalog find-texts come from search excerpts of docs.cyberark.com; re-verify on the live page.</small></p>
<script>
document.querySelectorAll('.pill').forEach(function(p){p.onclick=function(){var s=p.dataset.all?null:p.textContent.split(':')[0];
document.querySelectorAll('tbody tr').forEach(function(r){r.style.display=(!s||r.dataset.status===s)?'':'none'})}});
</script></body></html>
"@
}

#endregion

Export-ModuleMember -Function Invoke-CyberArkHardeningAudit, Export-HardeningReport, Get-HardeningCatalog, Test-HardeningCatalog, ConvertTo-HardeningHtml
