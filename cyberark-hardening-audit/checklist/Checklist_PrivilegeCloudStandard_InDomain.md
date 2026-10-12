# CyberArk PSM / CPM hardening checklist - by tool

Platform: **PrivilegeCloudStandard** | Domain mode: **InDomain** | Catalog 2026-10-10

Basis: **Doc** = path/value stated by CyberArk or Microsoft docs. **Windows** = the step is documented but the path/value is standard Windows knowledge, verify on your build. Optional steps are marked *(optional)*.

## Registry

| Done | ID | Applies to | Path / location | Value / setting | Type | Expected after hardening | Verify | Basis |
|---|---|---|---|---|---|---|---|---|
| [ ] | CPM-06 | CPM; Any | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers` | <full path>\PMTerminal.exe \| Telnet.exe \| Plink.exe | REG_SZ | Data contains DisableNXShowUI - _The doc names the executables; this registry mechanism is inferred._ | `Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers' -Name '<full path>\PMTerminal.exe \| Telnet.exe \| Plink.exe'` | Windows |
| [ ] | CPM-09 | CPM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client` | Enabled | REG_DWORD | 0 | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -Name 'Enabled'` | Doc |
| [ ] | CPM-09 | CPM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client` | Enabled | REG_DWORD | 0 | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Name 'Enabled'` | Doc |
| [ ] | CPM-09 | CPM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server` | DisabledByDefault | REG_DWORD | 1 | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Name 'DisabledByDefault'` | Doc |
| [ ] | CPM-09 | CPM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server` | Enabled | REG_DWORD | 0 | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Name 'Enabled'` | Doc |
| [ ] | CPM-09 | CPM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client` | DisabledByDefault | REG_DWORD | 1 | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -Name 'DisabledByDefault'` | Doc |
| [ ] | CPM-09 | CPM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server` | DisabledByDefault | REG_DWORD | 1 | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'DisabledByDefault'` | Doc |
| [ ] | CPM-09 | CPM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server` | DisabledByDefault | REG_DWORD | 1 | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Name 'DisabledByDefault'` | Doc |
| [ ] | CPM-09 | CPM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server` | Enabled | REG_DWORD | 0 | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Name 'Enabled'` | Doc |
| [ ] | CPM-09 | CPM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client` | Enabled | REG_DWORD | 0 | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'Enabled'` | Doc |
| [ ] | CPM-09 | CPM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server` | DisabledByDefault | REG_DWORD | 1 | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'DisabledByDefault'` | Doc |
| [ ] | CPM-09 | CPM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client` | DisabledByDefault | REG_DWORD | 1 | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'DisabledByDefault'` | Doc |
| [ ] | CPM-09 | CPM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client` | Enabled | REG_DWORD | 0 | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name 'Enabled'` | Doc |
| [ ] | CPM-09 | CPM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client` | DisabledByDefault | REG_DWORD | 1 | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name 'DisabledByDefault'` | Doc |
| [ ] | CPM-09 | CPM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server` | Enabled | REG_DWORD | 0 | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'Enabled'` | Doc |
| [ ] | CPM-09 | CPM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client` | DisabledByDefault | REG_DWORD | 1 | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Name 'DisabledByDefault'` | Doc |
| [ ] | CPM-09 | CPM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server` | Enabled | REG_DWORD | 0 | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'Enabled'` | Doc |
| [ ] | CPM-10 | CPM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server` | Enabled | REG_DWORD | Per your version: 1 if TLSVersions=UseTLS1_2 | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'Enabled'` | Windows |
| [ ] | CPM-10 | CPM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server` | Enabled | REG_DWORD | 1 on latest (doc: script enables TLS 1.3) | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server' -Name 'Enabled'` | Windows |
| [ ] | CPM-11 | CPM; Any *(optional)* | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy` | Enabled | REG_DWORD | 1 if FIPS required, else 0 | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy' -Name 'Enabled'` | Windows |
| [ ] | ENT-02 | Any; Any | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\pku2u` | AllowOnlineID | REG_DWORD | 1 (Enabled) - _Registry location is Windows knowledge; the policy name is from Microsoft Learn._ | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\Lsa\pku2u' -Name 'AllowOnlineID'` | Windows |
| [ ] | PSM-03 | PSM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp` | MinEncryptionLevel | REG_DWORD | 3 (High) - _Value from the CyberArk doc; key location is standard Windows._ | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'MinEncryptionLevel'` | Doc |
| [ ] | PSM-04 | PSM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp` | SecurityLayer | REG_DWORD | Value set by PSMHardening.ps1. Windows meaning: 0 = RDP, 1 = Negotiate, 2 = SSL/TLS. Target value not confirmed from the doc. | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'SecurityLayer'` | Doc |
| [ ] | PSM-05 | PSM; Any | `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters` | SMB1 | REG_DWORD | 0 (or value absent when the SMB1 feature is removed) | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1'` | Windows |
| [ ] | PSM-06 | PSM; Any | `HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10` | Start | REG_DWORD | 4 (Disabled) | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10' -Name 'Start'` | Doc |
| [ ] | PSM-06 | PSM; Any | `HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation` | DependOnService | REG_MULTI_SZ | Does NOT contain MRxSmb10 (typically Bowser, MRxSmb20, NSI) | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation' -Name 'DependOnService'` | Doc |
| [ ] | PSM-07 | PSM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server` | Enabled | REG_DWORD | 1 (or absent = OS default on) - _Doc: 'leaves only TLS 1.2 enabled'. Client key same._ | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'Enabled'` | Windows |
| [ ] | PSM-07 | PSM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client` | Enabled | REG_DWORD | 0 | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name 'Enabled'` | Doc |
| [ ] | PSM-07 | PSM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client` | Enabled | REG_DWORD | 0 | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'Enabled'` | Doc |
| [ ] | PSM-07 | PSM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server` | DisabledByDefault | REG_DWORD | 1 | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'DisabledByDefault'` | Doc |
| [ ] | PSM-07 | PSM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server` | Enabled | REG_DWORD | 0 | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server' -Name 'Enabled'` | Doc |
| [ ] | PSM-07 | PSM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client` | DisabledByDefault | REG_DWORD | 1 | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client' -Name 'DisabledByDefault'` | Doc |
| [ ] | PSM-07 | PSM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server` | DisabledByDefault | REG_DWORD | 1 | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'DisabledByDefault'` | Doc |
| [ ] | PSM-07 | PSM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server` | Enabled | REG_DWORD | 0 | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name 'Enabled'` | Doc |
| [ ] | PSM-07 | PSM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client` | DisabledByDefault | REG_DWORD | 1 | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Name 'DisabledByDefault'` | Doc |
| [ ] | PSM-07 | PSM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client` | Enabled | REG_DWORD | 0 | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client' -Name 'Enabled'` | Doc |
| [ ] | PSM-07 | PSM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server` | DisabledByDefault | REG_DWORD | 1 | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Name 'DisabledByDefault'` | Doc |
| [ ] | PSM-07 | PSM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server` | Enabled | REG_DWORD | 0 | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server' -Name 'Enabled'` | Doc |
| [ ] | PSM-07 | PSM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client` | DisabledByDefault | REG_DWORD | 1 | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -Name 'DisabledByDefault'` | Doc |
| [ ] | PSM-07 | PSM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client` | Enabled | REG_DWORD | 0 | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client' -Name 'Enabled'` | Doc |
| [ ] | PSM-07 | PSM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server` | DisabledByDefault | REG_DWORD | 1 | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Name 'DisabledByDefault'` | Doc |
| [ ] | PSM-07 | PSM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server` | Enabled | REG_DWORD | 0 | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server' -Name 'Enabled'` | Doc |
| [ ] | PSM-07 | PSM; Any | `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client` | DisabledByDefault | REG_DWORD | 1 | `Get-ItemProperty -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client' -Name 'DisabledByDefault'` | Doc |
| [ ] | PSM-30 | PSM; Any | `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services` | fDisableAutoReconnect | REG_DWORD | 1 | `Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'fDisableAutoReconnect'` | Windows |
| [ ] | PSM-31 | PSM; Any | `HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services` | MinEncryptionLevel | REG_DWORD | 3 | `Get-ItemProperty -Path 'Registry::HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name 'MinEncryptionLevel'` | Windows |

## Group Policy

| Done | ID | Applies to | Path / location | Value / setting | Type | Expected after hardening | Verify | Basis |
|---|---|---|---|---|---|---|---|---|
| [ ] | CON-01 | Any; InDomain | `gpresult /scope computer /r > Applied Group Policy Objects` | Privilege Cloud Connector Unified Hardening GPO (or In-Domain PSM GPO for PSM-only) |  | Listed as applied; legacy CPM/PSM GPO links removed (v13.0+) | `gpresult /scope computer /r` | Doc |
| [ ] | CPM-14 | CPM; Any | `Computer Configuration > Administrative Templates > Windows Components > Event Log Service > Application \| Security \| System` | Specify the maximum log file size (KB); Control Event Log behavior when the log file reaches its maximum size |  | Per CPM doc values (not verified here) (registry: HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\<Log>\MaxSize, Retention) | `gpresult /h C:\temp\rsop.html  (or rsop.msc)` | Windows |
| [ ] | PSM-04 | PSM; Any | `Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Security` | Require use of specific security layer for remote (RDP) connections |  | Match your approved value (registry: HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\SecurityLayer) | `gpresult /h C:\temp\rsop.html  (or rsop.msc)` | Windows |
| [ ] | PSM-05 | PSM; Any | `Computer Configuration > Administrative Templates > MS Security Guide` | Configure SMB v1 server |  | Disabled - _Requires the Microsoft Security Baseline SecGuide.admx._ | `gpresult /h C:\temp\rsop.html  (or rsop.msc)` | Windows |
| [ ] | PSM-06 | PSM; Any | `Computer Configuration > Administrative Templates > MS Security Guide` | Configure SMB v1 client driver |  | Enabled: Disable driver (recommended) - _Requires SecGuide.admx._ | `gpresult /h C:\temp\rsop.html  (or rsop.msc)` | Windows |
| [ ] | PSM-30 | PSM; Any | `Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Connections` | Automatic reconnection |  | Disabled (registry: HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisableAutoReconnect = 1) | `gpresult /h C:\temp\rsop.html  (or rsop.msc)` | Doc |
| [ ] | PSM-31 | PSM; Any | `Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Security` | Set client connection encryption level |  | Enabled: High Level (registry: HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\MinEncryptionLevel = 3) | `gpresult /h C:\temp\rsop.html  (or rsop.msc)` | Doc |
| [ ] | PSM-32 | PSM; Any *(optional)* | `Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Printer Redirection` | Do not allow client printer redirection |  | Enabled (if printers not used) (registry: HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisableCpm = 1) | `gpresult /h C:\temp\rsop.html  (or rsop.msc)` | Doc |
| [ ] | PSM-32 | PSM; Any *(optional)* | `Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Device and Resource Redirection` | Do not allow drive redirection |  | Enabled (if drives not used) (registry: HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisableCdm = 1) | `gpresult /h C:\temp\rsop.html  (or rsop.msc)` | Doc |
| [ ] | PSM-32 | PSM; Any *(optional)* | `Computer Configuration > Administrative Templates > Windows Components > Remote Desktop Services > Remote Desktop Session Host > Device and Resource Redirection` | Do not allow Clipboard redirection |  | Enabled (if clipboard not used) (registry: HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\fDisableClip = 1) | `gpresult /h C:\temp\rsop.html  (or rsop.msc)` | Doc |

## Local Security Policy

| Done | ID | Applies to | Path / location | Value / setting | Type | Expected after hardening | Verify | Basis |
|---|---|---|---|---|---|---|---|---|
| [ ] | CPM-05 | CPM; Any | `Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment` | Log on as a service (SeServiceLogonRight) |  | Includes PasswordManagerUser and ScannerUser; other holders reviewed | `secedit /export /areas USER_RIGHTS /cfg C:\temp\ur.inf ; Select-String SeServiceLogonRight C:\temp\ur.inf` | Doc |
| [ ] | CPM-05 | CPM; Any | `Computer Configuration > Windows Settings > Security Settings > Local Policies > User Rights Assignment` | Allow log on locally (SeInteractiveLogonRight) |  | Includes the CPM user (latest doc: without it CPM cannot manage accounts) | `secedit /export /areas USER_RIGHTS /cfg C:\temp\ur.inf ; Select-String SeInteractiveLogonRight C:\temp\ur.inf` | Doc |
| [ ] | CPM-11 | CPM; Any *(optional)* | `Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options` | System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing |  | Enabled ONLY if EnableFIPSCryptography=Yes (optional, default No) | `secpol.msc` | Windows |
| [ ] | ENT-02 | Any; Any | `Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options` | Network security: Allow PKU2U authentication requests to this computer to use online identities |  | Enabled when Entra ID RDP logon is required | `secpol.msc` | Doc |

## Advanced Audit Policy

| Done | ID | Applies to | Path / location | Value / setting | Type | Expected after hardening | Verify | Basis |
|---|---|---|---|---|---|---|---|---|
| [ ] | CPM-13 | CPM; Any | `Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration` | Subcategories |  | Per CPM task-description audit table (mostly Success and Failure) | `auditpol /get /category:*` | Doc |

## Services

| Done | ID | Applies to | Path / location | Value / setting | Type | Expected after hardening | Verify | Basis |
|---|---|---|---|---|---|---|---|---|
| [ ] | CPM-07 | CPM; Any | `Computer Configuration > Windows Settings > Security Settings > System Services  \|  HKLM\SYSTEM\CurrentControlSet\Services\RemoteAccess` | RemoteAccess | REG_DWORD Start | Disabled (Start = 4) | `Get-Service -Name 'RemoteAccess' \| Select Name,StartType,Status` | Windows |
| [ ] | CPM-07 | CPM; Any | `Computer Configuration > Windows Settings > Security Settings > System Services  \|  HKLM\SYSTEM\CurrentControlSet\Services\SNMPTRAP` | SNMPTRAP | REG_DWORD Start | Disabled (Start = 4) | `Get-Service -Name 'SNMPTRAP' \| Select Name,StartType,Status` | Windows |
| [ ] | CPM-07 | CPM; Any | `Computer Configuration > Windows Settings > Security Settings > System Services  \|  HKLM\SYSTEM\CurrentControlSet\Services\sacsvr` | sacsvr | REG_DWORD Start | Disabled (Start = 4) | `Get-Service -Name 'sacsvr' \| Select Name,StartType,Status` | Windows |
| [ ] | CPM-07 | CPM; Any | `Computer Configuration > Windows Settings > Security Settings > System Services  \|  HKLM\SYSTEM\CurrentControlSet\Services\WerSvc` | WerSvc | REG_DWORD Start | Disabled (Start = 4) | `Get-Service -Name 'WerSvc' \| Select Name,StartType,Status` | Windows |
| [ ] | CPM-07 | CPM; Any | `Computer Configuration > Windows Settings > Security Settings > System Services  \|  HKLM\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc` | WinHttpAutoProxySvc | REG_DWORD Start | Disabled (Start = 4) | `Get-Service -Name 'WinHttpAutoProxySvc' \| Select Name,StartType,Status` | Windows |
| [ ] | PSM-09 | PSM; Any | `Computer Configuration > Windows Settings > Security Settings > System Services  \|  HKLM\SYSTEM\CurrentControlSet\Services\AppIDSvc` | AppIDSvc | REG_DWORD Start | Automatic and Running (Application Identity) | `Get-Service -Name 'AppIDSvc' \| Select Name,StartType,Status` | Windows |
| [ ] | PSM-14 | PSM; Any | `Computer Configuration > Windows Settings > Security Settings > System Services  \|  HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager` | XblAuthManager | REG_DWORD Start | Disabled (Start = 4) if present | `Get-Service -Name 'XblAuthManager' \| Select Name,StartType,Status` | Windows |
| [ ] | PSM-14 | PSM; Any | `Computer Configuration > Windows Settings > Security Settings > System Services  \|  HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave` | XblGameSave | REG_DWORD Start | Disabled (Start = 4) if present | `Get-Service -Name 'XblGameSave' \| Select Name,StartType,Status` | Windows |
| [ ] | PSM-14 | PSM; Any | `Computer Configuration > Windows Settings > Security Settings > System Services  \|  HKLM\SYSTEM\CurrentControlSet\Services\XboxGipSvc` | XboxGipSvc | REG_DWORD Start | Disabled (Start = 4) if present | `Get-Service -Name 'XboxGipSvc' \| Select Name,StartType,Status` | Windows |
| [ ] | PSM-14 | PSM; Any | `Computer Configuration > Windows Settings > Security Settings > System Services  \|  HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc` | XboxNetApiSvc | REG_DWORD Start | Disabled (Start = 4) if present | `Get-Service -Name 'XboxNetApiSvc' \| Select Name,StartType,Status` | Windows |

## AppLocker

| Done | ID | Applies to | Path / location | Value / setting | Type | Expected after hardening | Verify | Basis |
|---|---|---|---|---|---|---|---|---|
| [ ] | PSM-09 | PSM; Any | `Computer Configuration > Windows Settings > Security Settings > Application Control Policies > AppLocker > Executable Rules` | Rules + enforcement |  | Rules from PSMConfigureAppLocker.xml present; enforcement = Enforce rules | `Get-AppLockerPolicy -Effective -Xml > C:\temp\applocker.xml` | Doc |

## Windows Firewall

| Done | ID | Applies to | Path / location | Value / setting | Type | Expected after hardening | Verify | Basis |
|---|---|---|---|---|---|---|---|---|
| [ ] | PSM-13 | PSM; Any | `wf.msc > Outbound Rules` | Block rule to 168.63.129.16 |  | Enabled, Action = Block, Protocol TCP, RemotePort 80,443, RemoteAddress 168.63.129.16 | `Get-NetFirewallRule -Direction Outbound -Action Block -Enabled True \| ? { ($_ \| Get-NetFirewallAddressFilter).RemoteAddress -contains '168.63.129.16' }` | Doc |

## Local Users & Groups

| Done | ID | Applies to | Path / location | Value / setting | Type | Expected after hardening | Verify | Basis |
|---|---|---|---|---|---|---|---|---|
| [ ] | CPM-04 | CPM; Any | `lusrmgr.msc > Users` | PasswordManagerUser, ScannerUser (latest docs also PluginManagerUser) |  | Exist | `Get-LocalUser PasswordManagerUser,ScannerUser,PluginManagerUser` | Doc |
| [ ] | PSM-08 | PSM; Any *(optional)* | `lusrmgr.msc > Groups > Remote Desktop Users` | Members |  | Empty if ClearRemoteDesktopUsers=Yes; otherwise only non-admin maintenance users | `Get-LocalGroupMember -Group 'Remote Desktop Users'` | Doc |
| [ ] | PSM-11 | PSM; Any | `lusrmgr.msc > Groups` | PSMShadowUsers |  | Group exists | `Get-LocalGroup -Name PSMShadowUsers` | Doc |

## File system ACL

| Done | ID | Applies to | Path / location | Value / setting | Type | Expected after hardening | Verify | Basis |
|---|---|---|---|---|---|---|---|---|
| [ ] | PSM-12 | PSM; Any | `<PSM install folder>; also C:\CyberArk and C:\InetPub (legacy doc)` | ACEs for PSMConnect, PSMAdminConnect, PSMShadowUsers |  | Allow/Deny rules written by the hardening script present | `icacls '<PSM>'` | Doc |

## Files & Logs

| Done | ID | Applies to | Path / location | Value / setting | Type | Expected after hardening | Verify | Basis |
|---|---|---|---|---|---|---|---|---|
| [ ] | CPM-01 | CPM; Any | `<CPM install>\InstallationAutomation\*.log` | Newest hardening log |  | Exists; no Error / Failed lines - _Log location inferred._ | `Get-ChildItem '<CPM>\InstallationAutomation' -Recurse -Filter *.log \| Sort LastWriteTime \| Select -Last 1 \| Select-String 'error\|failed'` | Doc |
| [ ] | CPM-02 | CPM; Any | `<CPM install>\InstallationAutomation\*.log vs <CPM install>\*.exe` | Timestamps |  | Hardening re-run (CPM_Hardening.ps1 -FromVersion <old>) after last upgrade | `compare LastWriteTime` | Doc |
| [ ] | PSM-01 | PSM; Any | `<PSM install>\Hardening\*.log` | Newest hardening log |  | Exists; no lines with Error / Failed / Exception - _The log file name and location are inferred; the doc says only 'check the log for errors'._ | `Get-ChildItem '<PSM>\Hardening\*.log' \| Sort LastWriteTime \| Select -Last 1 \| Select-String 'error\|failed\|exception'` | Doc |
| [ ] | PSM-02 | PSM; Any | `<PSM install>\Hardening\*.log vs <PSM install>\*.exe` | Log timestamp vs binary timestamp |  | Newest hardening log is newer than newest PSM binary (hardening re-run after upgrade) | `(Get-ChildItem '<PSM>\Hardening\*.log' \| Sort LastWriteTime)[-1].LastWriteTime ; (Get-ChildItem '<PSM>\*.exe' \| Sort LastWriteTime)[-1].LastWriteTime` | Doc |
| [ ] | PSM-10 | PSM; Any | `<PSM install>\Hardening` | PSMConfigureAppLocker.xml, PSMConfigureAppLocker.ps1 |  | Both present; custom rules (e.g. Universal Connector exes) re-merged after upgrade | `Test-Path '<PSM>\Hardening\PSMConfigureAppLocker.xml'` | Doc |

## Hardening config

| Done | ID | Applies to | Path / location | Value / setting | Type | Expected after hardening | Verify | Basis |
|---|---|---|---|---|---|---|---|---|
| [ ] | CPM-03 | CPM; Any | `<CPM install>\InstallationAutomation\CPM_Hardening_Config.xml` | IsPSMInstalled |  | True when PSM is on the same server (set BEFORE running) | `Select-String -Path '<CPM>\InstallationAutomation\CPM_Hardening_Config.xml' -Pattern 'IsPSMInstalled'` | Doc |
| [ ] | CPM-10 | CPM; Any | `<CPM install>\InstallationAutomation\CPM_Hardening_Config.xml` | TLSVersions |  | Approved value (e.g. UseTLS1_2) | `Select-String ... -Pattern 'TLSVersions'` | Doc |
| [ ] | PSM-08 | PSM; Any *(optional)* | `<PSM install>\Hardening\PSMHardening.ps1` | ClearRemoteDesktopUsers |  | Default No; Yes only if approved (leave No with ActiveX) | `Select-String -Path '<PSM>\Hardening\PSMHardening.ps1' -Pattern 'ClearRemoteDesktopUsers'` | Doc |
| [ ] | PSM-15 | PSM; Any | `<PSM install>\Hardening\PSMHardening.ps1` | SupportWebApplications / $SUPPORT_WEB_APPLICATIONS |  | Default Yes; set No if PSM is not used for web apps (security-team approved) | `Select-String -Path '<PSM>\Hardening\PSMHardening.ps1' -Pattern 'SUPPORT_WEB_APPLICATIONS\|SupportWebApplications'` | Doc |

## Server roles

| Done | ID | Applies to | Path / location | Value / setting | Type | Expected after hardening | Verify | Basis |
|---|---|---|---|---|---|---|---|---|
| [ ] | CPM-12 | CPM; Any | `Server Manager / Get-WindowsFeature` | Installed roles & features |  | Only the minimum required (no RDS Session Host on a CPM-only server) | `Get-WindowsFeature \| ? Installed \| Select Name,FeatureType` | Doc |
| [ ] | ENT-01 | Any; Any | `Get-WindowsFeature` | RDS-RD-Server (Remote Desktop Session Host) |  | If Entra joined: flag as RISK and test Entra / SSO logon | `Get-WindowsFeature RDS-RD-Server` | Windows |

## Entra ID join state

| Done | ID | Applies to | Path / location | Value / setting | Type | Expected after hardening | Verify | Basis |
|---|---|---|---|---|---|---|---|---|
| [ ] | ENT-01 | Any; Any | `dsregcmd /status` | AzureAdJoined, DomainJoined, AzureAdPrt |  | Document the join type; Microsoft goal state for Entra logon: AzureAdJoined : YES, AzureAdPrt : YES | `dsregcmd /status` | Doc |

## PowerShell

| Done | ID | Applies to | Path / location | Value / setting | Type | Expected after hardening | Verify | Basis |
|---|---|---|---|---|---|---|---|---|
| [ ] | PSM-05 | PSM; Any | `Get-SmbServerConfiguration` | EnableSMB1Protocol |  | False | `(Get-SmbServerConfiguration).EnableSMB1Protocol` | Windows |

## Task Scheduler

| Done | ID | Applies to | Path / location | Value / setting | Type | Expected after hardening | Verify | Basis |
|---|---|---|---|---|---|---|---|---|
| [ ] | PSM-14 | PSM; Any | `Task Scheduler Library > Microsoft > XblGameSave` | XblGameSaveTask |  | Disabled if present | `Get-ScheduledTask -TaskPath '\Microsoft\XblGameSave\'` | Windows |

## Active Directory

| Done | ID | Applies to | Path / location | Value / setting | Type | Expected after hardening | Verify | Basis |
|---|---|---|---|---|---|---|---|---|
| [ ] | CON-02 | Any; InDomain | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\State\Machine > Distinguished-Name` | Computer OU |  | Dedicated connector OU (GPO reaches no other servers) | `([adsisearcher]"(cn=$env:COMPUTERNAME)").FindOne().Path` | Doc |

## Change records

| Done | ID | Applies to | Path / location | Value / setting | Type | Expected after hardening | Verify | Basis |
|---|---|---|---|---|---|---|---|---|
| [ ] | CON-04 | Any; Any | `Upgrade runbook` | GPO update before component upgrade; GPO customisations re-applied |  | Evidence in change ticket | `n/a (process)` | Doc |

