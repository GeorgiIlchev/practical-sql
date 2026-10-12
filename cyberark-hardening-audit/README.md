# CyberArk (Idira) PSM / CPM Hardening Audit

This is a read-only PowerShell tool. It shows which CyberArk hardening steps were done on a PSM or CPM server (or a Privilege Cloud Connector), which were skipped, and which are still to be covered.

It covers three platforms:

| `-Platform` | Meaning |
|---|---|
| `SelfHosted` | PAM Self-Hosted (PAS) |
| `PrivilegeCloudStandard` | Privilege Cloud Standard |
| `PrivilegeCloudISPSS` | Privilege Cloud on Identity Security Platform Shared Services |

It covers both domain modes: `InDomain` (hardening by GPO) and `OutOfDomain` (hardening by INF or local policy). The mode is auto-detected unless you pass it.

## Run

From an elevated PowerShell 5.1+ session on the server:

```powershell
.\Invoke-HardeningAudit.ps1 -Platform PrivilegeCloudISPSS
.\Invoke-HardeningAudit.ps1 -Platform SelfHosted -DomainMode OutOfDomain -Component PSM -OutputFolder D:\Audit
.\Invoke-HardeningAudit.ps1 -Platform SelfHosted -ValidateCatalogOnly
```

The tool finds components from their services. Pass `-PSMPath` or `-CPMPath` if auto-detection fails.

Output is `reports\CyberArkHardening_<host>_<time>.html|csv|json`. In the HTML report, click a status pill to filter the table. Each row shows **Expected after hardening** (the exact registry path, value name, type and value, or the GPO setting path) next to the **Evidence** found on the box.

## Checklist by tool (no server needed)

```powershell
.\Invoke-HardeningAudit.ps1 -ExportChecklist -OutputFolder .\checklist
```

This writes the manual checklist, grouped by the tool you verify with: Registry, Group Policy, Local Security Policy, Advanced Audit Policy, Services, AppLocker, Windows Firewall, Local Users & Groups, file ACLs, logs, hardening config files, server roles and Entra ID.

| File | Use |
|---|---|
| `checklist/Checklist_ByTool.html` | Every item, with Platform / Domain / Component filters and tick boxes. Printable. |
| `checklist/Checklist_ByTool.csv` | The same data for Excel. |
| `checklist/Checklist_<Platform>_<InDomain\|OutOfDomain>.md` | Six pre-filtered Markdown checklists. |

Each line gives:
- **Registry items:** the full key path, value name, `REG_*` type, expected value and a `Get-ItemProperty` command.
- **Group Policy items:** the full `Computer Configuration > ...` setting path, the expected state, and the policy registry key it writes. The same path applies in a domain GPO (in-domain) or in `gpedit.msc` (out-of-domain).
- **User rights / Security Options:** the policy name, the `Se...Right` constant and a `secedit` command.
- **Basis:** `Doc` means the path or value is stated by CyberArk or Microsoft docs. `Windows` means the step is documented, but the path or value is standard Windows knowledge, so verify it on your build.

## Status model

| Status | Meaning |
|---|---|
| **DONE** | The hardened state is confirmed on the box. |
| **NOT DONE** | A mandatory step is not applied. It is yet to be covered. |
| **SKIPPED** | One of two cases: an optional or default-off step that was not applied, or a step set to `No`/`False` in `CPM_Hardening_Config.xml` or `PSMHardening.ps1`. Switches in those files that the catalog doesn't model are still reported, as `CFG-*` rows. |
| **MANUAL** | No reliable automatic signal exists, or the mechanism is inferred. Evidence is attached, and a person must confirm. |
| **N/A** | The step does not apply to this platform, component or domain mode. |
| **RISK** | Compatibility risk, not a CyberArk step. Example: Microsoft Entra ID logon (see below). |
| **ERROR** | The probe itself failed (for example, the session is not elevated). |

## What is covered

| Area | Checks |
|---|---|
| PSM hardening script | PSM-01…15: log, re-run after upgrade, RDP encryption and SecurityLayer, SMB1 server and client, TLS < 1.2 off, Remote Desktop Users, AppLocker, PSMShadowUsers, ACLs, WireServer block*, Xbox services*, SupportWebApplications |
| PSM out of domain | PSM-20…24: logon rights, idle RDS limit, advanced audit, INF import |
| PSM RDS policy | PSM-30…32: auto-reconnect, encryption High, redirection (optional) |
| PSM in-domain GPO | PSM-40 (Self-Hosted) |
| Privilege Cloud connector | CON-01…04: Unified Hardening GPO, dedicated OU, out-of-domain INF, GPO-before-upgrade |
| Entra ID compatibility | ENT-01…02: RDS Session Host role on an Entra-joined host, PKU2U |
| CPM | CPM-01…16: log, re-run after upgrade, IsPSMInstalled, service users, Log on as a service, DEP, services, TLS, FIPS (optional), roles, audit, event log, INF, GPO |

\* Documented on the Privilege Cloud **Standard** page only. ISPSS applicability was not verified.

Each check in `HardeningCatalog.json` carries:
- one or more official source URLs;
- a `find` phrase to Ctrl+F on that page;
- a `confidence` value.

Adding a step means adding a JSON entry. No code changes are needed unless it needs a new probe type.

## Microsoft Entra ID compatibility (ENT-01, ENT-02)

- **ENT-01. Entra ID joined server with the RDS Session Host role (`RDS-RD-Server`) installed → RISK.**
  - PSM needs this role.
  - Field reports say installing it breaks Entra ID SSO and Entra ID logon.
  - Microsoft Learn does **not** document this for standalone RDS, and AVD documents Entra-joined session hosts *with* this role. Treat it as unverified and test Entra logon after the role install and again after hardening.
  - Join state is read from `dsregcmd /status`.
- **ENT-02. PKU2U → RISK when Entra joined and not enabled.**
  - Microsoft documents that *"Network security: Allow PKU2U authentication requests to this computer to use online identities"* must be enabled on the server and on the client for Entra ID RDP sign-in.
  - Hardening baselines often disable it.
  - Source: [Microsoft Learn](https://learn.microsoft.com/en-us/entra/identity/devices/howto-vm-sign-in-azure-ad-windows). Ctrl+F `Allow PKU2U`.
  - The registry location `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\pku2u\AllowOnlineID` is my own Windows knowledge, not taken from that page.

## Honesty notes (read before relying on results)

1. **Source access.** The sandbox's network policy blocked `docs.cyberark.com`. Every source was found through web-search excerpts of the official pages, not by reading the full page. All URLs are official CyberArk docs (high credibility). The `find` phrases come from those excerpts, so re-verify them on the live pages.
2. **Confidence levels.**
   - `Documented`: the doc states the setting and the value.
   - `StepDocumented-MechanismInferred`: the doc names the step, but the registry path, service name or probe is my own Windows knowledge. These checks mostly fall back to MANUAL rather than NOT DONE.
   - `VersionDependent`: the docs differ by version. For example, CPM TLS 1.2 (v13.0) vs TLS 1.3 (latest), the CPM service list, and the GPO package version (v2.4.0 vs v2.5.0).
3. **Not checked.** The exact element names inside `CPM_Hardening_Config.xml` and the exact parameter list of `PSMHardening.ps1`. The parser is generic for that reason. Also not checked: the PSM `SecurityLayer` target value, the audit-subcategory table, and the event-log sizes. Those rows are evidence-only (MANUAL).
4. **Testing.** `tests/Run-Tests.ps1` mocks every Windows call and asserts statuses for a hardened ISPSS PSM and for a bare Self-Hosted PSM+CPM server. It passes on PowerShell 7.4 (Linux). The tool has **not** been run on a real Windows Server yet.

```powershell
pwsh ./tests/Run-Tests.ps1
```
