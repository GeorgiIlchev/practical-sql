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

Output is `reports\CyberArkHardening_<host>_<time>.html|csv|json`. In the HTML report, click a status pill to filter the table.

## Status model

| Status | Meaning |
|---|---|
| **DONE** | The hardened state is confirmed on the box. |
| **NOT DONE** | A mandatory step is not applied. It is yet to be covered. |
| **SKIPPED** | One of two cases: an optional or default-off step that was not applied, or a step set to `No`/`False` in `CPM_Hardening_Config.xml` or `PSMHardening.ps1`. Switches in those files that the catalog doesn't model are still reported, as `CFG-*` rows. |
| **MANUAL** | No reliable automatic signal exists, or the mechanism is inferred. Evidence is attached, and a person must confirm. |
| **N/A** | The step does not apply to this platform, component or domain mode. |
| **ERROR** | The probe itself failed (for example, the session is not elevated). |

## What is covered

| Area | Checks |
|---|---|
| PSM hardening script | PSM-01…15: log, re-run after upgrade, RDP encryption and SecurityLayer, SMB1 server and client, TLS < 1.2 off, Remote Desktop Users, AppLocker, PSMShadowUsers, ACLs, WireServer block*, Xbox services*, SupportWebApplications |
| PSM out of domain | PSM-20…24: logon rights, idle RDS limit, advanced audit, INF import |
| PSM RDS policy | PSM-30…32: auto-reconnect, encryption High, redirection (optional) |
| PSM in-domain GPO | PSM-40 (Self-Hosted) |
| Privilege Cloud connector | CON-01…04: Unified Hardening GPO, dedicated OU, out-of-domain INF, GPO-before-upgrade |
| CPM | CPM-01…16: log, re-run after upgrade, IsPSMInstalled, service users, Log on as a service, DEP, services, TLS, FIPS (optional), roles, audit, event log, INF, GPO |

\* Documented on the Privilege Cloud **Standard** page only. ISPSS applicability was not verified.

Each check in `HardeningCatalog.json` carries:
- one or more official source URLs;
- a `find` phrase to Ctrl+F on that page;
- a `confidence` value.

Adding a step means adding a JSON entry. No code changes are needed unless it needs a new probe type.

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
