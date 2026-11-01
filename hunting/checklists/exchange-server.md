# Checklist: Exchange server

On-premises Exchange servers (Mailbox and Edge Transport roles, with OWA, ECP, EWS, ActiveSync and Autodiscover in front). Run the [baseline](00-baseline-all-windows-hosts.md) first, and the [web server](web-server.md) checklist for the IIS side. Exchange is exploited from the internet more often than any other Windows server (ProxyLogon, ProxyShell, ProxyNotShell and their successors), holds every mailbox, and has very high rights in Active Directory, so the questions are how it was entered, whether mail was read, exported or redirected, and whether its AD rights were used.

## 1. Host profile

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 1.1 | Exchange version and cumulative update | [TRI-05](../queries/windows/00-triage/TRI-05-installed-software/) | 1.2.1, 1.2.3 | The CU and security update level against the exploited CVEs of the incident window; unsupported versions (2013 and older). |
| 1.2 | Which logs were collected | [TRI-02](../queries/windows/00-triage/TRI-02-event-log-coverage/) | 1.2.3, 2.4 | The `MSExchange Management` log, PowerShell Operational, Security with 4688 command lines. Without them most of sections 3 and 4 is blind. |
| 1.3 | Which mailboxes matter, and which accounts administer Exchange | | 1.3.2 | Ask the client: executives, finance and legal mailboxes; members of Organization Management. |

## 2. Exploitation and web shells

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 2.1 | Exploitation signs in the event logs | [IA-04](../queries/windows/TA0001-initial-access/IA-04-web-app-exploitation-events/) | 2.4 | Exchange paths (`/owa/auth`, `/ecp/`, `autodiscover.json`, `/powershell`) in errors, deserialization gadgets, `MSExchange` and `w3wp.exe` crashes. |
| 2.2 | Web exploitation in the IIS logs, if they were loaded | [AIA-04](../queries/aws/TA0001-initial-access/AIA-04-web-exploitation-attempts/), [APE-03](../queries/aws/TA0003-persistence/APE-03-web-shell-requests/) | 2.4 | `autodiscover.json?@...` and `/mapi/nspi` probes, `X-` headers and long encoded URLs answered with 200, POSTs to `.aspx` files few clients ever requested. |
| 2.3 | Web shells under the Exchange folders | [PE-17](../queries/windows/TA0003-persistence/PE-17-web-shell-files/) | 2.1.4 | New `.aspx` files in `FrontEnd\HttpProxy\owa\auth`, `ecp\auth`, `aspnet_client` and OAB folders, often small or with a random name. |
| 2.4 | Exchange processes starting shells | [PE-18](../queries/windows/TA0003-persistence/PE-18-server-process-spawns-shell-4688/), [PE-19](../queries/windows/TA0003-persistence/PE-19-server-process-spawns-shell-sysmon/) | 2.4.5 | `w3wp.exe` (MSExchange application pools), `UMWorkerProcess.exe`, `EdgeTransport.exe` starting `cmd`, PowerShell, `whoami`, `certutil` or `rundll32`. |
| 2.5 | Virtual directory and certificate changes | [CO-07](../queries/windows/TA0009-collection/CO-07-exchange-mailbox-exports-forwarding-and-permissions/) | 2.4 | `Set-OabVirtualDirectory -ExternalUrl` (the ProxyShell web-shell drop), new or imported Exchange certificates. |

## 3. Mail taken or redirected

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 3.1 | Mailbox exports and content searches | [CO-07](../queries/windows/TA0009-collection/CO-07-exchange-mailbox-exports-forwarding-and-permissions/) | 2.1.4 | `New-MailboxExportRequest` to a UNC or web-reachable path, `New-ComplianceSearch`, `Search-Mailbox -TargetMailbox`, then `Remove-MailboxExportRequest`. |
| 3.2 | Exported `.pst` files on disk | [CO-01](../queries/windows/TA0009-collection/CO-01-archives-and-staged-files/) | 2.1.4 | `.pst` files in `\inetpub\`, `\FrontEnd\HttpProxy\`, `C:\ProgramData` or temp folders. |
| 3.3 | Forwarding, inbox rules and transport rules | [CO-07](../queries/windows/TA0009-collection/CO-07-exchange-mailbox-exports-forwarding-and-permissions/) | 2.4 | `ForwardingSmtpAddress` to outside addresses, inbox rules that forward or delete, transport or journal rules with `BlindCopyTo`. |
| 3.4 | Mailbox and impersonation rights | [CO-07](../queries/windows/TA0009-collection/CO-07-exchange-mailbox-exports-forwarding-and-permissions/) | 2.4.20 | `Add-MailboxPermission ... FullAccess`, `ApplicationImpersonation` or `Mailbox Import Export` role assignments. |
| 3.5 | Data sent out | [EXF-04](../queries/windows/TA0010-exfiltration/EXF-04-exfil-and-cloud-sync-tools/), [C2-06](../queries/windows/TA0011-command-and-control/C2-06-outbound-connections-by-application-wfp/) | 2.4.7 | Archivers and transfer tools on the server, `w3wp.exe` or tools connecting to public addresses. |

## 4. Active Directory and the rest of the network

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 4.1 | Exchange AD groups and rights used | [PE-16](../queries/windows/TA0003-persistence/PE-16-account-and-group-changes/), [PR-02](../queries/windows/TA0004-privilege-escalation/PR-02-ad-sensitive-changes/) | 2.4.18 to 2.4.20 | Accounts added to `Exchange Windows Permissions`, `Exchange Trusted Subsystem` or `Organization Management`; DACL changes on the domain object (the path to DCSync). |
| 4.2 | Credential theft on the server | [CA-01](../queries/windows/TA0006-credential-access/CA-01-credential-dumping-events/), [CA-02](../queries/windows/TA0006-credential-access/CA-02-dump-files-mft/) | 2.4.22 | LSASS dumps (`comsvcs.dll MiniDump`, `procdump`) run by the web shell; Exchange often has domain admins' sessions in memory. |
| 4.3 | Lateral movement from the server | [LM-01](../queries/windows/TA0008-lateral-movement/LM-01-lateral-movement-methods/), [LM-03](../queries/windows/TA0008-lateral-movement/LM-03-logon-sessions-with-duration/) | 2.4.13 | RDP, SMB and WinRM sessions from the Exchange server to DCs and other servers. |
| 4.4 | Audit logging switched off | [CO-07](../queries/windows/TA0009-collection/CO-07-exchange-mailbox-exports-forwarding-and-permissions/), [DE-02](../queries/windows/TA0112-defense-impairment/DE-02-event-log-clearing/) | 2.4.21 | `Set-AdminAuditLogConfig`, mailbox audit bypass, cleared event logs. |

## Not covered by these queries

- Exchange's own log files: `HttpProxy` logs (the best record of ProxyShell-style requests), ECP and OWA logs, `MSExchange Management` cmdlet logs in `Logging\CmdletInfra`, message tracking logs (who sent what to whom) and the admin audit log mailbox. Collect them from the Exchange installation's `Logging` folder and read them, or load them as generic CSV.
- Microsoft's Exchange on-premises mitigation and `Test-ProxyLogon` scripts, run against a copy of those logs.
- Exchange Online and Microsoft 365 audit logs (Unified Audit Log), which this toolkit does not load.
