# CO-07 Exchange: mailbox exports and searches, forwarding and inbox rules, transport rules, mailbox permissions and audit changes

| | |
|---|---|
| Tactic | TA0009 Collection |
| ATT&CK | T1114.002 Remote Email Collection, T1114.003 Email Forwarding Rule, T1098.002 Additional Email Delegate Permissions, T1505.003 Web Shell, T1562 Impair Defenses |
| Indexes | `evtxlogs-*` |
| Needs | the `MSExchange Management` event log, PowerShell Operational 4104, Windows PowerShell 400/800 or Security 4688 with command lines, from the Exchange servers |
| Roles | Exchange server; any host where Exchange Management Shell is used |

**What it finds.** Exchange cmdlets that take or redirect mail, or prepare for it, from four sources: the `MSExchange Management` log (one event 1 per cmdlet run through Exchange PowerShell, with its parameters and caller), PowerShell script blocks, Windows PowerShell pipeline events and process command lines. Flags: mailbox export requests and compliance or mailbox searches (`New-MailboxExportRequest`, `New-ComplianceSearch`, `Search-Mailbox -TargetMailbox`) and their removal afterwards; forwarding on a mailbox (`Set-Mailbox -ForwardingSmtpAddress`); inbox rules that forward, redirect, move or delete; transport and journal rules, send connectors and transport agents; mailbox, folder, AD and role permissions (`Add-MailboxPermission`, `New-ManagementRoleAssignment`, `ApplicationImpersonation`, `Mailbox Import Export`); virtual directory and certificate changes (the ProxyShell and ProxyNotShell chains set the OAB virtual directory's `ExternalUrl` to drop a web shell); and audit configuration changes. Enumeration cmdlets (`Get-Mailbox`, `Get-Recipient`) score 1.

**Reading the output.** Highest score first. The `MSExchange Management` log shows who ran each cmdlet (in `detail`), including cmdlets run through a web shell or over remote PowerShell from another host. A `New-MailboxExportRequest` writing a `.pst` to a UNC path or to a web-reachable folder (`\inetpub\`, `\FrontEnd\HttpProxy\`) is data theft, often followed by `Remove-MailboxExportRequest`. Forwarding to an outside address, an `ApplicationImpersonation` or `Mailbox Import Export` assignment, or a transport rule with `BlindCopyTo` is a lead whoever ran it. Exchange's own health and monitoring accounts run many `Get-*` cmdlets; ignore score-1 rows from them.

**If it errors or looks empty.** No rows usually means the `MSExchange Management` log was not collected (it is under `Applications and Services Logs`; KAPE's `EventLogs` target includes it) and Script Block Logging was off. `winlog.payload.event_data.ScriptBlockText` or `kape.executable_info` unknown: replace it with `null` in the `raw` line.

**Next.** [PE-17](../../TA0003-persistence/PE-17-web-shell-files/) for web shells under the Exchange folders, [PE-18](../../TA0003-persistence/PE-18-server-process-spawns-shell-4688/) for `w3wp.exe` (MSExchange application pools) starting shells, [CO-01](../CO-01-archives-and-staged-files/) for `.pst` files staged on disk.
