# LM-01 Lateral movement via RDP, SMB, PsExec-style services, WinRM and WMI

| | |
|---|---|
| Tactic | TA0008 Lateral Movement |
| ATT&CK | T1021.001 RDP, T1021.002 SMB/Admin Shares, T1021.006 WinRM, T1047 WMI, T1569.002 Service Execution, T1550 Use Alternate Authentication Material |
| Indexes | `evtxlogs-*` |
| Needs | Security 4624/4648/4778/4779/5140/5145; TerminalServices RemoteConnectionManager 1149, LocalSessionManager 21/22/25/41, RdpCoreTS 98/131, RDPClient 1024/1102; SmbClient/Security 31001; WinRM 6/8/15/16/33/91/142/161/169; Windows PowerShell 400/403/800; PowerShell/Operational 8193/8194/8197/40961/40962/53504; WMI-Activity 5857/5858/5860/5861; System 7045 (and 7034/7035/7036) or Security 4697 |
| Roles | all |

**What it finds.** Every remote access method in one list, each row with a `method`, a `direction` (inbound to the host that logged it, or outbound from it), the account, source IP, target server, share and logon type: RDP sessions in and out (including reconnects and blank-user 1149s), type 3 and type 10 logons from remote addresses (NTLM network logons flagged), explicit-credential logons to other servers (4648, the outbound side of `runas /netonly`, PsExec and `net use`), admin share access, named pipes used by PsExec/remote SCM/AT/registry, PsExec-style service installs, failed outbound share logons (SmbClient 31001), WinRM and PowerShell remoting on both ends, remote WMI clients and WMI provider DLLs loaded from outside System32. Machine-account and anonymous network logons are scored down.

**Reading the output.** This is the earlier engagement's query, kept as it was apart from the 4697 service source. Sort by `@timestamp` instead of `score` to follow one session across hosts: an outbound row on host A (4648 or RDPClient 1024 naming B) should meet an inbound row on host B a second later. Session durations are in [LM-03](../LM-03-logon-sessions-with-duration/), share and pipe detail in [LM-05](../LM-05-share-access/).

**Inbound and outbound.** Every event type the query selects is kept when it appears on its own, in both directions (score 3 or more). Before 2026-11-20 inbound-only RDP (1149, LocalSessionManager 21/22/25, RdpCoreTS 131), reconnects (4778/4779) and inbound WinRM (91/169, PowerShell 400) scored 1 or 2 and were dropped by `WHERE score >= 3`. Events that carry no address and are logged for local use too are kept only on hosts that also show the matching remote activity, through `INLINE STATS` per host:

| Events | Kept when the same host also has |
|---|---|
| LocalSessionManager 41, RdpCoreTS 98 | an inbound RDP event (1149, remote 21/22/25, 131, 4778/4779, 4624 type 10) |
| PowerShell/Operational 53504 | an inbound WinRM session (91/169) or a wsmprovhost PowerShell 400/403/800 |
| WinRM 8/15/16/33, PowerShell/Operational 8193/8194/8197/40961/40962 | an outbound WinRM session (6 to another host) or a WinRM authentication error (161) |

WMI-Activity 5857 is logged for every provider load and is kept only when the provider DLL is outside `\Windows\System32` and `\SysWOW64` (`provider_path`). System 7034/7035/7036 are kept only for PsExec-style service names, like 7045. A 1149 with a blank user name scores 3 more: the RDP logon screen was reached without a user, the classic sign of a Sticky Keys or Utilman backdoor.

**If it errors.** `Unknown column` on one of the optional fields (`ClientIP`, `ClientAddress`, `ClientName`, `AccountName`, `UserName`, `ServerName`, `param1`, `EventXML.ServerName`, `EventXML.Param1`, `Operation_ClientFailure.*`, `Operation_StartedOperational.ProviderPath`, `ServiceFileName`) means no loaded host has that event type; replace the field with `null` in its `COALESCE`.
