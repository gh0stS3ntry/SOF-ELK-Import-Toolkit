# LM-01 Lateral movement via RDP, SMB, PsExec-style services, WinRM and WMI

| | |
|---|---|
| Tactic | TA0008 Lateral Movement |
| ATT&CK | T1021.001 RDP, T1021.002 SMB/Admin Shares, T1021.006 WinRM, T1047 WMI, T1569.002 Service Execution, T1550 Use Alternate Authentication Material |
| Indexes | `evtxlogs-*` |
| Needs | Security 4624/4648/4778/4779/5140/5145; TerminalServices RemoteConnectionManager 1149, LocalSessionManager 21/22/25, RdpCoreTS 131, RDPClient 1024/1102; WinRM 6/91/169; Windows PowerShell 400; WMI-Activity 5858/5860/5861; System 7045 or Security 4697 |
| Roles | all |

**What it finds.** Every remote access method in one list, each row with a `method`, a `direction` (inbound to the host that logged it, or outbound from it), the account, source IP, target server, share and logon type: RDP sessions in and out, type 3 and type 10 logons from remote addresses (NTLM network logons flagged), explicit-credential logons to other servers (4648, the outbound side of `runas /netonly`, PsExec and `net use`), admin share access, named pipes used by PsExec/remote SCM/AT/registry, PsExec-style service installs, WinRM and PowerShell remoting, and remote WMI clients. Machine-account and anonymous network logons are scored down.

**Reading the output.** This is the earlier engagement's query, kept as it was apart from the 4697 service source. Sort by `@timestamp` instead of `score` to follow one session across hosts: an outbound row on host A (4648 or RDPClient 1024 naming B) should meet an inbound row on host B a second later. Session durations are in [LM-03](../LM-03-logon-sessions-with-duration/), share and pipe detail in [LM-05](../LM-05-share-access/).

**If it errors.** `Unknown column` on one of the optional fields (`ClientIP`, `EventXML.ServerName`, `EventXML.Param1`, `Operation_ClientFailure.*`, `ServiceFileName`) means no loaded host has that event type; replace the field with `null` in its `COALESCE`.
