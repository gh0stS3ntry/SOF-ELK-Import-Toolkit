# PR-01 Accounts given sensitive privileges at logon (Security 4672), by rarity

| | |
|---|---|
| Tactic | TA0004 Privilege Escalation |
| ATT&CK | T1078 Valid Accounts, T1134 Access Token Manipulation |
| Indexes | `evtxlogs-*` |
| Needs | Security 4672 (policy "Audit Special Logon", on by default) |
| Roles | all; domain controllers and servers especially |

**What it finds.** Every account that logged on with administrator-equivalent privileges, excluding SYSTEM, LOCAL/NETWORK SERVICE, machine accounts and the DWM/UMFD font-driver accounts. One row per account with how many such logons, on how many hosts, the time range, and which sensitive privileges it held (`SeDebug`, `SeTcb`, `SeBackup`/`SeRestore`, `SeLoadDriver`, `SeImpersonate`/`SeAssignPrimaryToken`, `SeEnableDelegation`).

**Reading the output.** A rarely seen admin account (`logons` low, one host) at the top is either a break-glass account or one the attacker created or took over. Compare `first_seen` with [PE-16](../../TA0003-persistence/PE-16-account-and-group-changes/) group changes, and pivot to its logon sessions with [LM-03](../../TA0008-lateral-movement/LM-03-logon-sessions-with-duration/).
