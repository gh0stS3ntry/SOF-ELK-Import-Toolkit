# ALM-02 East-west administrative connections inside the VPC (SSH, RDP, SMB, WinRM, databases)

| | |
|---|---|
| Tactic | TA0008 Lateral Movement |
| ATT&CK | T1021 Remote Services, T1210 Exploitation of Remote Services |
| Indexes | `aws-vpcflow-*` |
| Needs | VPC Flow Logs (accepted traffic) |
| Applies to | every VPC with flow logs |

**What it finds.** Accepted internal connections on administrative and database ports, one row per source and destination pair, with how many such peers the source reached (`peers_of_source`) and how many sources normally reach that destination (`sources_of_peer`).

**Reading the output.** Bastion hosts, domain controllers and application servers have many peers by design. Rows sorted first are destinations that only one or two machines ever reach on that port: a web server opening SSH or RDP to another instance, or an instance that suddenly talks SMB to many others after [ADI-03](../../TA0007-discovery/ADI-03-vpc-internal-scanning/) flagged it, are what lateral movement looks like in flow logs. Correlate the times with logons on the destination.

**If it errors or looks empty.** `INLINE STATS` needs ES 9.x (older builds spell it `INLINESTATS`).
