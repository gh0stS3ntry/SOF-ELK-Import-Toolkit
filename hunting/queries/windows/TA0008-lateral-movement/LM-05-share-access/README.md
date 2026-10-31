# LM-05 Network share access by source, account and share, with named pipes

| | |
|---|---|
| Tactic | TA0008 Lateral Movement |
| ATT&CK | T1021.002 SMB/Windows Admin Shares, T1135 Network Share Discovery, T1039 Data from Network Shared Drive |
| Indexes | `evtxlogs-*` |
| Needs | Security 5140 ("Audit File Share"); 5145 ("Audit Detailed File Share", very noisy, rarely on) adds file and pipe names |
| Roles | file server, domain controller, all servers |

**What it finds.** Per host, source IP, account and hour: the shares used, whether an admin share (`ADMIN$`, `C$`) was among them, named pipes opened over `IPC$` (service control, task scheduler, registry, SAM/LSA, DRSUAPI, and Cobalt Strike's default `msagent_`, `postex_`, `status_` and `mojo.` pipes), and how many distinct files were touched on other shares.

**Reading the output.** `C$`/`ADMIN$` plus `svcctl` from a workstation IP is PsExec or `sc \\host create`; `drsuapi` from a non-DC is DCSync; hundreds of files touched on a file server by one account in an hour is collection or a ransomware encryptor running over SMB.

**If it errors.** `Unknown column` on `RelativeTargetName` means no 5145 events were loaded (RD01 has none); replace it with `""`.
