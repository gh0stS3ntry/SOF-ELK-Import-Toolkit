# DI-04 Local user and group membership enumeration (Security 4798/4799)

| | |
|---|---|
| Tactic | TA0007 Discovery |
| ATT&CK | T1087.001 Local Account Discovery, T1069.001 Local Groups |
| Indexes | `evtxlogs-*` |
| Needs | Security 4798 (user's local groups enumerated) / 4799 (local group membership enumerated), Windows 10 / Server 2016+ |
| Roles | all |

**What it finds.** Per user account and 10 minutes: how many accounts or groups were enumerated, and by which processes (`CallerProcessName`). `net.exe`, PowerShell, `whoami`, `wmic`, AdFind, SharpHound or anything in a user-writable folder scores 3; enumerating 5 or more targets adds 2; windows where only Explorer, MMC, svchost and similar callers appear lose 2.

**Reading the output.** Machine accounts are removed. A burst of 4799 for Administrators, Remote Desktop Users and Domain Admins from `net1.exe` right after a logon is hands-on-keyboard recon; pivot to [DI-06](../DI-06-discovery-command-bursts/) for the commands around it.
