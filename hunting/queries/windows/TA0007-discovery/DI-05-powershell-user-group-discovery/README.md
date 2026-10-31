# DI-05 User, group, domain and trust discovery in PowerShell and command lines

| | |
|---|---|
| Tactic | TA0007 Discovery |
| ATT&CK | T1087.001/.002 Account Discovery, T1069 Permission Groups Discovery, T1482 Domain Trust Discovery, T1033 System Owner/User Discovery |
| Indexes | `evtxlogs-*` |
| Needs | PowerShell Operational 4104 on at least one loaded host; Security 4688 and Sysmon 1 add `net`, `whoami`, `nltest`, `dsquery` and AdFind command lines |
| Roles | all |

**What it finds.** The ActiveDirectory module and PowerView cmdlets, `[adsisearcher]`/DirectorySearcher queries, local user and group cmdlets, `net user|group|localgroup`, `whoami`, `nltest /domain_trusts|/dclist`, `dsquery`, `quser`, `cmdkey /list`, `klist`, and AD recon tools (SharpHound, AdFind, ADRecon, PingCastle). Naming a privileged group or `krbtgt` adds weight.

**Reading the output.** In time order, so a recon session reads top to bottom. Without command-line auditing, 4688 shows only the image names (`whoami.exe`, `net1.exe`), which still date the session.

**If it errors.** `Unknown column` on `ScriptBlockText` means no 4104 events were loaded; delete that line.
