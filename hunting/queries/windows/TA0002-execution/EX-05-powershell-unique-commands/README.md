# EX-05 Unique PowerShell host applications across hosts (long tail)

| | |
|---|---|
| Tactic | TA0002 Execution |
| ATT&CK | T1059.001 PowerShell |
| Indexes | `evtxlogs-*` |
| Needs | `Windows PowerShell` 400/403/600/800, or PowerShell Operational 4103, with `HostApplication=` in the event text (checklist 2.4.12) |
| Roles | all |

**What it finds.** Every distinct PowerShell host command line (`HostApplication=`), how often and on how many hosts it appeared, and each host's first and last time. Rare commands come first.

**Reading the output.** Commands seen once or twice are where encoded payloads, download cradles and one-off admin actions show up. `hosts` lists each host with its time range, so a command that appears on many hosts within minutes points to remote execution or a deployment.

**Tuning.** Very common lines (bare `powershell.exe`, SQLPS agent jobs, Server Manager) can be excluded with `| WHERE command_line NOT LIKE "..."` as in [EX-06](../EX-06-powershell-command-timeline/).
