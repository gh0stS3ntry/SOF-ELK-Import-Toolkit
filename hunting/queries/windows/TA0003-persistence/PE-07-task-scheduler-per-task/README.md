# PE-07 Task Scheduler Operational log summarised per host and task

| | |
|---|---|
| Tactic | TA0003 Persistence |
| ATT&CK | T1053.005 Scheduled Task |
| Indexes | `evtxlogs-*` |
| Needs | `Microsoft-Windows-TaskScheduler/Operational` (enabled by default on Windows 10+ and Server 2016+) |
| Roles | all |

**What it finds.** One row per host and task: when it was registered (106), updated (140), deleted (141) or disabled (142), the first and last time it appears, the programs it launched (129/200), who changed it, and whether any launched program is an interpreter or sits in a user-writable folder.

**Reading the output.** `f_not_ms = true` and `suspicious_action = 1` first. A task registered and deleted within minutes is a common way to run a payload once as SYSTEM (`schtasks /create ... /ru system`, run, delete). Task names starting with `\Microsoft\` can still be malicious (attackers use names like `\Microsoft\Windows\UpdateOrchestrator\...`); compare `launched_programs` with what that built-in task should run.
