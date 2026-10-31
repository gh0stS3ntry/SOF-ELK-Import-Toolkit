# PE-06 Scheduled task creation and changes from the command line or PowerShell

| | |
|---|---|
| Tactic | TA0003 Persistence |
| ATT&CK | T1053.005 Scheduled Task |
| Indexes | `evtxlogs-*` |
| Needs | PowerShell Operational 4104 on at least one host (`ScriptBlockText`); Security 4688 / Sysmon 1 add `schtasks.exe` and `at.exe` command lines |
| Roles | all |

**What it finds.** `schtasks /create|/change|/run|/delete`, `at.exe`, the ScheduledTasks cmdlets and the `Schedule.Service` COM object, scored for a remote target (`/s`, `-CimSession`), interpreter actions, user-writable paths, encoded commands, SYSTEM/highest run level and boot/logon/every-minute triggers.

**Reading the output.** Without command-line auditing, 4688 shows only `schtasks.exe` with no arguments; the task itself is then in [PE-07](../PE-07-task-scheduler-per-task/), [PE-08](../PE-08-scheduled-task-created-4698/) and [PE-09](../PE-09-taskcache-registry/).

**If it errors.** `Unknown column` on `ScriptBlockText` means no 4104 events were loaded; delete that line from `cmd`.
