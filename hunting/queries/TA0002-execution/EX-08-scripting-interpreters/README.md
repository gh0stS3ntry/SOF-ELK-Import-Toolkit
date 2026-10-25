# EX-08 Script interpreter execution across event sources

| | |
|---|---|
| Tactic | TA0002 Execution |
| ATT&CK | T1059.001 PowerShell, T1059.005 Visual Basic, T1059.006 Python, T1059.007 JavaScript, T1218.005 Mshta |
| Indexes | `evtxlogs-*` |
| Needs | PowerShell Operational 4104 on at least one loaded host (the query reads `ScriptBlockText`). Security 4688 and Sysmon 1 are added when present |
| Roles | all |

**What it finds.** Interpreter use (Python, `wscript`/`cscript`, `mshta`, PowerShell, Perl/Ruby/Node/AutoIt/AutoHotkey) and script payload keywords (Python socket/subprocess/ctypes, VBS/JS COM objects) in any event that carries a command line or script text. For 4688 and Sysmon 1 it reads EvtxECmd's `ExecutableInfo` (`kape.executable_info`), which is the new process image followed by its command line, so it also works on hosts with 4688 but no command-line auditing (where it sees only image names). For 4104 it reads `ScriptBlockText`.

**Reading the output.** `score` adds weight for inline or encoded execution, obfuscation, user-writable paths, script arguments, URLs and Office parents. `kape.map_description` names the EvtxECmd map that produced the row.

**Tuning.** Administrative Python or VBS in a client's estate (monitoring agents, logon scripts) will appear with a score of 1 to 2; add `| WHERE score >= 3` to hide them.

**If it errors.** `Unknown column` on `winlog.payload.event_data.ScriptBlockText` means no loaded host has 4104 events; delete that `COALESCE` line from `txt`. Services and scheduled tasks that launch interpreters are covered by [PE-05](../../TA0003-persistence/PE-05-service-install-events/) and [PE-06](../../TA0003-persistence/PE-06-scheduled-task-commands/).
