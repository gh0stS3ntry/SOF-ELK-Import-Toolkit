# PE-19 Web, database or mail server process starting shells and tools (Sysmon 1)

| | |
|---|---|
| Tactic | TA0003 Persistence |
| ATT&CK | T1505.003 Web Shell, T1190 Exploit Public-Facing Application, T1059.003 Windows Command Shell |
| Indexes | `evtxlogs-*` |
| Needs | Sysmon event 1 |
| Roles | web server, database server, Exchange, any application server |

**What it finds.** The same as [PE-18](../PE-18-server-process-spawns-shell-4688/) from Sysmon, with the full command line, the parent's command line (which for `w3wp.exe` names the application pool), the user, integrity level, hashes and process GUIDs.

**Reading the output.** Follow `ProcessGuid` to the child's own children with `| WHERE winlog.payload.event_data.ParentProcessGuid == "<guid>"` in a copy of [EX-02](../../TA0002-execution/EX-02-process-creation-sysmon/).

**If it errors.** `Unknown column` on a Sysmon field means no loaded host has Sysmon 1 events.
