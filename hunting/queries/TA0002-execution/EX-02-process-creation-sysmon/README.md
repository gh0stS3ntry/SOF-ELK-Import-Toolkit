# EX-02 Suspicious process creation (Sysmon 1)

| | |
|---|---|
| Tactic | TA0002 Execution |
| ATT&CK | T1059, T1218, T1204.002, T1036.003 Rename System Utilities |
| Indexes | `evtxlogs-*` |
| Needs | Sysmon event 1 (`Microsoft-Windows-Sysmon/Operational`) |
| Roles | all |

**What it finds.** The [EX-01](../EX-01-process-creation-4688/) scoring applied to Sysmon process creation, which always carries the full command line, the parent command line, hashes and the PE `OriginalFileName`. It adds one signal 4688 cannot give: a renamed binary (`OriginalFileName` is a different `.exe`/`.dll` than the file on disk, for example `rundll32.exe` running as `update.exe`).

**Reading the output.** `reasons` explains the score. Chain processes with `ProcessGuid` / `ParentProcessGuid`, which are unique per process across reboots, unlike PIDs. `Hashes` holds whatever the Sysmon config asked for (`SHA256=...,MD5=...`); pivot on them in [EX-04](../EX-04-rare-binaries-sysmon/) and in Amcache with [EX-15](../EX-15-execution-evidence-pivot/).

**If it errors.** `Unknown column` on `winlog.payload.event_data.Image` means no loaded host has Sysmon 1 events; [TRI-02](../../00-triage/TRI-02-event-log-coverage/) confirms it.
