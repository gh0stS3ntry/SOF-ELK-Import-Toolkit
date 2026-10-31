# EX-16 Program execution recorded in UserAssist and BAM/DAM

| | |
|---|---|
| Tactic | TA0002 Execution |
| ATT&CK | T1204.002 Malicious File, T1059 Command and Scripting Interpreter |
| Indexes | `registry-*` |
| Needs | RECmd `UserAssist` (NTUSER.DAT) and/or `BamDam` (SYSTEM) plugin output |
| Roles | all; UserAssist matters most on workstations and RDP/jump hosts |

**What it finds.** Per-user program execution: UserAssist records GUI launches with a run count, focus count and last run; BAM/DAM records the last execution time of each program per user SID (Windows 10 1709+). Each row is scored for user-writable paths, tool names, shells/LOLBins/remote tools, and programs seen on one host only.

**Reading the output.** Both are proof of execution with a time. `account` is the hive owner for UserAssist and the SID from the key for BAM. UserAssist paths may start with a known-folder GUID (`{1AC14E77-...}` is System32, `{6D809377-...}` Program Files); that is normal.

**If it errors.** `Unknown column` on `registry.plugin.program_name` or `registry.plugin.program` means one of the two plugins was not loaded on any host; drop it from the `COALESCE`.
