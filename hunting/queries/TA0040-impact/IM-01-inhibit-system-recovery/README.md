# IM-01 Shadow copy, backup and recovery tampering

| | |
|---|---|
| Tactic | TA0040 Impact |
| ATT&CK | T1490 Inhibit System Recovery, T1485 Data Destruction, T1489 Service Stop |
| Indexes | `evtxlogs-*` |
| Needs | Security 4688, Sysmon 1 or PowerShell 4104 for commands; Application 524/8193/8194 and `Microsoft-Windows-Backup` when loaded |
| Roles | all; file servers, database servers and backup servers first |

**What it finds.** The commands ransomware runs just before encryption: `vssadmin delete shadows` / `resize shadowstorage`, WMI `Win32_ShadowCopy` deletion, `wbadmin delete catalog`, `bcdedit` recovery off, `reagentc /disable`, `diskshadow`, stopping VSS/backup/SQL/Exchange services, killing database and backup processes, `cipher /w`, SDelete and `fsutil usn deletejournal`; plus the event-log side effects (System Catalog deleted, backup catalog deleted, VSS errors). `f_cmd` is true for command lines, false for the side-effect events.

**Reading the output.** The first hit marks the start of the impact phase; the same user and parent session usually ran the encryptor a few minutes later. Without process-creation logging (as on RD01) only 4104 script blocks and the side-effect events show up, so also look at the `$J` for renames ([IM-02](../IM-02-mass-file-renames/)).
