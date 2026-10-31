# CA-01 OS credential dumping signs in the event logs

| | |
|---|---|
| Tactic | TA0006 Credential Access |
| ATT&CK | T1003.001 LSASS Memory, T1003.002 SAM, T1003.003 NTDS, T1003.006 DCSync, T1547.005 Security Support Provider, T1068 (BYOVD) |
| Indexes | `evtxlogs-*` |
| Needs | Security, System, Application, Defender Operational and PowerShell Operational 4104 on at least one loaded host (the fields read come from those). Security 4656/4663 need SACLs on `lsass.exe`; 4662 needs Directory Service Access auditing on a DC; Sysmon 1/10 are added when present |
| Roles | all; domain controllers for DCSync and NTDS |

**What it finds.** Defender detections of credential tools, ASR blocks involving LSASS, handles to `lsass.exe` from unusual processes, malicious or non-default LSA packages (4614/4622), dump or vulnerable drivers installed as services (4697/7045), code integrity violations and crashes involving `lsass.exe`, dump commands in 4688/Sysmon command lines and 4104 script blocks (`comsvcs.dll MiniDump`, `procdump lsass`, `ntdsutil ifm`, `reg save hklm\sam`, shadow-copy paths, Mimikatz modules), Sysmon 10 access to lsass and DCSync replication requests from user accounts (4662).

**Reading the output.** Score 5 rows are near-certain; confirm the dump file in [CA-02](../CA-02-dump-files-mft/) and the tool's execution in [CA-04](../CA-04-dump-tools-execution-evidence/). Compared with the earlier engagement's version, the `message` field is no longer read (the importer sets it to the KAPE map name only), and the Defender, LSA-package, object-access and service fields are read directly.

**If it errors.** `Unknown column` on one of the `txt` fields means no loaded host has events that carry it; delete that line.
