# PE-01 Autostart (ASEP) registry values, scored

| | |
|---|---|
| Tactic | TA0003 Persistence |
| ATT&CK | T1547.001 Registry Run Keys, T1547.004 Winlogon Helper, T1546.012 IFEO, T1546.015 COM Hijacking, T1137 Office Application Startup, T1037.001 Logon Script |
| Indexes | `registry-*` |
| Needs | RECmd batch CSV (`event.dataset: registry.batch`). Only keys the batch file dumps can be found: Kroll/`RECmd_Batch_MC` cover most of them; the DFIRBatch used on RD01 has Run keys, Winlogon and Services but no IFEO, KnownDLLs or TaskCache\Tree |
| Roles | all |

**What it finds.** Values in about 25 autostart locations (Run/RunOnce, Policies\Explorer\Run, Winlogon Shell/Userinit, IFEO Debugger, SilentProcessExit, AppInit/AppCert DLLs, BootExecute, LSA packages, Netsh helpers, time providers, print monitors, Active Setup, Command Processor AutoRun, `UserInitMprLogonScript`, RDP startup programs and add-ins, Explorer hooks, per-user COM servers, Office add-ins and "Office Test", SafeBoot services, service ImagePath/ServiceDll, TaskCache). Each row is scored by how unusual the location is, plus user-writable paths, LOLBins, scripts, encoded commands, URLs, UNC paths, DLLs outside system folders and non-default Winlogon values.

**Reading the output.** `registry.last_write` is the key's last write, which for a Run key is the last time any value under it changed. `user.name` is the hive owner for NTUSER.DAT / UsrClass.dat. Score 1 rows are ordinary Run/Service entries; read them with [PE-02](../PE-02-asep-rarity/) instead.

**Next.** Search the file names in [EX-15](../../TA0002-execution/EX-15-execution-evidence-pivot/) and the `$MFT`.
