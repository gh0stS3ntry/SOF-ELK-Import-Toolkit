# LM-04 Executables and scripts created in admin-share reachable folders

| | |
|---|---|
| Tactic | TA0008 Lateral Movement |
| ATT&CK | T1570 Lateral Tool Transfer, T1021.002 SMB/Windows Admin Shares, T1569.002 Service Execution |
| Indexes | `filesystem-*` |
| Needs | MFTECmd `$MFT` and/or `$J` output |
| Roles | all; servers and domain controllers especially |

**What it finds.** Executables, DLLs, drivers and scripts directly in `\Windows`, `\Windows\Temp`, writable System32 subfolders, the drive root and root-level staging folders (`\PerfLogs`, `\ProgramData`, `\Users\Public`, `\Temp`, `\Intel`), from the `$MFT` and from `$J` creations and renames. Scored for PsExec/PAExec/RemCom/Cobalt Strike-style names, random-looking names that mix letters and digits or are long hex strings (Impacket's `psexec`, many RaaS affiliates), names on one host only, and `$SI` earlier than `$FN`.

**Reading the output.** The `$FN` creation time of a pushed binary is the moment of lateral movement; match it with a type 3 logon in [LM-03](../LM-03-logon-sessions-with-duration/) and a service install in [PE-05](../../TA0003-persistence/PE-05-service-install-events/) on the same host. Windows Update and driver installs also write to these folders; they arrive in large same-second batches with Microsoft names.
