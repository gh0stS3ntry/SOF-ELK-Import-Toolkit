# PE-14 KnownDLLs tampering

| | |
|---|---|
| Tactic | TA0003 Persistence |
| ATT&CK | T1574.001 DLL Search Order Hijacking |
| Indexes | `registry-*` |
| Needs | RECmd batch CSV that dumps `SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` and the `ExcludeFromKnownDlls` value (not in RD01's DFIRBatch) |
| Roles | all |

**What it finds.** `DllDirectory` pointing away from System32/SysWOW64, a populated `ExcludeFromKnownDlls` (which lets a planted copy of a system DLL load from the application folder), KnownDLLs values with paths, values that are not DLLs, and values whose data does not match the name.

**Reading the output.** `f_name_mismatch` alone (score 1) is common for legitimate entries such as `_wow64cpu`; anything with score 4 or more needs an explanation.
