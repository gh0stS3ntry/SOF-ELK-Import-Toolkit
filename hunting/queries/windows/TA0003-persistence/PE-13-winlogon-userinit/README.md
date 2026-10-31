# PE-13 Extra entries in Winlogon Userinit

| | |
|---|---|
| Tactic | TA0003 Persistence |
| ATT&CK | T1547.004 Winlogon Helper DLL |
| Indexes | `registry-*` |
| Needs | RECmd batch CSV with `Microsoft\Windows NT\CurrentVersion\Winlogon` (RD01's DFIRBatch has it) |
| Roles | all |

**What it finds.** Splits the `Userinit` value on commas and returns every entry other than `userinit.exe` itself. Anything here runs at every interactive logon. Each entry is scored for user-writable paths, interpreters, encoded commands, URLs and UNC paths, a `Userinit` value in a user hive (only valid in HKLM), names without a path, look-alike names (`userinit32.exe`), extra files from System32 and the WOW6432Node copy of the key.

**Reading the output.** Every row is suspicious (score starts at 4). [PE-01](../PE-01-asep-registry-scoring/) covers the other Winlogon values (`Shell`, `Taskman`, `AppSetup`).
