# DE-09 Masquerading: Windows binary names in the wrong folder, and look-alike names

| | |
|---|---|
| Tactic | TA0112 Defense Impairment (Defense Evasion in older ATT&CK versions) |
| ATT&CK | T1036.005 Match Legitimate Name or Location, T1036.003 Rename System Utilities, T1036.004 Masquerade Task or Service |
| Indexes | `amcache-*`, `shimcache-*`, `prefetch-*` |
| Needs | any of the three; remove the families you did not load from `FROM` |
| Roles | all |

**What it finds.** About 40 Windows binary names (`svchost.exe`, `lsass.exe`, `rundll32.exe`, `dllhost.exe`, `conhost.exe`, `explorer.exe`, `powershell.exe`...) recorded outside `\Windows\System32`, `\SysWOW64`, the component store and the update folders, and typosquatted names (`scvhost.exe`, `lsas.exe`, `rundl32.exe`, `expl0rer.exe`...) anywhere. User-writable folders and one-host-only entries score higher.

**Reading the output.** Amcache gives the SHA-1 and PE product name; a `svchost.exe` in `\ProgramData` with no Microsoft product name is almost certainly malware. Copies under `\Windows\Temp\<guid>.tmp` and `$Windows.~BT` are from updates and are left out. Prefetch rows without a full executable path are skipped; for those, use the prefetch `directories` list in [EX-13](../../TA0002-execution/EX-13-prefetch-rare-executables/).
