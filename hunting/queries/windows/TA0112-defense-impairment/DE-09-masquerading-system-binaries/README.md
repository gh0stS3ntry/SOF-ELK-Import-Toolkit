# DE-09 Masquerading: Windows binary names in the wrong folder, and look-alike names

| | |
|---|---|
| Tactic | TA0112 Defense Impairment (Defense Evasion in older ATT&CK versions) |
| ATT&CK | T1036.005 Match Legitimate Name or Location, T1036.003 Rename System Utilities, T1036.004 Masquerade Task or Service |
| Indexes | `amcache-*`, `shimcache-*`, `filesystem-*` ($MFT) |
| Needs | any of the three; remove the families you did not load from `FROM` |
| Roles | all |

**What it finds.** About 40 Windows binary names (`svchost.exe`, `lsass.exe`, `rundll32.exe`, `dllhost.exe`, `conhost.exe`, `explorer.exe`, `powershell.exe`...) recorded outside `\Windows\System32`, `\SysWOW64`, the component store and the update folders, and typosquatted names (`scvhost.exe`, `lsas.exe`, `rundl32.exe`, `expl0rer.exe`...) anywhere. User-writable folders and one-host-only entries score higher.

**Expected folders.** Since 2026-11-20 each name is checked against its own folder, following the SANS Hunt Evil "Know Normal" poster, and `expected_dir` says where it belongs:

| Name | Expected folder |
|---|---|
| `smss.exe`, `csrss.exe`, `wininit.exe`, `winlogon.exe`, `services.exe`, `lsass.exe`, `lsaiso.exe`, `lsm.exe` | `\Windows\System32` only; there is no 32-bit copy, so a copy in `SysWOW64` is flagged |
| `explorer.exe` | `\Windows` (and its 32-bit copy in `\Windows\SysWOW64`); a copy in `System32` is flagged |
| `powershell.exe` | `\Windows\System32` or `SysWOW64` `\WindowsPowerShell\v1.0` |
| `wmiprvse.exe` | `\Windows\System32` or `SysWOW64` `\wbem` |
| `notepad.exe` | `\Windows`, `System32`, `SysWOW64`, or the Windows 11 Store app folder and its per-user alias |
| every other name | `\Windows\System32` or `\Windows\SysWOW64` |

The component store, servicing, update and upgrade folders (`WinSxS`, `servicing`, `SoftwareDistribution`, `SystemApps`, `UUS`, `$Windows.~BT`, `Windows.old`) are accepted for every name. Earlier versions accepted any of these names directly in `\Windows`, so a `C:\Windows\svchost.exe` or `C:\Windows\lsass.exe` was missed; they are flagged now. Paths written as `%SystemRoot%`, `%windir%` or with a `\\?\` prefix are normalised first.

**Reading the output.** Amcache gives the SHA-1 and PE product name; a `svchost.exe` in `\ProgramData` with no Microsoft product name is almost certainly malware. Copies under `\Windows\Temp\<guid>.tmp` and `$Windows.~BT` are from updates and are left out. `$MFT` adds every copy present on disk, including files that never ran and deleted entries still in the MFT; `artifacts` shows `filesystem` for those, and `first_seen`/`last_seen` are the $SI created/modified times. `$J` rows have no parent path and are left out. Prefetch is not read, because it records only the executable name (use the prefetch `directories` list in [EX-13](../../TA0002-execution/EX-13-prefetch-rare-executables/)).
