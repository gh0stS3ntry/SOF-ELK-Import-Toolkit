# LM-08 Remote execution traces in the $MFT: new profiles, copied files, .mof files, WMI repository

| | |
|---|---|
| Tactic | TA0008 Lateral Movement |
| ATT&CK | T1570 Lateral Tool Transfer, T1021.002 SMB/Admin Shares, T1021.006 WinRM, T1047 WMI, T1546.003 WMI Event Subscription |
| Indexes | `filesystem-*` |
| Needs | MFTECmd `$MFT` output |
| Roles | all (baseline); servers and domain controllers especially |
| Source | SANS DFIR "Hunt Evil" poster (FOR508), destination-side file system artifacts |

**What it finds.** Four file-system traces the poster lists on the destination host of lateral movement, from the `$MFT`:

| `kind` | Poster technique | Score |
|---|---|---|
| user profile folder created | PsExec without `-e`, `Enter-PSSession`, first RDP or interactive logon of an account: Windows builds `C:\Users\<name>` | 2, +1 when the profile name is on one host only |
| executable or script copied in (modified before created) | Files pushed over SMB / admin shares: a copy keeps the source's `$SI` modified time but gets a new `$SI` created time, so modified is earlier than created. The created time is the time of the copy | 3, +1 for a script, +1 for a name on one host only |
| .mof file outside the WMI folder | `mofcomp` of an attacker's `.mof` to register WMI classes or event consumers | 4 |
| .mof file in wbem\AutoRecover, WMI repository file | MOFs compiled with `#pragma autorecover` are copied here; `OBJECTS.DATA`, `INDEX.BTR` and `MAPPING*.MAP` change when the repository changes | 1 (timeline context) |

PsExec / PAExec / RemCom / CSExec / winexe service binary names add 3. Copied files are only looked for in folders remote tools drop into: the drive root, `\Windows` itself (the `ADMIN$` root), `\Windows\Temp`, root-level `\PerfLogs`, `\Temp`, `\Tmp`, `\Intel`, `\Users\Public`, the top of `\ProgramData`, and each user's `Temp`, `Downloads`, `Desktop` and `Documents`. System32 and the program folders are left out, because every file Windows Update or an installer writes is "copied" by this test; [LM-04](../LM-04-executables-dropped-in-admin-share-paths/) covers the System32 subfolders that users can write to.

**Reading the output.** `event_time` is the `$FN` created time (falls back to `$SI` created). Line a new profile folder up with the type 3 or type 10 logon of that account in [LM-03](../LM-03-logon-sessions-with-duration/) and with `psexesvc` or `wsmprovhost` in [LM-07](../LM-07-lateral-movement-tool-execution-evidence/). For a copied file, `file.stdinfo.mtime` is the modification time on the attacker's system, often a useful pivot to other hosts with the same file. Archives extracted by a user also give "modified before created"; a single file in `\Windows` or `\Windows\Temp` is the classic admin-share push. A `.mof` file outside `wbem` should be read together with [PE-15](../../TA0003-persistence/PE-15-wmi-event-subscriptions/) and WMI-Activity 5860/5861 in [LM-01](../LM-01-lateral-movement-methods/). The WMI repository rows only give the last write time of the repository files; compare it to the incident window.

**If it errors or looks empty.** No rows: no `$MFT` was loaded for the host (check [TRI-01](../../00-triage/TRI-01-data-coverage/)). Profiles that were deleted show `kape.mft.inuse = false`.
