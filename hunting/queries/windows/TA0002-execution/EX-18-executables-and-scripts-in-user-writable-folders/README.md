# EX-18 Executables and scripts in user-writable and world-writable folders

| | |
|---|---|
| Tactic | TA0002 Execution |
| ATT&CK | T1204.002 Malicious File, T1105 Ingress Tool Transfer, T1036.005 Match Legitimate Name or Location, T1059 Command and Scripting Interpreter |
| Indexes | `filesystem-*` |
| Needs | MFTECmd `$MFT` output |
| Roles | all (baseline) |

**What it finds.** Every PE file (`.exe`, `.dll`, `.sys`, `.scr`, `.cpl`, `.ocx`, `.com`, `.pif`, `.msi`, `.jar` and similar) and every script (`.ps1`, `.bat`, `.cmd`, `.vbs`, `.js`, `.hta`, `.wsf`, `.py`, `.sh`, `.pl`, `.php` and similar) that the `$MFT` holds in a folder a standard user can write to: user profiles (`AppData`, `Temp`, `Downloads`, `Desktop`, `Documents` and the rest of `\Users\<name>`), `\Users\Public`, `\ProgramData`, `\Windows\Temp`, the System32 and SysWOW64 subfolders users can write to (`Tasks`, `spool\drivers\color`, `spool\PRINTERS`, `FxsTmp`, `com\dmp`, `MachineKeys`, `\Windows\Tasks`, `\Windows\tracing`), the Recycle Bin, `\PerfLogs`, the drive root and non-standard folders at the drive root (`C:\temp`, `C:\tmp`, `C:\Intel` and the like, which any authenticated user can create). Deleted entries whose path is still known are listed too. The file type comes from the extension: the `$MFT` has no file contents.

**Reading the output.** Highest `score` first. Points for a temp folder, a folder that rarely holds programs (Recycle Bin, Public, System32 writable subfolders, PerfLogs, drive-root folders), a file loose in `%APPDATA%`, `%LOCALAPPDATA%` or `%ProgramData%` with no vendor folder around it, a double extension (`invoice.pdf.exe`), a random-looking name, a script, a name seen on one host only, the hidden attribute, a deleted entry and `$SI` created more than a minute before `$FN` created. Per-user software that installs itself into these folders by design (OneDrive, Teams, Edge, Chrome, Slack, Zoom, VS Code, Defender platform updates, Package Cache, Chocolatey) loses 3 points and sorts to the bottom; it is not removed, because attackers also hide in those folders. `event_time` is the `$FN` creation time, the best estimate of when the file arrived. `kape.mft.hasads` true usually means a `Zone.Identifier` stream: check where it came from with [C2-02](../../TA0011-command-and-control/C2-02-motw-zone-identifier/).

**If it errors or looks empty.** `Unknown column [file.attributes.hidden]`: replace `file.attributes.hidden` with `false`. No rows: no `$MFT` was loaded for the host (check [TRI-01](../../00-triage/TRI-01-data-coverage/)). Entries under `PathUnknown` (orphans whose parent folder is gone) cannot be placed and are left out. On RD01 the query returns about 1,100 rows; about 1,000 of them are vendor software scored below zero.

**Next.** For each lead, [EX-15](../EX-15-execution-evidence-pivot/) shows whether and when it ran; [EX-10](../EX-10-amcache-long-tail/), [EX-11](../EX-11-shimcache-long-tail/) and [EX-13](../EX-13-prefetch-rare-executables/) show execution by rarity; sort `filesystem-*` around `event_time` for what arrived with it.
