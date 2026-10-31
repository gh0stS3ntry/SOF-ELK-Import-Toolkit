# CO-03 Archiver tools in Amcache, ShimCache and SRUM, with bytes written

| | |
|---|---|
| Tactic | TA0009 Collection |
| ATT&CK | T1560.001 Archive via Utility |
| Indexes | `amcache-*`, `shimcache-*`, `srum-*` |
| Needs | any of the three; remove the families you did not load from `FROM` |
| Roles | all |

**What it finds.** 7-Zip, WinRAR, `rar.exe`, PeaZip, Bandizip, WinZip, `makecab` and `tar` per normalised path, with the artifacts that saw them, users, SHA-1, and MB read and written according to SRUM. Portable copies in user-writable folders sort first.

**Reading the output.** `7za.exe` or `rar.exe` in `\ProgramData` or `\Users\Public` with hundreds of MB written is the classic pre-exfiltration step; compare `first_seen`/`last_seen` with the archives found by [CO-01](../CO-01-archives-and-staged-files/). Ported from the earlier engagement's query to the template field names (`file.path`, `process.executable`, `srum.*`).
