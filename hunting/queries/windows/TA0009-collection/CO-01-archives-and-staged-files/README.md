# CO-01 Archives and large staged files in user-writable and staging folders

| | |
|---|---|
| Tactic | TA0009 Collection |
| ATT&CK | T1074.001 Local Data Staging, T1560.001 Archive via Utility |
| Indexes | `filesystem-*` |
| Needs | MFTECmd `$MFT` output |
| Roles | all; file servers and database servers for large staging |

**What it finds.** Archives (`.zip`, `.rar`, `.7z`, `.tar`, `.gz`, `.cab`, split `.001` volumes, `.pst`) and large data-like files (`.dat`, `.bin`, `.tmp`, `.bak` over 100 MB) in high-risk staging folders (`\Users\Public`, `\ProgramData`, `\PerfLogs`, `\Windows\Temp`, the Recycle Bin, `\Windows\Debug`, `\spool\drivers\color`...) or user-writable folders, kept when the score is 6 or more. Size, generic names (`1.zip`, `data.7z`, `out.rar`), hidden attributes, deletion and `$SI` earlier than `$FN` add weight.

**Reading the output.** The earlier engagement's query, with the directory filter moved to `file.type`. An archive's `$FN` creation is when staging finished; the archiver's execution ([CO-03](../CO-03-archiver-tools-execution/)) and outbound transfer ([EXF-03](../../TA0010-exfiltration/EXF-03-srum-network-usage/)) should follow. Deleted archives are common after exfiltration.
