# DE-01 Timestomping: `$SI` earlier than `$FN`, zeroed sub-seconds

| | |
|---|---|
| Tactic | TA0112 Defense Impairment (Defense Evasion in older ATT&CK versions) |
| ATT&CK | T1070.006 Timestomp |
| Indexes | `filesystem-*` |
| Needs | MFTECmd `$MFT` output |
| Roles | all |

**What it finds.** Files whose `$STANDARD_INFORMATION` creation time is earlier than the `$FILE_NAME` creation time, or with two or more `$SI` timestamps ending in `.0000000`, the two classic traces of tools that set timestamps through the Windows API. Executables and scripts, staging folders, `$SI` created/modified later than the MFT-change time and a whole-second `$SI` next to a fractional `$FN` add to the score; rows score 5 or more. Component-store and installer folders are left out.

**Reading the output.** The earlier engagement's query, with the directory filter moved to `file.type`. Installers and archive extractors legitimately copy old timestamps (`$SI` earlier than `$FN` alone is common for extracted files), so the zeroed sub-seconds and the executable flag carry the most weight. `file.filename.created` is the real arrival time of a timestomped file; use it as the pivot time.
