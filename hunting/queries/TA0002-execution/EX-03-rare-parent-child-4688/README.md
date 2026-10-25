# EX-03 Rare parent and child process pairs (Security 4688)

| | |
|---|---|
| Tactic | TA0002 Execution |
| ATT&CK | T1059, T1204 |
| Indexes | `evtxlogs-*` |
| Needs | Security 4688 with `ParentProcessName` (Windows 10 / Server 2016 and later) |
| Roles | all; most useful with several hosts of the same role |

**What it finds.** Long-tail (least frequency of occurrence) analysis of who started what: one row per parent and child image, with how many hosts and events show the pair. Drive letters, `\Device\HarddiskVolumeN` and user-profile names are normalised so the same binary counts once across hosts and users.

**Reading the output.** Start at the top: pairs seen on one host a handful of times. Anything under `\users\*\appdata`, `\programdata` or `\windows\temp`, or a service host (`services.exe`, `w3wp.exe`, `sqlservr.exe`, `wmiprvse.exe`) starting a shell, deserves a look. `sample_cmds` shows up to five command lines (or image paths when command-line auditing is off).

**Tuning.** On a single host everything has `host_count = 1`; sort by `events ASC` instead. Add `| WHERE host_count <= 2` for large estates.
