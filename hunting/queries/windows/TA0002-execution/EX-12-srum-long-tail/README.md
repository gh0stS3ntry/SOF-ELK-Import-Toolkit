# EX-12 SRUM applications by rarity, with resource use

| | |
|---|---|
| Tactic | TA0002 Execution |
| ATT&CK | T1204.002 Malicious File |
| Indexes | `srum-*` |
| Needs | SrumECmd `AppResourceUseInfo` |
| Roles | all (SRUM exists on Windows 8+ clients and on servers with the Diagnostic Policy Service running) |

**What it finds.** Least frequency of occurrence over every executable SRUM recorded resource use for, with the user accounts, total foreground/background bytes read and written, and the first and last SRUM record times.

**Reading the output.** SRUM writes records roughly hourly, so `first_seen` and `last_seen` bound when the program was running to within an hour; they are not start times. Large `bg_bytes_written` for a rare, user-path executable can mean a tool staging data (archivers, encryptors). Service and package names (no path) stay in `srum.exe_info` and are not in this query.

**Next.** [EXF-03](../../TA0010-exfiltration/EXF-03-srum-network-usage/) for the same programs' network use.
