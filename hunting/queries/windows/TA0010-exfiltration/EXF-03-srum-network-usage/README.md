# EXF-03 Network bytes sent and received per application and user (SRUM)

| | |
|---|---|
| Tactic | TA0010 Exfiltration |
| ATT&CK | T1041 Exfiltration Over C2 Channel, T1567 Exfiltration Over Web Service, T1048 Exfiltration Over Alternative Protocol |
| Indexes | `srum-*` |
| Needs | SrumECmd `NetworkUsages` output (`event.dataset: srum.network_usages`) |
| Roles | all with SRUM (clients by default; servers when the Diagnostic Policy Service runs) |

**What it finds.** Per host and program: MB sent and received over the roughly 30-60 days SRUM keeps, upload/download ratio, users, first and last record, and on how many hosts the program appears. Upload-heavy programs (100 MB+ and sending at least twice what they receive), transfer, sync, remote-access and archiver tools, programs in user-writable folders and over 1 GB sent score highest.

**Reading the output.** Browsers and Teams send a lot legitimately; `rclone.exe` in `\ProgramData` with 40 GB sent does not. Narrow to the hours involved with `FROM srum-* | WHERE event.dataset == "srum.network_usages" AND process.executable LIKE "*rclone*"` and read `@timestamp` per record (hourly). Services appear without a path in `srum.exe_info`.
