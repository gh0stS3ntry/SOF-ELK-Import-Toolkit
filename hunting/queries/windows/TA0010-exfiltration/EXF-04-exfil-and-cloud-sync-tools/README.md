# EXF-04 Exfiltration and cloud-transfer tools in execution artifacts

| | |
|---|---|
| Tactic | TA0010 Exfiltration |
| ATT&CK | T1567.002 Exfiltration to Cloud Storage, T1048 Exfiltration Over Alternative Protocol, T1537 Transfer Data to Cloud Account |
| Indexes | `amcache-*`, `shimcache-*`, `srum-*` |
| Needs | any of the three; remove the families you did not load from `FROM` |
| Roles | all; file servers and database servers especially |

**What it finds.** rclone, MEGA clients, SFTP/FTP clients (WinSCP, PSCP, FileZilla), cloud storage command lines (restic, AzCopy, gsutil, AWS CLI, S3 Browser), non-system copies of curl and wget, sync clients, and named exfiltration tools (ExMatter, StealBit), with paths, users, SHA-1 and first and last time across the three artifacts.

**Reading the output.** rclone renamed to look harmless still keeps its PE metadata in Amcache: search `file.pe.product` for `rclone` if nothing shows here. Its config file (`rclone.conf`) names the remote; look for it in the `$MFT`. Bytes moved are in [EXF-03](../EXF-03-srum-network-usage/).
