# Checklist: File server

File shares, DFS namespaces, and Windows backup targets. Run the [baseline](00-baseline-all-windows-hosts.md) first. A file server is where data is taken from and where ransomware does the most damage, often from another host over SMB. Many rows here therefore look at the network side (who connected to which share) and at the file system, not at programs run on the server.

## 1. Host profile

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 1.1 | Shares, what they hold, and who should use them | | 1.2.5, 2.3.6 | Ask the client for the share list and the sensitive shares (HR, finance, engineering). |
| 1.2 | Whether object access and share auditing were on | [TRI-02](../queries/windows/00-triage/TRI-02-event-log-coverage/) | 2.4.6, 2.4.11 | 5140/5145 and 4663 exist only when "Audit File Share", "Detailed File Share" or "File System" auditing was enabled. Without them, rows 2.x rely on the `$MFT`, `$J` and User Access Logging. |
| 1.3 | Backups and snapshots of the shares | | 1.2.6 | Where they are and whether they survived; decides recovery options. |

## 2. Who accessed the shares

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 2.1 | Share access by source, account and share | [LM-05](../queries/windows/TA0008-lateral-movement/LM-05-share-access/) | 2.4.6, 2.3.7 | Accounts and hosts that do not normally use a share; admin shares; access outside office hours. |
| 2.2 | Clients over time (User Access Logging) | [LM-06](../queries/windows/TA0008-lateral-movement/LM-06-sum-ual-client-access/) | 2.3.7 | Client addresses and accounts with their first and last access and access counts, even when the Security log has rolled. |
| 2.3 | Logons to the server | [LM-03](../queries/windows/TA0008-lateral-movement/LM-03-logon-sessions-with-duration/), [LM-01](../queries/windows/TA0008-lateral-movement/LM-01-lateral-movement-methods/) | 2.4.3, 2.4.13 | Network logons (type 3) from unusual hosts, RDP to the file server, explicit-credential logons. |
| 2.4 | Folders browsed by admins logged on locally | [CO-04](../queries/windows/TA0009-collection/CO-04-shellbags-network-removable-and-other-profiles/) | 2.1.5 | Shellbags of admin profiles on the server: which share folders were opened. |

## 3. Collection and exfiltration

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 3.1 | Mass copies and staging folders | [CO-02](../queries/windows/TA0009-collection/CO-02-mass-copy-bursts/), [CO-01](../queries/windows/TA0009-collection/CO-01-archives-and-staged-files/) | 2.1.4 | Hundreds of documents copied into one folder; large archives in `\Users\Public`, `\PerfLogs` or a share root. |
| 3.2 | Archivers and exfiltration tools run on the server | [CO-03](../queries/windows/TA0009-collection/CO-03-archiver-tools-execution/), [EXF-04](../queries/windows/TA0010-exfiltration/EXF-04-exfil-and-cloud-sync-tools/) | 2.1.1 | 7-Zip/WinRAR from odd paths, rclone with a config file, WinSCP. |
| 3.3 | Outbound transfers | [C2-06](../queries/windows/TA0011-command-and-control/C2-06-outbound-connections-by-application-wfp/), [EXF-03](../queries/windows/TA0010-exfiltration/EXF-03-srum-network-usage/) | 2.4.7 | A file server making long-lived connections to public addresses; large bytes sent per app. |

## 4. Ransomware impact

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 4.1 | Encryption bursts and their start time | [IM-02](../queries/windows/TA0040-impact/IM-02-mass-file-renames/) | 2.1.10 | The first five-minute window of mass renames; the extension used. |
| 4.2 | Ransom notes | [IM-03](../queries/windows/TA0040-impact/IM-03-ransom-notes/) | 2.1.10 | Note name, size and first creation time on each volume. |
| 4.3 | Shadow copies, backups and services | [IM-01](../queries/windows/TA0040-impact/IM-01-inhibit-system-recovery/) | 2.4.9 | `vssadmin delete shadows`, backup catalog deleted, backup services stopped. |
| 4.4 | Where the encryption came from | [LM-05](../queries/windows/TA0008-lateral-movement/LM-05-share-access/), [LM-06](../queries/windows/TA0008-lateral-movement/LM-06-sum-ual-client-access/), [LM-04](../queries/windows/TA0008-lateral-movement/LM-04-executables-dropped-in-admin-share-paths/) | 2.4.6 | If no encryptor ran locally (no execution evidence), the files were encrypted over SMB: the client connected at the time of 4.1 is the source host. |
| 4.5 | Deleted tools | [DE-07](../queries/windows/TA0112-defense-impairment/DE-07-deleted-executables-usn/) | 2.1.5 | The encryptor or staging tools deleted after the run. |

## Not covered by these queries

- NAS appliances and non-Windows file servers: their own audit logs.
- DFS replication and FSRM logs; file-screen events if FSRM was configured.
- Volume Shadow Copies that survived: mount them from the image to recover files and older `$MFT`/`$J` data.
