# Checklist: Linux file server

Samba and NFS servers, and Linux hosts with shared data folders reached over SFTP or rsync. Run the [Linux baseline](linux-baseline-all-hosts.md) first. A file server is where data is taken from, and where ransomware running on a client encrypts the most files over the network. The files change on this server even when the process doing it ran elsewhere, so the file-system rows matter more than the command rows. The `IR ref` column is approximate, because the IR checklist is written for Windows hosts.

## 1. Host profile

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 1.1 | Shares, exports and what they hold | | 1.2.5, 2.3.6 | Ask the client, or read `smb.conf` and `/etc/exports` from the collection; `no_root_squash` exports and guest shares matter for row 3.1. |
| 1.2 | Which evidence exists | [LTRI-01](../queries/linux/00-triage/LTRI-01-linux-data-coverage/) | 1.2.3, 2.4 | The bodyfile is the main source here; Samba logs reach the journal only when configured to. Check the bodyfile was taken before files were restored. |
| 1.3 | Snapshots and backups of the shares | | 1.2.6 | Where they are and whether they survived; decides recovery. See the [backup server](linux-backup-server.md) checklist. |

## 2. Who accessed the server

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 2.1 | Logins and sessions | [LIA-01](../queries/linux/TA0001-initial-access/LIA-01-remote-logins-from-public-addresses/), [LLM-01](../queries/linux/TA0008-lateral-movement/LLM-01-inbound-sessions-with-duration/), [LCA-01](../queries/linux/TA0006-credential-access/LCA-01-brute-force-and-password-spraying/) | 2.4.1 to 2.4.4, 2.4.13 | SSH and SFTP sessions from hosts and accounts that do not normally manage the server. |
| 2.2 | FTP and web transfers | [LEXF-03](../queries/linux/TA0010-exfiltration/LEXF-03-large-transfers-served-by-web-and-ftp/) | 2.4.7 | Clients that pulled the most data through FTP or a web front end. |

## 3. Collection, exfiltration and abuse of the shares

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 3.1 | Setuid files and root-owned files planted through the shares | [LPR-02](../queries/linux/TA0004-privilege-escalation/LPR-02-setuid-setgid-files-and-permission-changes/) | 2.4.19 | Setuid binaries in exported folders (written by a client through a `no_root_squash` export). |
| 3.2 | Mass copies and archives | [LCO-02](../queries/linux/TA0009-collection/LCO-02-file-creation-bursts/), [LCO-01](../queries/linux/TA0009-collection/LCO-01-archives-dumps-and-staging/) | 2.1.4 | Hundreds of files created in one folder within minutes, large archives in shares or temporary folders. |
| 3.3 | Exfiltration tools and destinations | [LEXF-01](../queries/linux/TA0010-exfiltration/LEXF-01-exfiltration-tools-and-commands/), [LC2-02](../queries/linux/TA0011-command-and-control/LC2-02-outbound-destinations-firewall-audit-vpn/) | 2.4.7 | `rclone`, `curl -T`, `scp` run on the server; rare outbound destinations. |
| 3.4 | Malware stored on the shares | [LEX-02](../queries/linux/TA0002-execution/LEX-02-programs-in-temp-hidden-and-user-writable-locations/), [LDE-04](../queries/linux/TA0112-defense-impairment/LDE-04-hidden-masquerading-and-deleted-binaries/) | 2.1.4 | Executables and scripts in share folders, hidden files and folders, files named like system daemons. |

## 4. Ransomware impact

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 4.1 | Encryption bursts, ransom notes and their start time | [LIM-02](../queries/linux/TA0040-impact/LIM-02-ransomware-notes-and-encryption/) | 2.1.10 | The first hour of files with a new extension, the note name, and the folders hit; `file.owner` shows which share account wrote them. |
| 4.2 | Snapshots and data deleted | [LIM-01](../queries/linux/TA0040-impact/LIM-01-destructive-commands/) | 2.4.9 | `zfs destroy`, `lvremove`, `btrfs subvolume delete` and recursive deletes of share folders. |
| 4.3 | Where the encryption came from | [LLM-01](../queries/linux/TA0008-lateral-movement/LLM-01-inbound-sessions-with-duration/) | 2.4.13 | Sessions open at the time of the first encrypted file. With Samba logging, the client address is in the Samba log (see below). |

## Not covered by these queries

- Samba's own logs (`/var/log/samba/log.<client>`) and `full_audit` VFS logs, and NFS client lists (`/var/lib/nfs/rmtab`): they name the client that wrote each file. Read them from the collection.
- NAS appliances (Synology, QNAP, TrueNAS): use their own logs and exports.
