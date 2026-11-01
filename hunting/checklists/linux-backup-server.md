# Checklist: Linux backup server

Backup servers and repositories on Linux: Bacula/Bareos, Veeam Linux repositories and proxies, Proxmox Backup Server, UrBackup, Borg, restic, rsnapshot and rsync targets, ZFS or LVM snapshot hosts. Run the [Linux baseline](linux-baseline-all-hosts.md) first. Ransomware operators go for backups before they encrypt, and a backup server holds a copy of everything, so the questions are whether it was reached, whether backups and snapshots were deleted or encrypted, and whether data was taken from it. The `IR ref` column is approximate, because the IR checklist is written for Windows hosts.

## 1. Host profile

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 1.1 | Backup software, version and installed tools | [LTRI-04](../queries/linux/00-triage/LTRI-04-software-installed-and-removed/), [LPE-09](../queries/linux/TA0003-persistence/LPE-09-repositories-and-local-packages/) | 1.2.1, 1.2.3 | Backup products and their versions against known exploited CVEs (Veeam, Bacula, Proxmox); `rclone` or cloud CLIs that the backup design does not need. |
| 1.2 | Backup schedule, retention and which hosts send backups | | 1.2.6 | Ask the client; needed to tell a scheduled deletion from an attacker's. |
| 1.3 | Accounts on the server and what they can reach | [LTRI-03](../queries/linux/00-triage/LTRI-03-accounts-and-their-activity/), [LPR-03](../queries/linux/TA0004-privilege-escalation/LPR-03-privileged-groups-and-sudoers-changes/) | 1.3.2, 2.4.18 | Backup service accounts with interactive logins, `sudo` rules for backup tools, accounts shared with the production domain. |

## 2. Access

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 2.1 | Who logged in, from where | [LIA-01](../queries/linux/TA0001-initial-access/LIA-01-remote-logins-from-public-addresses/), [LLM-01](../queries/linux/TA0008-lateral-movement/LLM-01-inbound-sessions-with-duration/), [LCA-01](../queries/linux/TA0006-credential-access/LCA-01-brute-force-and-password-spraying/) | 2.4.1 to 2.4.4, 2.4.13 | Interactive sessions from hosts that only push backups, logins outside maintenance windows, brute force against the backup account. |
| 2.2 | SSH keys | [LPE-04](../queries/linux/TA0003-persistence/LPE-04-ssh-authorized-keys-and-their-logins/) | 2.4.18 | Keys added to the backup or root account; one key used by many client hosts (a key stolen from any client opens the repository). |
| 2.3 | Credentials and repository keys | [LCA-02](../queries/linux/TA0006-credential-access/LCA-02-credential-files-and-cracking-tools/), [LEXF-01](../queries/linux/TA0010-exfiltration/LEXF-01-exfiltration-tools-and-commands/) | 2.4.22 | Private keys outside `.ssh`, cloud credentials and `.env` files read or copied; `rclone`, s3cmd and cloud CLI configuration files that name outside storage. |

## 3. Backups and snapshots destroyed

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 3.1 | Repositories, snapshots and backup folders deleted | [LIM-01](../queries/linux/TA0040-impact/LIM-01-destructive-commands/) | 2.4.9 | `borg delete`, `rclone delete`/`purge`, `zfs destroy`, `lvremove`, `btrfs subvolume delete`, `rm -rf` of backup folders, backup services stopped or masked. |
| 3.2 | Backup jobs changed or disabled | [LPE-02](../queries/linux/TA0003-persistence/LPE-02-cron-and-at-jobs-configured-and-run/), [LPE-01](../queries/linux/TA0003-persistence/LPE-01-systemd-units-defined-started-and-changed/) | 2.4.25, 2.4.14 | Backup cron jobs or timers removed, edited or pointed elsewhere; new jobs that run deletions. |
| 3.3 | Retention defeated through the clock | [LDE-03](../queries/linux/TA0112-defense-impairment/LDE-03-timestomping-and-clock-changes/) | 2.1.5 | System clock moved forward (which makes retention expire everything), `touch -d` on repository files. |
| 3.4 | Encryption of the repositories | [LIM-02](../queries/linux/TA0040-impact/LIM-02-ransomware-notes-and-encryption/) | 2.1.10 | Bursts of files with a new extension in the repository folders, ransom notes. |
| 3.5 | Security and logging stopped first | [LDE-01](../queries/linux/TA0112-defense-impairment/LDE-01-log-and-history-tampering/), [LDE-02](../queries/linux/TA0112-defense-impairment/LDE-02-security-tools-and-logging-disabled/) | 2.4.21, 2.4.26 | auditd, journald and the backup software's own logging stopped before the deletions. |

## 4. Data taken from the backups

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 4.1 | Restores, mounts and archives outside the schedule | [LCO-01](../queries/linux/TA0009-collection/LCO-01-archives-dumps-and-staging/), [LCO-02](../queries/linux/TA0009-collection/LCO-02-file-creation-bursts/) | 2.1.4 | Archives in temporary folders, bursts of restored files, `borg mount`/`restic mount` folders. |
| 4.2 | Uploads and destinations | [LEXF-01](../queries/linux/TA0010-exfiltration/LEXF-01-exfiltration-tools-and-commands/), [LC2-02](../queries/linux/TA0011-command-and-control/LC2-02-outbound-destinations-firewall-audit-vpn/) | 2.4.7 | `rclone`, `restic` or `curl` to outside storage the backup design does not use; rare destinations. |
| 4.3 | Pivoting from the backup server to the hosts it backs up | [LLM-02](../queries/linux/TA0008-lateral-movement/LLM-02-outbound-remote-access-from-this-host/), [LDI-03](../queries/linux/TA0007-discovery/LDI-03-port-scans-in-firewall-and-audit-records/) | 2.4.13 | SSH from the backup server to clients with its keys, scans of the client networks. |

## Not covered by these queries

- The backup software's own job, audit and catalog logs (Bacula/Bareos catalog, Veeam logs under `/var/log/VeeamBackup`, Proxmox Backup Server task logs, Borg and restic output captured by cron). Read them from the collection to date each deletion and restore.
- Immutable or off-site copies, storage-array snapshots and object-lock settings: check with the client whether a clean copy survived.
