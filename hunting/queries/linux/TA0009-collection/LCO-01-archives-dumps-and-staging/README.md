# LCO-01 Archives and database dumps in staging folders, and the archive and dump commands that made them

| | |
|---|---|
| Tactic | TA0009 Collection |
| ATT&CK | T1560.001 Archive via Utility, T1074.001 Local Data Staging, T1005 Data from Local System |
| Indexes | `bodyfile-*`, `logstash-*`, `auditd-*`, `linuxconfig-*` |
| Needs | bodyfile-* (files); logstash-*, auditd-*, linuxconfig-* for commands |
| Applies to | every Linux host; file and database servers first |

**What it finds.** Data staged for theft: archives and database dumps (`.tar`, `.tgz`, `.zip`, `.7z`, `.rar`, `.sql`, `.dump`, `.bak`, ...) in temporary folders, web roots, home folders, `/opt`, `/mnt` and `/media`, grouped by folder with their count, total and largest size, newest file and owners; and the archive, compression and dump commands (`tar`, `zip`, `7z`, `split`, `mysqldump`, `pg_dump`, `mongodump`, `redis-cli`) run through sudo, pkexec, cron or recorded by auditd, or set up in cron entries and units.

**Reading the output.** Archives in a web root (+3) are often staged there to be downloaded over HTTP: check the access log for the file name ([LEXF-03](../../TA0010-exfiltration/LEXF-03-large-transfers-served-by-web-and-ftp/)). Large archives in `/tmp`, `/dev/shm` or a hidden folder, a dump of a database the account does not own, and archives created inside the incident window rank next. Backups written by cron to a fixed folder every night are the usual false positive; they repeat with the same names and sizes. Set `since` first.

**If it errors or looks empty.** `Unknown column [file.directory]`: no `bodyfile-*` index exists; remove it and the archive terms to keep only the commands.

**Next.** [LCO-02](../LCO-02-file-creation-bursts/) for bursts of copied files, [LEXF-01](../../TA0010-exfiltration/LEXF-01-exfiltration-tools-and-commands/) for how they left.
