# LEXF-01 Exfiltration commands and tools: uploads with rclone, curl, scp, cloud CLIs, netcat; tools installed and their config files

| | |
|---|---|
| Tactic | TA0010 Exfiltration |
| ATT&CK | T1048 Exfiltration Over Alternative Protocol, T1567.002 Exfiltration to Cloud Storage, T1041 Exfiltration Over C2 Channel |
| Indexes | `logstash-*`, `auditd-*`, `linuxconfig-*`, `packages-*`, `bodyfile-*` |
| Needs | any of logstash-*, auditd-*, linuxconfig-*, packages-*, bodyfile-* |
| Applies to | every Linux host |

**What it finds.** Data leaving the host by command: `rclone copy/sync`, `curl -T`/`--upload-file`/`-F`/`--data-binary @file`, `wget --post-file`, `scp`/`rsync`/`sftp` to a remote host, `nc`/`/dev/tcp` with a file redirected in, `aws s3 cp`, `gsutil cp`, `az storage blob upload`, `azcopy`, MEGA tools, `transfer.sh`, `lftp put`, `smbclient put`, `restic backup` (sudo, pkexec, cron and audit command lines, cron entries, units and startup files, apt and dnf command lines); upload tools installed by a package; and rclone, MEGA, s3cmd and cloud CLI configuration files, plus upload binaries outside `/usr`.

**Reading the output.** A timeline, newest first. The command shows the destination (bucket, remote, host or URL) and the files. An `rclone.conf` names the remotes and their type (S3, MEGA, Google Drive, SFTP) even when no command was logged; read it from the collection. On a server that does not normally back up to the cloud, a cloud CLI installed during the incident window is a lead. Without auditd, uploads run without sudo leave no command line; the configuration files and [LEXF-03](../LEXF-03-large-transfers-served-by-web-and-ftp/) still show.

**If it errors or looks empty.** `Unknown column [package.name]`: no `packages-*` index exists; remove it and the `is_pkg` line. `Unknown column [file.created]`: no `bodyfile-*`; remove it and replace `file.created` with `null`.

**Next.** [LEXF-02](../LEXF-02-file-sharing-and-paste-sites/) for cloud and file-sharing sites, [LCO-01](../../TA0009-collection/LCO-01-archives-dumps-and-staging/) for what was staged.
