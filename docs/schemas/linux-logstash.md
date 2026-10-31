# Linux system log schema (`logstash-*`)

Loaded by `Linux/journal2sofelk.py` (`event.dataset` `syslog.journal`), `Linux/syslog2sofelk.py` (`event.dataset` `syslog.file`) and `Linux/vsftpd2sofelk.py` (`event.dataset` `ftp.vsftpd` and `ftp.xferlog`, see [FTP logs](#ftp-logs-vsftpd2sofelkpy)). Mapping: `Linux/index_templates/component-toolkit-linux-common.json` plus `Linux/index_templates/index-logstash.json`, applied when the importer creates `logstash-<hostname>` (no index template is installed, because `logstash-*` is SOF-ELK's own family). The index uses `dynamic: false`, so a field not listed here is not searchable.

## Common fields (every Linux index)

| Field | Type | Content |
|---|---|---|
| `@timestamp` | date | UTC. Journal: `__REALTIME_TIMESTAMP`. Text syslog: the line's time, converted from `event.timezone`. |
| `case` | keyword | `--case` |
| `tags` | keyword | `got_ssh`, `got_pam`, `got_sudo`, `got_su`, `got_pkexec`, `got_account`, `got_logind`, `got_cron`, `got_iptables`, `kernel_module`, `usb_device` |
| `labels.type` | keyword | `syslog` (as in SOF-ELK) |
| `event.dataset` | keyword | `syslog.journal` or `syslog.file` |
| `event.kind` / `category` / `type` / `action` / `outcome` | keyword | set for recognised messages (see below) |
| `event.timezone` | keyword | the zone used for local times (text syslog) |
| `log.file.path` | keyword | path inside the collection, e.g. `[root]/var/log/auth.log.2.gz` or `journal/journalctl_full_journal_logs.json` |
| `log.offset` | long | line position in the file, counted from 0 |
| `host.name` | keyword | normalised evidence host name |
| `host.id` | keyword | `/etc/machine-id` |
| `host.os.type` / `name` / `version` / `full` / `platform` / `family` / `kernel` | keyword | from `/etc/os-release` (or `redhat-release` etc.) and UAC's `uname -a` |

## Syslog fields (SOF-ELK names)

| Field | Type | Journal source | Text syslog source |
|---|---|---|---|
| `message` (+ `message.text`) | keyword (ignore_above 8191) + match_only_text | `MESSAGE` | the text after `prog[pid]:` |
| `log.syslog.hostname` | keyword | `_HOSTNAME` | the host on the line |
| `log.syslog.appname` / `process.name` | keyword | `SYSLOG_IDENTIFIER` / `_COMM` | the program name |
| `log.syslog.procid` / `process.pid` | keyword / long | `SYSLOG_PID` / `_PID` | the `[pid]` |
| `log.syslog.msgid` | keyword |  | RFC 5424 MSGID |
| `log.syslog.priority` | integer | facility × 8 + severity | RFC 5424 PRI |
| `log.syslog.facility.code` / `name` | integer / keyword | `SYSLOG_FACILITY` | RFC 5424 PRI |
| `log.syslog.severity.code` / `name` | integer / keyword | `PRIORITY` | RFC 5424 PRI |
| `host.uptime` | float | kernel `[ 12.345678]` prefix | same |

## Journal fields

| Journal field | Field | Type |
|---|---|---|
| `_EXE`, `_CMDLINE` | `process.executable`, `process.command_line` (+ `.text`) | keyword |
| `_UID`, `_GID` | `process.user.id`, `process.group.id` | keyword |
| `_TRANSPORT` | `journald.transport` | keyword |
| `_SYSTEMD_UNIT`, `_SYSTEMD_USER_UNIT`, `_SYSTEMD_SLICE`, `_SYSTEMD_CGROUP` | `journald.unit`, `user_unit`, `slice`, `cgroup` | keyword |
| `_SYSTEMD_INVOCATION_ID`, `INVOCATION_ID` | `journald.invocation_id` | keyword |
| `_BOOT_ID`, `_MACHINE_ID` | `journald.boot_id`, `journald.machine_id` | keyword |
| `__CURSOR`, `__SEQNUM`, `__SEQNUM_ID` | `journald.cursor`, `seqnum` (long), `seqnum_id` | keyword |
| `__MONOTONIC_TIMESTAMP`, `__REALTIME_TIMESTAMP` | `journald.monotonic_timestamp`, `realtime_timestamp` (µs) | long |
| `_SOURCE_REALTIME_TIMESTAMP` | `journald.source_realtime` | date |
| `_AUDIT_SESSION`, `_AUDIT_LOGINUID` | `journald.audit_session`, `audit_loginuid` | keyword |
| `_RUNTIME_SCOPE`, `MESSAGE_ID`, `_CAP_EFFECTIVE`, `_SELINUX_CONTEXT` | `journald.runtime_scope`, `message_id`, `cap_effective`, `selinux_context` | keyword |
| `_KERNEL_SUBSYSTEM`, `_KERNEL_DEVICE`, `_UDEV_SYSNAME`, `_UDEV_DEVNODE` | `journald.kernel.subsystem`, `kernel.device`, `udev.sysname`, `udev.devnode` | keyword |
| `CODE_FILE`, `CODE_FUNC`, `CODE_LINE`, `ERRNO` | `journald.code.file`, `code.func`, `code.line` (long), `journald.errno` (integer) | keyword |
| any other field | `journald.extra`, one `KEY=value` entry per field (long values are cut) | keyword |

`SYSLOG_TIMESTAMP`, `SYSLOG_RAW`, `_SOURCE_MONOTONIC_TIMESTAMP` and `_STREAM_ID` are dropped. Byte-array values (non-UTF-8 messages) are decoded, and a field repeated in one entry keeps every value.

## Fields from message parsing

| Field | Type | Set by |
|---|---|---|
| `user.name`, `user.id` | keyword | sshd, PAM, sudo, su, pkexec, logind, cron |
| `user.effective.name` / `id` | keyword | sudo, su, pkexec (the account the command ran as) |
| `user.target.name` / `id`, `group.name` / `id` | keyword | account tools (`useradd`, `usermod`, `groupadd`, ...) |
| `source.ip` / `port` / `address` / `mac`, `destination.ip` / `port` / `mac` | ip / integer / keyword | sshd, PAM `rhost`, iptables, UFW, firewalld |
| `source.bytes`, `network.bytes`, `network.transport` | long / keyword | iptables |
| `observer.ingress.interface.name` / `egress` | keyword | iptables |
| `event.auth_result`, `ssh.*` | keyword | sshd (SOF-ELK 6015-sshd.conf names) |
| `pam.module`, `service`, `sessiontype`, `event`, `by_user`, `by_uid`, `logname`, `ruser`, `rhost`, `tty` | keyword | PAM (SOF-ELK 6016-pam.conf names, plus the authentication-failure keys) |
| `sudo.tty` / `result` / `env`, `su.tty` / `result`, `pkexec.tty` / `result` | keyword | sudo, su, pkexec |
| `process.working_directory` | keyword | sudo `PWD=` |
| `account.home` / `shell` / `tty` | keyword | account tools |
| `logind.session_id` | keyword | systemd-logind |
| `iptables.label` / `ttl` / `ether_type` | keyword / integer / keyword | iptables, UFW, firewalld (SOF-ELK 6017-iptables.conf names) |

`event.action` values: `ssh-login`, `ssh-invalid-user`, `ssh-max-auth-tries`, `ssh-connection`, `ssh-connection-closed`, `ssh-disconnected`, `ssh-received-disconnect`, `ssh-negotiation-failed`, `ssh-listening`, `session-opened`, `session-closed`, `authentication-failure`, `password-changed`, `sudo-command`, `su`, `pkexec-command`, `user-created`, `user-deleted`, `user-changed`, `user-locked`, `group-created`, `group-deleted`, `group-membership-added`, `group-membership-removed`, `password-aging-changed`, `session-created`, `session-removed`, `cron-command`, `firewall-block`, `firewall-allow`, `firewall-log`, `kernel-module-warning`, `usb-device`.

## FTP logs (`vsftpd2sofelk.py`)

FTP server logs share `logstash-<hostname>` with the system logs. Files: `/var/log/vsftpd.log` (vsftpd's own format, written with `xferlog_std_format=NO` or `dual_log_enable=YES`), `/var/log/xferlog` (wu-ftpd transfer format, written by vsftpd, ProFTPD and pure-ftpd), the same names under `/var/log/vsftpd/`, `/var/log/proftpd/` and `/var/log/pure-ftpd/` (also pure-ftpd's `transfer.log`), rotated copies, and any `--ftp-log` file. vsftpd configured with `syslog_enable=YES` logs to syslog or the journal instead, which the other two importers already load.

**Time zone.** vsftpd writes GMT unless `use_localtime=YES` (Debian and Ubuntu ship `YES`, RHEL leaves the default). The importer reads the setting from the evidence's `/etc/vsftpd.conf` or `/etc/vsftpd/vsftpd.conf`; `--ftp-time local|utc` overrides it, and with no config it reads UTC and warns. ProFTPD's xferlog is local time. The zone used is in `event.timezone`.

**Passwords are removed before sending.** A `PASS` command logged with `log_ftp_protocol=YES`, vsftpd's `anon password "..."`, and xferlog's user name for anonymous sessions (which holds the password the client typed) are replaced with `<redacted>` in `message`, `ftp.command_arg` and `user.name` (`anonymous`).

| Field | Type | vsftpd.log | xferlog |
|---|---|---|---|
| `message` | keyword (+ `.text`) | the line (passwords redacted) | the line (anonymous password redacted) |
| `log.syslog.appname`, `process.name` | keyword | `vsftpd` | `vsftpd`, or `proftpd` under `/var/log/proftpd/` |
| `process.pid`, `log.syslog.procid` | long / keyword | `[pid N]` | |
| `user.name` | keyword | `[user]` | user name, or `anonymous` |
| `source.ip` / `source.address` | ip / keyword | `Client "..."` (IPv4-mapped IPv6 `::ffff:a.b.c.d` becomes `a.b.c.d`) | remote host |
| `event.action` | keyword | `ftp-connect`, `ftp-login`, `ftp-download`, `ftp-upload`, `ftp-delete`, `ftp-mkdir`, `ftp-rmdir`, `ftp-rename`, `ftp-chmod`, `ftp-command`, `ftp-response` | `ftp-download`, `ftp-upload`, `ftp-delete` (direction `o` / `i` / `d`) |
| `event.outcome` | keyword | `OK` success, `FAIL` failure | completion `c` success, `i` failure |
| `event.category` / `event.type` | keyword | `authentication` / `start`, `file` / `access`, `creation`, `deletion`, `change`, `network` / `connection`, `protocol` | `file` / ... |
| `file.path`, `file.name` | keyword | the quoted path | file name (may contain spaces) |
| `ftp.action` | keyword | the raw action, e.g. `OK DOWNLOAD`, `FAIL LOGIN`, `FTP command` | |
| `ftp.command`, `ftp.command_arg` | keyword | `log_ftp_protocol` commands, e.g. `USER` / `ftpuser`, `RETR` / `file` | |
| `ftp.response.code`, `ftp.response.message` | integer / keyword | `log_ftp_protocol` responses | |
| `ftp.transfer.bytes` | long | `N bytes` | file size |
| `ftp.transfer.rate` | keyword | e.g. `512.00Kbyte/sec` | |
| `ftp.transfer.duration` | long | | seconds |
| `ftp.transfer.type`, `ftp.transfer.direction` | keyword | | `ascii` / `binary`, `outgoing` / `incoming` / `delete` |
| `ftp.access_mode`, `ftp.special_action`, `ftp.service`, `ftp.auth_method`, `ftp.auth_user_id`, `ftp.completion` | keyword | | `real` / `guest` / `anonymous`, `none` / `compressed` / ..., `ftp`, `none` / `rfc931`, `*` left out, `complete` / `incomplete` |
| `ftp.rename_to` | keyword | `RENAME` target (vsftpd writes `"old new"`, so a path with spaces splits at the last space; the line is in `message`) | |
| `labels.type` | keyword | `ftp` | `ftp` |

```esql
FROM logstash-* METADATA _index
| WHERE event.dataset IN ("ftp.vsftpd", "ftp.xferlog") AND event.action IN ("ftp-upload", "ftp-download", "ftp-delete", "ftp-rename")
| KEEP @timestamp, _index, event.dataset, event.action, event.outcome, user.name, source.ip, file.path, ftp.transfer.bytes, ftp.rename_to
| SORT @timestamp
```

## Example ES|QL

```esql
FROM logstash-* METADATA _index
| WHERE event.dataset == "syslog.journal" AND event.action IN ("sudo-command", "su", "pkexec-command")
| KEEP @timestamp, _index, event.action, event.outcome, user.name, user.effective.name, process.command_line, process.working_directory, sudo.tty
| SORT @timestamp
```

```esql
FROM logstash-* METADATA _index
| WHERE event.action == "ssh-login"
| STATS logins = COUNT(*), first = MIN(@timestamp), last = MAX(@timestamp) BY _index, user.name, source.ip, event.outcome, ssh.login_method
| SORT logins DESC
```
