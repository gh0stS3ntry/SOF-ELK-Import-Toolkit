# Linux audit log schema (`auditd-*`)

Loaded by `Linux/auditd2sofelk.py` (`event.dataset` `auditd.log`) into `auditd-<hostname>`. Mapping: `Linux/index_templates/component-toolkit-linux-common.json` plus `Linux/index_templates/index-auditd.json` (index template `sofelk-toolkit-auditd`, `dynamic: false`). The common fields (`@timestamp`, `case`, `host.*`, `event.*`, `log.file.path`, `log.offset`) are described in [linux-logstash.md](linux-logstash.md#common-fields-every-linux-index).

**One document per audit event.** The kernel writes one event as several records that share the id `msg=audit(<epoch>.<ms>:<serial>)` (for an `execve`: `SYSCALL`, `EXECVE`, `CWD`, `PATH`..., `PROCTITLE`, `EOE`). The importer groups them back together, as Auditbeat does, so one row holds the user, the command line, the directory and the file. `message` keeps the raw records, one per line. `log.offset` is the line of the event's first record.

Names follow Auditbeat's auditd module (`auditd.*`) and ECS. Values are read from the raw fields, and `.name` fields come from the log's ENRICHED part (`log_format = ENRICHED`, the RHEL 8+ default) or, when the log is RAW, from the collected `/etc/passwd` and `/etc/group` (names at collection time, so an account deleted or renumbered earlier can resolve wrongly).

## Event fields

| Field | Type | Source |
|---|---|---|
| `@timestamp` | date | the event id's epoch time (UTC, millisecond precision) |
| `message` (+ `.text`) | keyword + match_only_text | raw records |
| `auditd.sequence` | long | serial number of the event id |
| `auditd.node` | keyword | `node=` prefix (when `name_format` is set) |
| `auditd.log.record_type` | keyword | type of the first record (`SYSCALL`, `USER_LOGIN`, `ADD_USER`, ...) |
| `auditd.record_types` | keyword (array) | every record type in the event |
| `auditd.result` | keyword | `success` / `fail` (`success=` of SYSCALL, `res=` of user-space records) |
| `auditd.key` | keyword (array) | audit rule key(s) (`key=`; hex-encoded multi-keys are split) |
| `auditd.session` | keyword | `ses=` (unset `4294967295` is left out) |
| `auditd.data.syscall` | keyword | syscall name (from ENRICHED, else a built-in x86_64/aarch64 table; unknown numbers stay numeric) |
| `auditd.data.arch` | keyword | `x86_64`, `i386`, `aarch64`, ... |
| `auditd.data.exit`, `a0`..`a3`, `items`, `tty`, `ppid_comm` | keyword | raw SYSCALL fields (`a0`..`a3` are hex numbers) |
| `auditd.data.op`, `terminal`, `res`, `hostname`, `addr`, `unit` | keyword | fields inside the `msg='...'` of user-space records (`unit` for SERVICE_START/STOP) |
| `auditd.data.name` | keyword | module name of a `KERN_MODULE` record |
| `auditd.data.socket.family` / `addr` / `port` / `path` | keyword / ip / long / keyword | `SOCKADDR` `saddr=` decoded (ipv4, ipv6, unix, netlink) |
| `auditd.paths.name` / `nametype` / `inode` / `mode` / `ouid` / `ogid` / `item` | keyword | one entry per `PATH` record; relative names are joined with `CWD`. An array of objects: the values of different entries are not tied together in queries. |

## ECS fields

| Field | Type | Source |
|---|---|---|
| `event.action` | keyword | `executed` (any event with `EXECVE`), the syscall name for other SYSCALL events (`openat`, `connect`, ...), `loaded-kernel-module`, `unloaded-kernel-module`, or Auditbeat's action for user-space records: `logged-in`, `logged-out`, `authenticated`, `was-authorized`, `started-session`, `ended-session`, `acquired-credentials`, `ran-command`, `added-user-account`, `deleted-user-account`, `added-group-account-to`, `changed-password`, `modified-user-account`, `started-service`, `stopped-service`, `changed-audit-configuration`, ... Other types: the record type in lower case with dashes. |
| `event.category` / `event.type` | keyword | `process`/`start` for executions, `authentication`, `session`, `iam`, `network`, `driver`, `file`, `configuration`, `host` |
| `event.outcome` | keyword | `success` / `failure` from `auditd.result` |
| `process.pid` / `process.parent.pid` | long | `pid=` / `ppid=` |
| `process.name` / `process.executable` | keyword | `comm=` / `exe=` |
| `process.args` | keyword (array) | `EXECVE` `a0`..`aN` (hex-decoded; long arguments split as `aN[0]`, `aN[1]` are joined) |
| `process.command_line` (+ `.text`) | keyword + match_only_text | `process.args` joined with spaces; else the `cmd=` of a `USER_CMD` (sudo) record; else `PROCTITLE` for an execve |
| `process.title` (+ `.text`) | keyword + match_only_text | `PROCTITLE` (hex-decoded, NULs as spaces; the kernel truncates it at 128 bytes) |
| `process.working_directory` | keyword | `CWD` record, or `cwd=` of `USER_CMD` |
| `user.id` / `user.name` | keyword | `uid=` (see below) |
| `user.audit.id` / `.name` | keyword | `auid=`, the login user, kept across `su`/`sudo` |
| `user.effective.id` / `.name` | keyword | `euid=` |
| `user.group.id` / `.name`, `user.effective.group.id` / `.name` | keyword | `gid=`, `egid=` |
| `process.user.id` / `.name` | keyword | `uid=` of authentication and session records (the sshd/login/sudo process, usually root) |
| `user.target.id` / `.name` | keyword | account changed by an account-management record (`acct=`, else `id=` resolved through `/etc/passwd`) |
| `group.id` / `group.name` | keyword | group changed by `ADD_GROUP`, `DEL_GROUP`, `GRP_MGMT` |
| `file.path` / `inode` / `mode` / `uid` / `gid` / `owner` / `group` | keyword | the first `PATH` record that is not the `PARENT` directory entry; `mode` is the permission part (`0755`) |
| `source.ip` / `source.address` | ip / keyword | `addr=` (and `hostname=` when it differs) of user-space records; for `bind`/`accept` the socket address |
| `source.port` | long | `bind`/`accept` socket port |
| `destination.ip` / `destination.port` | ip / long | `connect`/`sendto` socket address |

**Which user is `user.name`?** For authentication and session records (`USER_AUTH`, `USER_ACCT`, `USER_LOGIN`, `USER_LOGOUT`, `USER_START`, `USER_END`, `CRED_*`, `USER_ERR`, `ANOM_LOGIN_*`) it is the account logging in (`acct=`, or `id=`), as for sshd in `logstash-*`, and the uid of the process writing the record is in `process.user.id`. For account management (`ADD_USER`, `DEL_USER`, `USER_CHAUTHTOK`, `USER_MGMT`, ...) the account changed is in `user.target.*` and the actor in `user.*`. Everywhere else `user.*` is the subject's `uid=`.

## Notes

- Records of one event are usually adjacent but may interleave with other events; they are grouped by id. A single-record user-space event (no `EOE`) is written once 1,000 more lines have passed.
- The `_id` is derived from the host, `auditd.node` and the event id, so the same event found in a rotated copy in a later collection overwrites instead of duplicating.
- The hex encoding the kernel uses for values with spaces or special characters (`proctitle`, `EXECVE` arguments, `name`, `cwd`, `comm`, `exe`, `acct`, `cmd`, `key`, ...) is decoded. `a0`..`a3` of `SYSCALL` records are numbers and stay hex.
- Fixture-tested only: no real audit log has been available (the Kali sample has no auditd).

## ES|QL examples

```esql
FROM auditd-* METADATA _index
| WHERE event.action == "executed" AND process.working_directory IN ("/tmp", "/dev/shm", "/var/tmp")
| KEEP @timestamp, _index, user.audit.name, user.name, process.working_directory, process.command_line, auditd.key
| SORT @timestamp
```

```esql
FROM auditd-* METADATA _index
| WHERE auditd.log.record_type == "USER_LOGIN" AND event.outcome == "failure"
| STATS failures = COUNT(*), users = COUNT_DISTINCT(user.name) BY _index, source.ip
| SORT failures DESC
```
