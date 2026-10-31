# Linux login records schema (`wtmp-*`)

Loaded by `Linux/wtmp2sofelk.py` (`event.dataset` `wtmp`) into `wtmp-<hostname>`. Mapping: `Linux/index_templates/component-toolkit-linux-common.json` plus `Linux/index_templates/index-wtmp.json` (index template `sofelk-toolkit-wtmp`, `dynamic: false`). Common fields: see [linux-logstash.md](linux-logstash.md#common-fields-every-linux-index).

Sources (`wtmp.source`):

| `wtmp.source` | File | Format |
|---|---|---|
| `wtmp` | `/var/log/wtmp` and rotations (`wtmp.1`, `wtmp-20261025.gz`, ...) | glibc utmp records, 384 bytes each |
| `btmp` | `/var/log/btmp` and rotations | same format; every record is a failed login |
| `wtmpdb` | `/var/lib/wtmpdb/wtmp*.db` (Debian 13+, openSUSE Tumbleweed, SLE 16) | SQLite table `wtmp(ID, Type, User, Login, Logout, TTY, RemoteHost, Service)`, times in microseconds |

`utmp` (`/var/run/utmp`) is not loaded: it only holds the sessions open at collection time, which are also in `wtmp`. `lastlog` and `faillog` are left out as unreliable.

| Field | Type | Content |
|---|---|---|
| `@timestamp` | date | record time (`ut_tv`, microseconds), or wtmpdb `Login` / `Logout` (UTC) |
| `event.action` | keyword | `login`, `logout`, `failed-login`, `boot`, `shutdown`, `runlevel-change`, `clock-changed`, `login-prompt`, `init-process`, `process-ended`, `accounting` |
| `event.category` / `event.type` / `event.outcome` | keyword | `authentication`+`session`/`start` for logins (`success`), `authentication`/`start`/`failure` for btmp, `session`/`end` for logouts, `host` for boot/shutdown/runlevel |
| `event.start` / `event.end` / `event.duration` | date / date / long | on a paired login and its logout: session start, end, length in nanoseconds |
| `user.name` | keyword | `ut_user` of logins, logouts (copied from the paired login) and failed logins; wtmpdb `User` |
| `source.address` / `source.ip` | keyword / ip | `ut_host` and `ut_addr_v6` (IPv4 or IPv6), wtmpdb `RemoteHost`. X displays such as `:0` are not a source and stay in `wtmp.host`. |
| `process.pid` | long | `ut_pid` (login/getty process) |
| `wtmp.type` / `wtmp.type_name` | integer / keyword | `ut_type` and its name (`USER_PROCESS`, `DEAD_PROCESS`, `BOOT_TIME`, `RUN_LVL`, ...); wtmpdb rows use `BOOT_TIME`, `RUN_LVL`, `USER_PROCESS` (and `DEAD_PROCESS` for the logout document made from `Logout`) |
| `wtmp.line` | keyword | terminal (`pts/0`, `tty7`, `ssh:notty`), wtmpdb `TTY` |
| `wtmp.id` | keyword | `ut_id` (inittab id or terminal suffix) |
| `wtmp.user` | keyword | raw `ut_user` of every record (`reboot`, `shutdown`, `runlevel`, `LOGIN` included) |
| `wtmp.host` | keyword | raw `ut_host`; the kernel release on boot, shutdown and runlevel records |
| `wtmp.session` | long | `ut_session` |
| `wtmp.exit.termination` / `wtmp.exit.status` | integer | `ut_exit` when set |
| `wtmp.runlevel` / `wtmp.previous_runlevel` | keyword | runlevel records (`5`, `N`, ...) |
| `wtmp.logout_type` | keyword | how a login ended: `logout`, `shutdown` (a shutdown record came first), `crash` (the next boot came with no shutdown) |
| `wtmp.service` / `wtmp.record_id` | keyword / long | wtmpdb `Service` (`sshd`, `login`, `systemd-user`) and row `ID` |

`log.file.path` is the file read; `log.offset` is the record number in a utmp file (counted from 0) or the wtmpdb row `ID`.

## Pairing

As `last` does, a login (`USER_PROCESS`) is closed by the next `DEAD_PROCESS` on the same terminal, else by the next shutdown or boot. Rotated copies are read oldest first, so a session that spans a rotation is still paired. A `DEAD_PROCESS` that closes no login (a getty on `tty1` exiting, or the logout of a login in a wtmp file that was not collected) gets `event.action` `process-ended`, so counting `logout` gives real session ends only. Logins still open at collection time have no `event.end`, and the importer prints how many there are. wtmpdb stores the login and logout in one row, which becomes a `login` and a `logout` document.

## Notes

- Records are glibc's 384-byte `struct utmp` (x86, x86_64, ARM, aarch64). Big-endian files (s390x, POWER) are detected; musl (Alpine) usually keeps no wtmp.
- The `_id` is derived from the record bytes (wtmpdb: row `ID` and login time), so the same record found under a new rotated name in a later collection overwrites instead of duplicating.
- The Kali sample has `wtmp` and `btmp` but no `wtmpdb` database (only its systemd units), so wtmpdb is fixture-tested only.

## ES|QL examples

```esql
FROM wtmp-* METADATA _index
| WHERE event.action IN ("login", "failed-login") AND source.ip IS NOT NULL
| STATS logins = COUNT(*), first = MIN(@timestamp), last = MAX(@timestamp) BY _index, user.name, source.ip, event.action
| SORT last DESC
```

```esql
FROM wtmp-* METADATA _index
| WHERE event.action == "login"
| EVAL minutes = event.duration / 60000000000
| KEEP @timestamp, _index, user.name, source.address, wtmp.line, event.end, minutes, wtmp.logout_type
| SORT @timestamp DESC
```
