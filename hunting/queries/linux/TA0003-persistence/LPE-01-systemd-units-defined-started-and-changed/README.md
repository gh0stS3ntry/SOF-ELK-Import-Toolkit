# LPE-01 systemd services, timers and other units: definition, unit-file times, starts and audited writes, scored

| | |
|---|---|
| Tactic | TA0003 Persistence |
| ATT&CK | T1543.002 Systemd Service, T1053.006 Systemd Timers |
| Indexes | `linuxconfig-*`, `bodyfile-*`, `logstash-*`, `auditd-*` |
| Needs | linuxconfig-* (unit definitions); bodyfile-*, logstash-*, auditd-* add file times, starts and writes |
| Applies to | every Linux host |

**What it finds.** One row per systemd unit and host, built from four sources: the unit definition (`ExecStart`, run-as user, `WantedBy`, timer schedule, enabled or masked, origin `admin`/`vendor`/`runtime`/`user_home`, and flags such as `runs_from_temp` or `reverse_shell`), the unit file and its `.wants/` links in the bodyfile (modification and inode-change times), `Started <unit>` lines in the journal or syslog (how often and when it ran), and audit records of writes to unit folders. Vendor units with nothing odd score 0 and are left out.

**Reading the output.** Score 5 and above first. Typical persistence: an `admin` or `user_home` unit whose `exec_start` points into `/tmp`, `/dev/shm`, a home or hidden folder, or runs a shell, interpreter or download; a timer with a short schedule; a unit enabled (`newest_ctime` of its `.wants/` link is when) inside the incident window; a `run-*` transient unit (made by `systemd-run`, which leaves no file); and a `.service` that started but has no unit file left (`f_no_file`, deleted after use, or a generated unit). An attacker editing a vendor unit shows as a vendor unit with a recent `newest_ctime`. Set the `since` line to the start of the incident window first.

**If it errors or looks empty.** `Unknown column [linuxconfig.systemd.unit]`: no `linuxconfig-*` index exists; this query needs it. `Unknown column [file.type]` or `[file.mtime]`: no `bodyfile-*` index exists; remove `bodyfile-*` (the unit definitions still carry `file.mtime`). `auditd-*` is optional.

**Next.** [LPE-02](../LPE-02-cron-and-at-jobs-configured-and-run/) for cron, [LEX-02](../../TA0002-execution/LEX-02-programs-in-temp-hidden-and-user-writable-locations/) for programs started from odd folders.
