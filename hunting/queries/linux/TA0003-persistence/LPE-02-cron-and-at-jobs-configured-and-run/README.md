# LPE-02 Cron, anacron and at jobs: what is configured, what ran, and changes to the cron files

| | |
|---|---|
| Tactic | TA0003 Persistence |
| ATT&CK | T1053.003 Cron, T1053.002 At |
| Indexes | `linuxconfig-*`, `logstash-*`, `bodyfile-*`, `auditd-*` |
| Needs | linuxconfig-* (configured jobs) or cron messages in logstash-*; bodyfile-*, auditd-* add file times and edits |
| Applies to | every Linux host |

**What it finds.** Every cron job and at job on the host, joined across sources by its command: the jobs configured in `/etc/crontab`, `/etc/cron.d`, user crontabs in `/var/spool/cron`, anacron, the `cron.*` script folders and at jobs (with schedule, user and file); the jobs cron actually ran (`CRON[pid]: (user) CMD (...)` in the journal or `cron`/`syslog` log); the cron files themselves in the bodyfile and in audit records; and `crontab`, `at` and cron-file commands run through sudo or recorded by auditd.

**Reading the output.** `kinds` tells which sources saw the row. Leads: a command that `ran` but is no longer `configured` (`f_gone`, a job removed after use, or one defined somewhere the importer does not read); jobs in user crontabs and at jobs; download, shell, interpreter or `/tmp` content (`f_odd`, `flags`); and a cron file changed inside the incident window (`file_ctime`). Set `since` first. Cron logs only the command, as written in the crontab, so a configured line and its runs match exactly; scripts in `cron.daily` are listed line by line under their file and run through `run-parts`, so their runs show as `run-parts --report /etc/cron.daily`.

**If it errors or looks empty.** `Unknown column [linuxconfig.cron.schedule]`: no `linuxconfig-*` index exists; replace the `linuxconfig.*` fields with `null`. `Unknown column [file.type]`: no `bodyfile-*`; remove it. No `ran` rows: cron messages were not logged (cron logs to syslog facility `cron`, which some distros send nowhere).

**Next.** [LPE-01](../LPE-01-systemd-units-defined-started-and-changed/) for systemd timers, [LEX-04](../../TA0002-execution/LEX-04-suspicious-command-lines/) for suspicious command lines.
