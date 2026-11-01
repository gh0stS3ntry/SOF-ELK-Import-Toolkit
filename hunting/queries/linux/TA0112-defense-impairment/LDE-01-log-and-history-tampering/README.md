# LDE-01 Log and shell-history tampering: clearing commands, history disabled, empty or redirected logs, journald and syslog stops

| | |
|---|---|
| Tactic | TA0112 Defense Impairment |
| ATT&CK | T1070.002 Clear Linux or Mac System Logs, T1070.003 Clear Command History, T1562.003 Impair Command History Logging |
| Indexes | `logstash-*`, `auditd-*`, `linuxconfig-*`, `bodyfile-*` |
| Needs | any of logstash-*, auditd-*, linuxconfig-*, bodyfile-* |
| Applies to | every Linux host |

**What it finds.** Attempts to remove or stop the record of what happened: `history -c`, `unset HISTFILE`, `HISTSIZE=0`, `set +o history`, history linked to `/dev/null`; deleting, truncating, `shred`-ing or `sed -i`-editing files in `/var/log`, emptying `wtmp`/`btmp`/`lastlog`, `utmpdump`, `journalctl --vacuum-*`/`--rotate`, forced `logrotate`, stopping or masking journald, rsyslog, syslog-ng or auditd, `auditctl -D`/`-e 0` (commands from sudo, pkexec, cron and audit records, and the same lines planted in shell startup files, cron entries and units); journald, rsyslog and auditd messages about stopping, vacuuming or deleting journals; shell and tool history files that are empty or are symlinks; and key log files that are empty or point to `/dev/null`.

**Reading the output.** A history file that is a symlink (to `/dev/null`) or a history-disabling line in a startup file scores 4: whoever did it expected to come back. Empty logs may be a fresh rotation (check the `.1` file next to it); empty `wtmp` or `btmp` with a long uptime is not. Compare the times with the log gaps in [LTRI-02](../../00-triage/LTRI-02-boots-shutdowns-and-log-gaps/): a journal boot that ends early and a `journal stopped` message with no shutdown is a stop by hand. Vacuum messages from journald's own size limit are normal, but not right after a login.

**If it errors or looks empty.** `Unknown column [file.target_path]`: no `bodyfile-*` index exists; remove it and its terms. `Unknown column [linuxconfig.line]`: no `linuxconfig-*`; replace `linuxconfig.line` with `null`.

**Next.** [LTRI-02](../../00-triage/LTRI-02-boots-shutdowns-and-log-gaps/) for log gaps, [LDE-02](../LDE-02-security-tools-and-logging-disabled/) for security tools stopped.
