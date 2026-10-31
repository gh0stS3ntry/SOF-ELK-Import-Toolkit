# LEX-01 Commands run with sudo, su, pkexec and other elevation, per account (stacked)

| | |
|---|---|
| Tactic | TA0002 Execution |
| ATT&CK | T1548.003 Sudo and Sudo Caching, T1059.004 Unix Shell |
| Indexes | `logstash-*`, `auditd-*` |
| Needs | sudo/su/pkexec messages in logstash-*, or auditd-* |
| Applies to | every Linux host |

**What it finds.** Every distinct command an account ran through sudo, su or pkexec, from the journal or `auth.log`/`secure` and from audit `USER_CMD` records, with how often, when first and last, as whom, from which directory and terminal, and how many attempts were refused.

**Reading the output.** Sorted newest first, so the most recent activity is on top; sort by `runs` to stack instead (a command run once is more interesting than one run every day). Look for: shells and editors run as root (`su`, `bash`, `vi /etc/sudoers`), downloads and installs, commands run from `/tmp`, `/dev/shm` or a home directory (`directories`, and relative paths such as `./proxy`), user and group changes, edits to `/etc/hosts`, `/etc/passwd` or SSH and PAM files, service starts and stops, and `failures` (wrong password, user not in sudoers). sudo logs only the command it ran; what that shell or editor did next is not logged unless auditd recorded it.

**If it errors or looks empty.** `Unknown column [sudo.tty]` cannot happen while `logstash-*` exists; on a host with only an audit log, remove `logstash-*` and `sudo.tty`. No rows: no sudo, su or pkexec messages were logged (check [LTRI-01](../../00-triage/LTRI-01-linux-data-coverage/)).

**Next.** [LPR-01](../../TA0004-privilege-escalation/LPR-01-sudo-su-pkexec-use-failures-and-rules/) for refused attempts and sudoers rules, [LEX-04](../LEX-04-suspicious-command-lines/) for suspicious command lines.
