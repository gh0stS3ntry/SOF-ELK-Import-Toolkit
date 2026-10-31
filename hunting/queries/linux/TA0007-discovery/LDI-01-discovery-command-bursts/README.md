# LDI-01 Discovery command bursts: many system, user and network discovery commands in a few minutes

| | |
|---|---|
| Tactic | TA0007 Discovery |
| ATT&CK | T1082 System Information Discovery, T1033 System Owner/User Discovery, T1016 System Network Configuration Discovery, T1057 Process Discovery, T1083 File and Directory Discovery |
| Indexes | `logstash-*`, `auditd-*` |
| Needs | sudo/pkexec commands in logstash-*, or auditd-* |
| Applies to | every Linux host |

**What it finds.** Ten-minute windows in which one account ran four or more different discovery commands (`id`, `whoami`, `uname`, `ip`, `ss`, `netstat`, `ps`, `last`, `getent`, `sudo -l`, `getcap`, `crontab -l`, `systemctl`, `docker`, cloud CLIs, `cat /etc/passwd`, `find / -perm -4000`, ...), or ran an enumeration script (`linpeas`, `LinEnum`, `lse.sh`, `pspy`, `linux-exploit-suggester`, `deepce`, `traitor`), from audit `execve` records and sudo, pkexec and cron command lines.

**Reading the output.** A burst of varied discovery right after a new login or an exploited web request is the classic first minutes of an intrusion; check the account and `first_time` against [LIA-01](../../TA0001-initial-access/LIA-01-remote-logins-from-public-addresses/) and [LIA-02](../../TA0001-initial-access/LIA-02-web-exploitation-on-linux-web-servers/). Enumeration scripts score +5 on their own. Admins troubleshoot the same way, so the account and the time decide. Without auditd, only commands run through sudo or pkexec are visible, and most discovery runs without sudo, so a quiet result on a host without `auditd-*` means little; `sudo -l` (logged as `list`) still shows.

**If it errors or looks empty.** No rows on a host without auditd is expected (see above). `Unknown column [process.working_directory]` does not occur while `logstash-*` or `auditd-*` exists.

**Next.** [LDI-02](../LDI-02-network-scanning-tools/) for network scanning, [LPR-02](../../TA0004-privilege-escalation/LPR-02-setuid-setgid-files-and-permission-changes/) for what a `find -perm -4000` would have found.
