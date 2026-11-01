# LPR-01 sudo, su and pkexec use and refusals per account, with the sudoers rules that apply

| | |
|---|---|
| Tactic | TA0004 Privilege Escalation |
| ATT&CK | T1548.003 Sudo and Sudo Caching, T1078.003 Local Accounts |
| Indexes | `logstash-*`, `auditd-*`, `linuxconfig-*` |
| Needs | logstash-* (sudo/su/pkexec/PAM) or auditd-*; linuxconfig-* for sudoers |
| Applies to | every Linux host |

**What it finds.** For each account: how often it elevated with sudo, su or pkexec (and audit `USER_CMD`), how many distinct commands it ran, how often it opened a root shell or interpreter, its refusals (wrong password, not in sudoers, command not allowed, PAM authentication failures for sudo, su and polkit) and when they started, and the sudoers rules that name it directly, with their `NOPASSWD` and `ALL` settings.

**Reading the output.** Leads: refusals for an account that does not normally use sudo (someone trying a stolen password, or probing with `sudo -l`), a burst of failures followed by elevations, root shells from an account that should only run specific commands, and a `NOPASSWD: ALL` rule for a user account. `elevations` with no `sudoers_rules` is normal when the right comes from a group (`%sudo`, `%wheel`), which [LPR-03](../LPR-03-privileged-groups-and-sudoers-changes/) lists. `user.name` is who asked; `as_users` is whom they became.

**If it errors or looks empty.** `Unknown column [linuxconfig.sudoers.principal_type]`: no `linuxconfig-*` index exists; remove it and replace the `linuxconfig.*` fields with `null`. `Unknown column [pam.service]`: no `logstash-*` index exists.

**Next.** [LEX-01](../../TA0002-execution/LEX-01-commands-run-with-sudo-su-pkexec/) for the commands, [LPR-02](../LPR-02-setuid-setgid-files-and-permission-changes/) for setuid files and capabilities.
