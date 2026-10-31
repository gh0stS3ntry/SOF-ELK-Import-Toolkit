# LPR-03 Privileged group members and sudoers rules, with group changes and sudoers file edits

| | |
|---|---|
| Tactic | TA0004 Privilege Escalation |
| ATT&CK | T1098 Account Manipulation, T1548.003 Sudo and Sudo Caching |
| Indexes | `linuxconfig-*`, `logstash-*`, `auditd-*`, `bodyfile-*` |
| Needs | linuxconfig-*; logstash-*, auditd-*, bodyfile-* add changes and file times |
| Applies to | every Linux host |

**What it finds.** Who holds root-equivalent rights and when that changed: members of privileged groups (`root`, `sudo`, `wheel`, `adm`, `admin`, `docker`, `lxd`, `libvirt`, `disk`, `shadow`, and groups named in sudoers), with members added or removed since the `/etc/group-` backup; every sudoers rule, `Defaults` line and include; group-membership messages and audit records; inode-change times of `/etc/sudoers`, `sudoers.d` files, `/etc/group` and `/etc/gshadow`; and `visudo`, `usermod -aG`, `gpasswd -a` and sudoers edits run through sudo.

**Reading the output.** A timeline, newest first; `score` marks rows worth reading first. Membership of `docker`, `lxd`, `libvirt` or `disk` is root in practice. Look for a user added to a privileged group inside the incident window, a sudoers file in `sudoers.d` with a recent inode change, `NOPASSWD` rules for accounts that are not automation, and `Defaults` that keep `LD_PRELOAD` or turn off `env_reset` (`env_preserved`). For `linux.*` rows `ts` is the file's modification time, which dates the last edit of the whole file, not of that line.

**If it errors or looks empty.** `Unknown column [linuxconfig.group.privileged]`: no `linuxconfig-*` index exists; this query needs it for the snapshot rows. `Unknown column [file.type]`: no `bodyfile-*`; remove it.

**Next.** [LPR-01](../LPR-01-sudo-su-pkexec-use-failures-and-rules/) for how the rights were used, [LPE-05](../../TA0003-persistence/LPE-05-account-and-group-changes/) for account changes.
