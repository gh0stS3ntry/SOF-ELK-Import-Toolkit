# LPE-05 Account and group changes: created, deleted, modified, password changes, and the passwd/shadow/group files

| | |
|---|---|
| Tactic | TA0003 Persistence |
| ATT&CK | T1136.001 Local Account, T1098 Account Manipulation |
| Indexes | `logstash-*`, `auditd-*`, `linuxconfig-*`, `bodyfile-*` |
| Needs | any of logstash-*, auditd-*, linuxconfig-*, bodyfile-* |
| Applies to | every Linux host |

**What it finds.** A timeline of account and group changes from every source: the messages of `useradd`, `usermod`, `groupadd`, `gpasswd`, `passwd`, `chage` and the like in the journal or `auth.log`/`secure`; audit `ADD_USER`, `DEL_USER`, `USER_MGMT`, `ADD_GROUP`, `GRP_MGMT` and `USER_CHAUTHTOK` records; the account commands run through sudo or recorded by auditd; the accounts and groups that differ from the backup copies (`/etc/passwd-`, `/etc/group-`, so changed by the last edit), accounts with flags (`uid0`, `empty_password`, `password_in_passwd`, `sudoers_rule`) and privileged groups with their members; and the inode-change times of `/etc/passwd`, `/etc/shadow`, `/etc/group` and `/etc/sudoers`.

**Reading the output.** Newest first. Look for accounts created or added to `sudo`, `wheel`, `adm`, `docker`, `lxd` or `root` inside the incident window, a password change for a service account, `uid0` accounts other than root, and a `/etc/shadow` inode change with no matching log line (an edit with `vipw`, `sed`, or a direct write). `ts` is the event time for log rows, the password's last-change date for `linux.account` rows (day precision), and the inode-change time for `bodyfile` rows; `linux.group` rows carry the group file's modification time. `user.name` is who acted (sudo, audit) or the account (snapshot); `user.target.name` is the account changed.

**If it errors or looks empty.** `Unknown column [linuxconfig.account.state]`: no `linuxconfig-*` index exists; remove it and replace the `linuxconfig.*` terms with `null` (the `WHERE` lines on `linux.account` and `linux.group` can go). `Unknown column [file.ctime]`: no `bodyfile-*`; remove it and its `CASE` branches.

**Next.** [LTRI-03](../../00-triage/LTRI-03-accounts-and-their-activity/) for each account's activity, [LPR-03](../../TA0004-privilege-escalation/LPR-03-privileged-groups-and-sudoers-changes/) for privileged groups and sudoers.
