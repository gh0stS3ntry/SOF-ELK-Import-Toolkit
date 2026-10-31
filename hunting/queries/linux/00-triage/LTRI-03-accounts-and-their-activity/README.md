# LTRI-03 Accounts, their login rights and password state, and their activity in the logs

| | |
|---|---|
| Tactic | Triage (first cut) |
| ATT&CK | T1078.003 Local Accounts, T1087.001 Local Account |
| Indexes | `linuxconfig-*`, `wtmp-*`, `logstash-*`, `auditd-*` |
| Needs | linuxconfig-* (accounts); wtmp-*, logstash-*, auditd-* for activity |
| Applies to | every Linux host |

**What it finds.** One row per account and host: from `/etc/passwd` and the metadata of `/etc/shadow` (UID, shell, whether it can log in, password state and last change, flags such as `uid0` or `empty_password`), joined with what the account did in `wtmp`, the system logs and the audit log: successful logins, failures, sudo/su/pkexec use, remote source addresses and the first and last time it was seen.

**Reading the output.** Start with the accounts that can log in (`can_log_in`) or that show activity. Look for: an account with `uid0` or `empty_password` in `flags`; `account_state` `new_since_backup` (added by the last change to `/etc/passwd`, so recent) or `only_in_backup` (removed by it); a service account (`can_log_in` false) with logins or elevations; a `password_changed` date inside the incident window; and rows with `in_passwd` false, which are names that appear in the logs but are not local accounts (invalid users tried by a brute force, domain or LDAP accounts, or an account deleted since). `remote_sources` lists the addresses it logged in from or failed from.

**If it errors or looks empty.** `Unknown column` on a `wtmp.*` or `linuxconfig.*` field: that family was not loaded; remove it from `FROM` (and, for `linuxconfig-*`, the `linuxconfig.*` fields). `auditd-*` is optional: the query uses no auditd-only field.

**Next.** [LPE-05](../../TA0003-persistence/LPE-05-account-and-group-changes/) for account changes over time, [LCA-01](../../TA0006-credential-access/LCA-01-brute-force-and-password-spraying/) for brute force, [LPR-01](../../TA0004-privilege-escalation/LPR-01-sudo-su-pkexec-use-failures-and-rules/) for sudo use.
