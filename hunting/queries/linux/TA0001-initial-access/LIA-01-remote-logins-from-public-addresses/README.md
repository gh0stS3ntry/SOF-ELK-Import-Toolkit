# LIA-01 Remote logins from public addresses (SSH, login records, audit, FTP)

| | |
|---|---|
| Tactic | TA0001 Initial Access |
| ATT&CK | T1133 External Remote Services, T1078 Valid Accounts |
| Indexes | `logstash-*`, `wtmp-*`, `auditd-*` |
| Needs | sshd or PAM logs in logstash-*, or wtmp-* |
| Applies to | internet-facing hosts; every host reachable through a VPN or NAT |

**What it finds.** Every public address that logged in or tried to, per host, from sshd and PAM messages in the journal or `auth.log`/`secure`, from `wtmp`/`btmp`, from the audit log (`USER_LOGIN`, `USER_AUTH`) and from FTP logs. Successful logins from the internet score highest, and a success after many failures from the same address scores higher still.

**Reading the output.** A score of 6 (success after 10 or more failures) is a likely brute force that worked: take the account and `first_success` into [LLM-01](../../TA0008-lateral-movement/LLM-01-inbound-sessions-with-duration/) and the command timelines ([LEX-01](../../TA0002-execution/LEX-01-commands-run-with-sudo-su-pkexec/)). A success with no failures from an address the host's owners do not know is the next priority; `methods` shows `password` or `publickey`. Rows with only failures are internet noise unless `users_tried` holds real account names. The same login usually appears in several datasets (`datasets`), so `successes` counts records, not sessions.

**If it errors or looks empty.** `Unknown column [ssh.login_method]`: no sshd messages were parsed, which happens only when `logstash-*` is missing; remove `ssh.login_method`. No rows: no public sources; delete the line under `// EDIT:` to see private ones (internal movement is in [LLM-01](../../TA0008-lateral-movement/LLM-01-inbound-sessions-with-duration/)).

**Next.** [LCA-01](../../TA0006-credential-access/LCA-01-brute-force-and-password-spraying/) for brute force and spraying, [LPE-04](../../TA0003-persistence/LPE-04-ssh-authorized-keys-and-their-logins/) for the SSH keys used.
