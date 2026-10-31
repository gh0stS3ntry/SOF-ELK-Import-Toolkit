# LLM-01 Inbound remote sessions per account and source, with session length, terminal and method

| | |
|---|---|
| Tactic | TA0008 Lateral Movement |
| ATT&CK | T1021.004 SSH, T1078 Valid Accounts |
| Indexes | `wtmp-*`, `logstash-*`, `auditd-*` |
| Needs | wtmp-* or sshd logs in logstash-* |
| Applies to | every Linux host |

**What it finds.** Every account and source address that logged in to the host remotely: `wtmp` sessions (paired with their logout, so with a length in minutes, the terminal, and whether the session was still open at collection or ended in a crash), sshd logins from the journal or `auth.log`/`secure` (with the method: password, publickey, keyboard-interactive), audit `USER_LOGIN` records, and FTP logins. Internal sources come first, since they are how an intruder moves between hosts.

**Reading the output.** Look for accounts logging in from hosts they do not normally use, service accounts with interactive sessions, logins from another server rather than from an admin workstation or jump host, long sessions, sessions still open (`still_open`) at collection time, and `publickey` logins for accounts that normally use a password (a planted key, see [LPE-04](../../TA0003-persistence/LPE-04-ssh-authorized-keys-and-their-logins/)). Take `source.ip` to that host's own pack: the same session should appear there as outbound SSH ([LLM-02](../LLM-02-outbound-remote-access-from-this-host/)). wtmp and sshd record the same login, so `logins` can count one session twice.

**If it errors or looks empty.** `Unknown column [event.duration]` or `[wtmp.line]`: no `wtmp-*` index exists; replace the `wtmp.*` fields and `event.duration` with `null`.

**Next.** [LLM-02](../LLM-02-outbound-remote-access-from-this-host/) for outbound remote access, [LCA-01](../../TA0006-credential-access/LCA-01-brute-force-and-password-spraying/) for failed logins before these.
