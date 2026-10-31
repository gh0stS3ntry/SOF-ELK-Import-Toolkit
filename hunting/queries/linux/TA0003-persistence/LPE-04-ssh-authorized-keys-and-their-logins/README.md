# LPE-04 SSH authorized keys: who can log in with which key, file changes, and the logins that used each key

| | |
|---|---|
| Tactic | TA0003 Persistence |
| ATT&CK | T1098.004 SSH Authorized Keys |
| Indexes | `linuxconfig-*`, `bodyfile-*`, `logstash-*`, `auditd-*` |
| Needs | linuxconfig-* or bodyfile-*; sshd logins in logstash-* |
| Applies to | every Linux host running sshd |

**What it finds.** Every key in `authorized_keys` files (root, each home directory, `/etc/ssh/authorized_keys*`), by SHA256 fingerprint, with its comment, options and file times; the `authorized_keys` files themselves from the bodyfile (also those for which no key was parsed); the public-key logins sshd recorded, matched to the key by the same fingerprint; and commands or audited writes that touched an `authorized_keys` file.

**Reading the output.** `id` is a key fingerprint for `key` and `login` rows, a file for `key file` rows, and a command for `edit command` rows. Leads: a login with a key that is in no `authorized_keys` file any more (`f_unknown_key`, removed after use, or kept in a path set by `AuthorizedKeysFile` that the collection missed); a key added to root (`root_authorized_key`); a key file changed inside the incident window (`file_ctime`); a key whose `comment` names a user or host that does not belong (`root@kali`, an attacker's laptop); and commands such as `echo ssh-ed25519 ... >> /root/.ssh/authorized_keys`. Set `since` first.

**If it errors or looks empty.** `Unknown column [linuxconfig.ssh.fingerprint]`: no `linuxconfig-*` index exists; replace the `linuxconfig.*` fields with `null`. `Unknown column [ssh.login_method]`: no `logstash-*` index exists; remove it and the `ssh.*` fields.

**Next.** [LIA-01](../../TA0001-initial-access/LIA-01-remote-logins-from-public-addresses/) and [LLM-01](../../TA0008-lateral-movement/LLM-01-inbound-sessions-with-duration/) for the logins themselves.
