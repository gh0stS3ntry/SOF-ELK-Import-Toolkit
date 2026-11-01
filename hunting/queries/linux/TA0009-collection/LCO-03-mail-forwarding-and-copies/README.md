# LCO-03 Mail copied or redirected on the server: .forward, procmail and Sieve files, aliases, Postfix BCC and filter settings

| | |
|---|---|
| Tactic | TA0009 Collection |
| ATT&CK | T1114.003 Email Forwarding Rule, T1114.002 Remote Email Collection, T1556 Modify Authentication Process |
| Indexes | `bodyfile-*`, `logstash-*`, `auditd-*` |
| Needs | bodyfile-* for the files; logstash-*, auditd-* for the commands that changed them |
| Applies to | Linux mail servers; any host with user mailboxes |

**What it finds.** Ways to get a copy of mail without touching a mailbox: users' `.forward`, `.procmailrc`, `.mailfilter` and Sieve scripts (Dovecot `*.sieve`, `.dovecot.sieve`, compiled `*.svbin`) on disk, the mail server's configuration (`/etc/postfix`, `/etc/exim4`, `/etc/dovecot`, `/etc/aliases` and the filter and signing tools beside them) with their modification and inode-change times, audited writes to those files, and commands that change them (`postconf -e`, `always_bcc`, `sender_bcc_maps`/`recipient_bcc_maps`, `content_filter`, `transport_maps`, `header_checks`, `postmap`, `newaliases`, `sievec`, `doveadm sieve`).

**Reading the output.** Set `since` first, then read highest score first. `always_bcc` or a BCC map sends a copy of every message to one address; a `content_filter` or `transport_maps` entry can route mail through an attacker's relay. A `.forward` or Sieve redirect in one mailbox, created inside the incident window, is the server-side version of a forwarding rule (the bodyfile names the file but holds no content: read it from the collection). Package upgrades rewrite files in `/etc/postfix` and `/etc/dovecot`; compare with [LTRI-04](../../00-triage/LTRI-04-software-installed-and-removed/).

**If it errors or looks empty.** `Unknown column [file.ctime]` or `[file.type]`: no `bodyfile-*` index exists; remove `bodyfile-*` and those fields (the command rows still work). No command rows on a host without auditd can simply mean the edits were made without sudo.

**Next.** [LEXF-04](../../TA0010-exfiltration/LEXF-04-mail-sent-per-user-and-client/) for where the mail went, [LCA-03](../../TA0006-credential-access/LCA-03-mail-login-attacks/) for the login that preceded it.
