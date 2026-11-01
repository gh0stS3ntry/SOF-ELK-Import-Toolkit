# LEXF-04 Mail sent through Postfix per authenticated user and client: messages, size, recipient domains and relay rejections

| | |
|---|---|
| Tactic | TA0010 Exfiltration |
| ATT&CK | T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol, T1114.003 Email Forwarding Rule, T1566 Phishing |
| Indexes | `logstash-*` |
| Needs | Postfix lines in logstash-* (mail.log/maillog or the journal) |
| Applies to | Linux mail servers |

**What it finds.** What each sender pushed through a Postfix server, rebuilt from the queue ID that ties a message's log lines together: the `smtpd` line (`client=host[address]`, `sasl_method`, `sasl_username`), the `qmgr` line (`from=<...>`, `size=`) and each `smtp`/`lmtp` delivery (`to=<...>`, `status=sent`). Rows are grouped by authenticated user (empty for unauthenticated and locally submitted mail) and client address, with the number of messages and delivered recipients, total size, recipient domains and senders. `NOQUEUE: reject` lines with `Relay access denied` are counted per client.

**Reading the output.** Highest score first. A stolen mailbox password shows as an authenticated user sending from a public address that is not its usual one, often to hundreds of recipients or domains (spam or phishing from the trusted domain) or, for exfiltration, a few large messages to one outside domain. Compare `first_seen` with the login in [LCA-03](../../TA0006-credential-access/LCA-03-mail-login-attacks/). Many `relay_denied` from one client is an open-relay probe; an unexpected relay that succeeded shows as an unauthenticated public `client_ip` delivering to outside domains. Mail delivered locally (to mailboxes on this server) appears with `lmtp`/`local`/`virtual` recipient domains of your own.

**If it errors or looks empty.** No rows: the Postfix log lines were not collected. Rows with no `sasl_user` and no `client_ip` are local submissions (`pickup`, cron and application mail). Queue IDs are reused after a restart only in very rare cases; a very long row in `sample_domains` for one message is a mailing list. When both `mail.log` and the journal were loaded, counts double.

**Next.** [LCA-03](../../TA0006-credential-access/LCA-03-mail-login-attacks/) for how the account was taken, [LCO-03](../../TA0009-collection/LCO-03-mail-forwarding-and-copies/) for silent copies set up on the server.
