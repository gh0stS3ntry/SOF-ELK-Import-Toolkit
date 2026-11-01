# LCA-03 Mail login attacks: Postfix SASL and Dovecot IMAP/POP3 failures and logins per client address

| | |
|---|---|
| Tactic | TA0006 Credential Access |
| ATT&CK | T1110.001 Password Guessing, T1110.003 Password Spraying, T1078 Valid Accounts |
| Indexes | `logstash-*` |
| Needs | Postfix and Dovecot lines in logstash-* (mail.log/maillog or the journal) |
| Applies to | Linux mail servers |

**What it finds.** Password guessing against the mail services, read from the mail log lines in `logstash-*` (Debian `mail.log`, RHEL `maillog`, or the journal): Postfix `SASL LOGIN/PLAIN authentication failed` warnings and successful SMTP AUTH (`sasl_username=`), and Dovecot IMAP and POP3 logins (`imap-login: Login: user=<...>`) and failures (`auth failed`, `pam_authenticate() failed`, `password mismatch`, `unknown user`). The client address and account are taken from the message text (`rip=`, `[address]`, `pam(user,address,...)`, `user=<...>`, `sasl_username=`), one row per client and host, with the same spraying and brute-force labels as [LCA-01](../LCA-01-brute-force-and-password-spraying/).

**Reading the output.** Highest score first. A public client that failed against many accounts and then logged in (`success_after_failures`) holds a valid mail password: reset it and look for that account's later SMTP AUTH sends in [LEXF-04](../../TA0010-exfiltration/LEXF-04-mail-sent-per-user-and-client/) and for mail rules in [LCO-03](../../TA0009-collection/LCO-03-mail-forwarding-and-copies/). Mail servers on the internet see constant guessing; failures alone matter little, logins from the same addresses matter a lot. Postfix SASL failure lines do not name the account (only the base64 prompt), so `accounts_failed` counts Dovecot rows only. When both `mail.log` and the journal were loaded the same line is counted twice: compare `datasets`.

**If it errors or looks empty.** No rows: the host's mail logs were not collected, or the mail server is not Postfix or Dovecot (Exim and Sendmail log elsewhere, see the Linux mail server checklist). `TO_IP` warnings on odd client values are harmless.

**Next.** [LEXF-04](../../TA0010-exfiltration/LEXF-04-mail-sent-per-user-and-client/) for what the accounts sent, [LCA-01](../LCA-01-brute-force-and-password-spraying/) for SSH guessing from the same addresses.
