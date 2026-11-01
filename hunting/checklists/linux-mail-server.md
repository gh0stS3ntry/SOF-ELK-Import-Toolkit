# Checklist: Linux mail server

Postfix, Exim and Sendmail mail transfer agents, Dovecot and Courier IMAP/POP3 servers, and the webmail (Roundcube, SOGo) and filtering (SpamAssassin, Amavis, rspamd) beside them. Run the [Linux baseline](linux-baseline-all-hosts.md) first. If the host also serves webmail, run the [web server](linux-web-server.md) checklist too. The questions are whether mailbox passwords were guessed or stolen, whether the server was used to send spam or phishing or to take mail out, whether copies of mail are being sent somewhere, and whether the mail software itself was exploited. The `IR ref` column is approximate, because the IR checklist is written for Windows hosts.

## 1. Host profile

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 1.1 | Mail software and versions | [LTRI-04](../queries/linux/00-triage/LTRI-04-software-installed-and-removed/), [LPE-09](../queries/linux/TA0003-persistence/LPE-09-repositories-and-local-packages/) | 1.2.1, 1.2.3 | Postfix, Exim, Dovecot, Roundcube and Zimbra versions against known exploited CVEs (Exim and Roundcube above all). |
| 1.2 | Which mail logs were loaded and their time range | [LTRI-01](../queries/linux/00-triage/LTRI-01-linux-data-coverage/) | 1.2.3, 2.4 | `mail.log`/`maillog` or journal lines from `postfix/*` and `dovecot`. Exim writes to `/var/log/exim4/mainlog` instead, which is not loaded (see below). |
| 1.3 | Domains served, relays allowed and who should send | | 1.3.1 | Ask the client; needed to judge rows 2.2 and 3.1. |

## 2. Access to mailboxes

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 2.1 | IMAP, POP3 and SMTP AUTH guessing and logins | [LCA-03](../queries/linux/TA0006-credential-access/LCA-03-mail-login-attacks/) | 2.4.1 to 2.4.4 | Clients that failed against many accounts and then logged in, logins from countries or providers the users never use. |
| 2.2 | SSH logins and brute force | [LIA-01](../queries/linux/TA0001-initial-access/LIA-01-remote-logins-from-public-addresses/), [LCA-01](../queries/linux/TA0006-credential-access/LCA-01-brute-force-and-password-spraying/) | 2.4.1 to 2.4.4 | Administrative logins from new addresses, success after failures. |

## 3. Mail abuse

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 3.1 | Mail sent per account and client | [LEXF-04](../queries/linux/TA0010-exfiltration/LEXF-04-mail-sent-per-user-and-client/) | 2.4.7 | An authenticated account sending to hundreds of outside domains (spam or phishing), a few large messages to one outside domain (exfiltration), unauthenticated relaying. |
| 3.2 | Silent copies and redirects | [LCO-03](../queries/linux/TA0009-collection/LCO-03-mail-forwarding-and-copies/) | 2.4 | `always_bcc` and BCC maps, `content_filter` or `transport_maps` pointing outside, `.forward` and Sieve redirects made in the window. |
| 3.3 | Mail spools and mailboxes copied | [LCO-01](../queries/linux/TA0009-collection/LCO-01-archives-dumps-and-staging/), [LCO-02](../queries/linux/TA0009-collection/LCO-02-file-creation-bursts/), [LEXF-01](../queries/linux/TA0010-exfiltration/LEXF-01-exfiltration-tools-and-commands/) | 2.1.4 | Archives of `/var/mail`, `/var/vmail` or `Maildir` folders, bursts of copied files, uploads. |

## 4. Exploitation of the mail software

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 4.1 | Commands run by the mail accounts | [LEX-02](../queries/linux/TA0002-execution/LEX-02-programs-in-temp-hidden-and-user-writable-locations/), [LEX-04](../queries/linux/TA0002-execution/LEX-04-suspicious-command-lines/), [LC2-01](../queries/linux/TA0011-command-and-control/LC2-01-reverse-shells-tunnels-and-proxies/) | 2.1.1, 2.4.5 | `Debian-exim`, `postfix`, `dovecot`, `vmail` or `www-data` (webmail) running shells, downloads or reverse shells; programs in `/tmp` owned by them. |
| 4.2 | Web shells in webmail | [LPE-07](../queries/linux/TA0003-persistence/LPE-07-web-shells-files-and-requests/), [LIA-02](../queries/linux/TA0001-initial-access/LIA-02-web-exploitation-on-linux-web-servers/) | 2.1.4 | New scripts in the Roundcube or SOGo folders, exploitation attempts against the webmail paths. |
| 4.3 | Persistence and miners | [LPE-01](../queries/linux/TA0003-persistence/LPE-01-systemd-units-defined-started-and-changed/), [LPE-02](../queries/linux/TA0003-persistence/LPE-02-cron-and-at-jobs-configured-and-run/), [LIM-03](../queries/linux/TA0040-impact/LIM-03-cryptominers/) | 2.4.14, 2.4.25, 2.1.10 | Units and cron jobs added after the exploit; miners are the usual payload of mass-exploited Exim. |

## Not covered by these queries

- Exim's `mainlog`, `rejectlog` and `paniclog`, Sendmail and Courier logs, and webmail logs (Roundcube `logs/`): read them from the collection. Postfix and Dovecot lines are covered only when they went to syslog or the journal.
- Mailbox contents and users' own filter rules inside the mailbox store (Dovecot keeps Sieve scripts on disk, which row 3.2 covers; other servers do not).
- SPF, DKIM and DMARC reports and the logs of outside filtering services in front of the server.
