# WCA-02 Passwords, API keys, session IDs and JWTs in URLs, and the same token used from several clients (session hijacking)

| | |
|---|---|
| Tactic | TA0006 Credential Access |
| ATT&CK | T1552.001 Credentials In Files, T1539 Steal Web Session Cookie, T1550.004 Web Session Cookie |
| OWASP WSTG | WSTG-SESS-04 Exposed Session Variables, WSTG-SESS-09 Session Hijacking, WSTG-SESS-10 JSON Web Tokens, WSTG-CRYP-03, WSTG-ATHN-01 |
| Indexes | `httpdlog-*` |
| Needs | web access logs in `httpdlog-*`: ALB/ELB (`alb2sofelk.py`), CloudFront (`cloudfrontaccess2sofelk.py`), IIS (`iisgeolocate2sofelk.py`), Apache/nginx/lighttpd (`httpd2sofelk.py`) |
| Applies to | every web application; legacy Java/PHP/ASP applications that put session IDs in URLs first |

**What it finds.** Query-string and path parameters named like a password, secret, token, API key or session ID (`;jsessionid=`, `PHPSESSID`, `access_token`, `api_key`, ...) and JSON Web Tokens anywhere in the URL. Each value is grouped and shown as a preview (first six and last four characters) and a SHA-256, so the output can be shared without the secret. Scored: the same session ID or token used by more than one client address +3, by more than one user agent +1, a password or secret in a URL +2, sent over plain HTTP +1.

**Reading the output.** One session ID or bearer token used from two unrelated addresses (different countries or providers, a different user agent) is session hijacking, or a token copied from logs, Referer headers or browser history. Mobile users switching networks also change address; the user agent usually stays the same. A password in a URL means every proxy, access log and Referer on the way has it: treat it as exposed. Search the raw logs with the preview (`LIKE "*first6*last4*"`) to see every use.

**If it errors or looks empty.** `httpdlog-*` also matches SOF-ELK's own `httpdlog-YYYY.MM` indexes when web logs went through its Logstash pipeline; their strings are `text`, the toolkit's `keyword`. If ES|QL reports a type conflict, name the toolkit indexes instead (`FROM httpdlog-web01, httpdlog-123456789012`). No rows: no web logs were loaded, or nothing crossed the thresholds marked `// EDIT:`.

**Next.** [WCA-01](../../TA0006-credential-access/WCA-01-login-brute-force-stuffing-and-reset-abuse/) for how the account was taken, and the application's session store or IdP logs for the token's owner.
