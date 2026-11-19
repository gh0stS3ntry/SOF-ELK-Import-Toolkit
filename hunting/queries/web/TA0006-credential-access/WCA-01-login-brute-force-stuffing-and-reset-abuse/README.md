# WCA-01 Login brute force, credential stuffing, account enumeration, password-reset and MFA code abuse against web sign-in endpoints, per client

| | |
|---|---|
| Tactic | TA0006 Credential Access |
| ATT&CK | T1110.001 Password Guessing, T1110.003 Password Spraying, T1110.004 Credential Stuffing, T1589.001 Credentials |
| OWASP WSTG | WSTG-ATHN-02, -03, -09, -11; WSTG-IDNT-04; WSTG-BUSL-05, -07 |
| Indexes | `httpdlog-*` |
| Needs | web access logs in `httpdlog-*`: ALB/ELB (`alb2sofelk.py`), CloudFront (`cloudfrontaccess2sofelk.py`), Apache/nginx/lighttpd (`httpd2sofelk.py`) |
| Applies to | every web application with its own sign-in, and servers using HTTP Basic/Digest authentication |

**What it finds.** Requests to sign-in, password reset, MFA/OTP and registration or user-check routes (matched on the path), plus every 401. Per client: sign-in submissions (POST/PUT) and 401s, the busiest minute, redirects and 200s after a sign-in POST, 403 and 429 answers, reset and MFA submissions, registration and user-exists probes, and the HTTP authentication user names tried. Scored on volume (20 and 200 attempts), speed (10 or more per minute), many user names (spraying), success-looking answers after many attempts, reset and MFA code abuse, many user agents (credential-stuffing tools rotate them) and rate limiting being hit.

**Reading the output.** Credential stuffing is many sign-ins, one or two per user, from many addresses: sort by `attempts` and look for several clients with the same user agents and endpoints in the same hours. A login POST normally answers 302 on success and 200 (form again) on failure, but that depends on the application; check one known failure in the raw logs before trusting `login_redirects`. `mfa_submits` of 10 or more from one client is someone guessing a one-time code. Reset requests in bulk are either user enumeration (different answers for known and unknown users) or someone flooding a victim's mailbox. `throttled_429` shows the lockout working; what matters is whether the same client got a success afterwards.

**If it errors or looks empty.** `httpdlog-*` also matches SOF-ELK's own `httpdlog-YYYY.MM` indexes when web logs went through its Logstash pipeline; their strings are `text`, the toolkit's `keyword`. If ES|QL reports a type conflict, name the toolkit indexes instead (`FROM httpdlog-web01, httpdlog-123456789012`). `client.user.name` comes only from Apache/nginx/lighttpd logs with HTTP authentication. The runner reads it as empty for ALB/CloudFront-only cases; by hand, add `| EVAL `client.user.name` = TO_STRING(NULL)` after `FROM` if ES|QL says it is unknown. No rows: no web logs were loaded, or nothing crossed the thresholds marked `// EDIT:`.

**Next.** [WCA-02](../../TA0006-credential-access/WCA-02-credentials-and-session-tokens-in-urls/), and the application's own authentication logs for which accounts actually signed in.
