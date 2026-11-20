# WPR-01 Access-control bypass: protected paths answered 2xx after 401/403, through path-confusion tricks, another HTTP method or a different case, per client and path

| | |
|---|---|
| Tactic | TA0004 Privilege Escalation |
| ATT&CK | T1190 Exploit Public-Facing Application, T1078 Valid Accounts |
| OWASP WSTG | WSTG-ATHZ-02 Bypassing Authorization Schema, WSTG-ATHZ-03 Privilege Escalation, WSTG-CONF-13 Path Confusion, WSTG-CONF-06 (access control bypass), WSTG-APIT-04 |
| Indexes | `httpdlog-*` |
| Needs | web access logs in `httpdlog-*`: ALB/ELB (`alb2sofelk.py`), CloudFront (`cloudfrontaccess2sofelk.py`), IIS (`iisgeolocate2sofelk.py`), Apache/nginx/lighttpd (`httpd2sofelk.py`) |
| Applies to | web applications and reverse proxies that protect admin or internal paths |

**What it finds.** Paths that some request was refused (401/403), normalised so that `/admin;x/`, `/admin/./`, `//admin`, `/%2e/admin` and `/admin/` are the same resource. Per client and path: refusals, 2xx answers, and 2xx answers reached through a path-confusion form (path parameters, `..;/`, encoded dots, slashes and backslashes, doubled slashes, trailing dots or spaces), through a different letter case on admin-like paths, or with a method other than GET/POST (HEAD or an invented verb). Scored: 2xx through a path trick +3, through a method change after a refusal +3, through a case change +2, 403 then 2xx for the same client +2, a client that never got refused reaching a path others were refused +1.

**Reading the output.** `ok_forms` shows the exact path forms that got through; compare them with the refused ones. `/admin` 403 then `/admin..;/` or `/ADMIN` 200 from the same client is the classic proxy-vs-application disagreement (Tomcat behind nginx, Spring path matching). A HEAD or `FOO` request answered 200 where GET got 403 is the method bypass from the HTTP methods test. `401` followed by `200` alone is just HTTP authentication and scores 0. Legitimate admins also appear (refused before signing in, then allowed): check whether the client is one of the client's admin addresses.

**If it errors or looks empty.** `httpdlog-*` also matches SOF-ELK's own `httpdlog-YYYY.MM` indexes when web logs went through its Logstash pipeline; their strings are `text`, the toolkit's `keyword`. If ES|QL reports a type conflict, name the toolkit indexes instead (`FROM httpdlog-web01, httpdlog-123456789012`). No rows: no web logs were loaded, or nothing crossed the thresholds marked `// EDIT:`.

**Next.** [WDI-01](../../TA0007-discovery/WDI-01-forced-browsing-backups-admin-and-api-docs/) for how the path was found, [WIA-02](../../TA0001-initial-access/WIA-02-http-method-abuse-and-verb-tampering/) for the same client's other methods.
