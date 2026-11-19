# Checklist: Web access logs (OWASP WSTG)

Hunts across every web access log loaded into `httpdlog-*`: ALB/ELB and CloudFront (`AWS/alb2sofelk.py`, `AWS/cloudfrontaccess2sofelk.py`) and Apache, nginx and lighttpd (`Linux/httpd2sofelk.py`). It is run with the [Windows web server](web-server.md), [Linux web server](linux-web-server.md) and [AWS web application](aws-web-application.md) checklists, after their exploitation rows. Each check turns a test from the OWASP Web Security Testing Guide (the `WSTG` IDs in the query READMEs) into what that test, or an attacker doing the same thing, leaves in an access log. Injection, traversal and probe patterns already in AIA-04 and LIA-02, web shells (APE-03, LPE-07) and large responses (AEXF-03, LEXF-03) are not repeated here. Access logs carry no request bodies and no headers beyond the user agent and referrer, so POSTed payloads and header-based attacks are only partly visible. The `IR ref` column is approximate, because the IR checklist is written for hosts.

## 1. What the logs can show

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 1.1 | Which web logs were loaded, for what time range, and which fields are filled | [WTRI-01](../queries/web/00-triage/WTRI-01-web-log-coverage-and-fields/) | 1.2.3, 2.4 | One row per index and source; gaps against the incident window; whether query strings, user agents and response sizes exist (several checks below need them); request lines the importer could not parse. |

## 2. Reconnaissance and mapping

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 2.1 | Forced browsing for backups, config and source files, admin consoles and API docs | [WDI-01](../queries/web/TA0007-discovery/WDI-01-forced-browsing-backups-admin-and-api-docs/) | 2.4.4 | 404 bursts per client; `.bak`, `.old`, `~`, `.sql`, `.tfstate`, `.svn`, `web.config`, `WEB-INF` requests; Tomcat manager, Jenkins script console, `elmah.axd`, `phpinfo.php`; Swagger/OpenAPI and GraphQL `__schema`. What was answered 2xx is an exposure whoever asked. |
| 2.2 | Malformed, desynced and smuggled requests | [WIA-03](../queries/web/TA0001-initial-access/WIA-03-malformed-and-smuggled-requests/) | 2.4 | ALB `Severe`/`Ambiguous` desync classifications, unparsed request lines, unusual HTTP versions, bursts of 400/414/431. |

## 3. Exploitation

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 3.1 | Injection classes beyond SQLi and traversal | [WIA-01](../queries/web/TA0001-initial-access/WIA-01-injection-classes-beyond-sqli-and-traversal/) | 2.4 | Template injection, SSRF to metadata addresses and out-of-band callback domains, XXE, NoSQL/LDAP/XPath, serialized objects, prototype pollution, CRLF, double encoding, PHP wrappers, open redirects; the clients whose payloads got a 2xx or a 5xx. Run with AIA-04 or LIA-02. |
| 3.2 | HTTP method abuse and verb tampering | [WIA-02](../queries/web/TA0001-initial-access/WIA-02-http-method-abuse-and-verb-tampering/) | 2.4, 2.1.4 | `PUT` or WebDAV `MOVE`/`COPY` of a script answered 201/204, TRACE/TRACK, invented verbs answered 2xx, `_method=` overrides. |
| 3.3 | Access-control bypass: refused, then allowed | [WPR-01](../queries/web/TA0004-privilege-escalation/WPR-01-access-control-bypass-denied-then-allowed/) | 2.4 | `/admin` 403 then `/admin..;/`, `/ADMIN`, `//admin` or a HEAD request answered 200 from the same client. |
| 3.4 | Malicious uploads and the files requested after them | [WPE-01](../queries/web/TA0003-persistence/WPE-01-malicious-uploads-and-the-files-requested-after/) | 2.1.4 | A client that POSTed to an upload route and then requested a `.php`/`.jsp`/`.aspx`, a `shell.php.jpg` or a `.htaccess` from the upload folder. |

## 4. Accounts and sessions

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 4.1 | Brute force, credential stuffing, reset and MFA code abuse | [WCA-01](../queries/web/TA0006-credential-access/WCA-01-login-brute-force-stuffing-and-reset-abuse/) | 2.4.1 to 2.4.4 | Many sign-in POSTs or 401s per client and minute, many user names, success-looking answers after many failures, ten or more MFA or reset submissions. |
| 4.2 | Credentials and session tokens in URLs, and tokens reused from several clients | [WCA-02](../queries/web/TA0006-credential-access/WCA-02-credentials-and-session-tokens-in-urls/) | 2.4.22 | Passwords, API keys, `jsessionid`/`PHPSESSID` and JWTs in query strings; one token used from unrelated addresses or user agents (hijacking). |

## 5. Data and availability

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 5.1 | Object ID enumeration and scraping (IDOR / BOLA) | [WCO-01](../queries/web/TA0009-collection/WCO-01-object-id-enumeration-and-scraping/) | 2.4.7 | One client reading hundreds of `/api/orders/{n}` objects with 200s, far above the endpoint's other clients; 403s mixed with 200s. |
| 5.2 | Request floods and server-error bursts | [WIM-01](../queries/web/TA0040-impact/WIM-01-request-floods-and-server-error-bursts/) | 2.1.10 | Peak requests per minute against the median; paths that started returning 500 (ReDoS, an exploit being tuned); 429 rate limiting. |

## Not covered by these queries

- Request bodies and most headers (`Host`, `X-Forwarded-Host`, `X-Original-URL`, cookies, `Origin`): host header injection, cache poisoning, CORS, CSRF, JWT tampering and most client-side tests (WSTG-CLNT) leave nothing in an access log. CloudFront logs keep cookies (`http.request.cookie`) when cookie logging is on; WAF logs keep headers ([AIA-06](../queries/aws/TA0001-initial-access/AIA-06-waf-count-mode-matches/)).
- IIS W3C logs (`u_ex*.log`): the toolkit has no IIS importer yet, so Windows web servers' own access logs are not in `httpdlog-*` unless they went through SOF-ELK's Logstash pipeline (dated indexes, which the checklist runner does not read).
- Business-logic abuse that looks like normal use (payment, coupon, inventory and workflow tests, WSTG-BUSL-01 to -04, -06, -10, -11) needs the application's own logs and the client's knowledge of normal behaviour.
