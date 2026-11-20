# WIA-01 Injection classes beyond SQLi and traversal (SSTI, SSRF and out-of-band callbacks, XXE, NoSQL/LDAP/XPath, deserialization, prototype pollution, CRLF, encoding evasion, file inclusion, open redirect, CSV, mass assignment), scored per client

| | |
|---|---|
| Tactic | TA0001 Initial Access |
| ATT&CK | T1190 Exploit Public-Facing Application, T1595.002 Vulnerability Scanning |
| OWASP WSTG | WSTG-INJT-05.6, -06, -07, -09, -11.1, -12, -13, -15, -18, -19, -20, -21, -22, -23, -24, -25; WSTG-CLNT-04 |
| Indexes | `httpdlog-*` |
| Needs | web access logs in `httpdlog-*`: ALB/ELB (`alb2sofelk.py`), CloudFront (`cloudfrontaccess2sofelk.py`), IIS (`iisgeolocate2sofelk.py`), Apache/nginx/lighttpd (`httpd2sofelk.py`) |
| Applies to | every internet-facing web application |

**What it finds.** Clients whose URL (path and query string, lower-cased, raw and percent-encoded forms) carries the injection classes the OWASP testing guide describes and that [AIA-04](../../../aws/TA0001-initial-access/AIA-04-web-exploitation-attempts/) and [LIA-02](../../../linux/TA0001-initial-access/LIA-02-web-exploitation-on-linux-web-servers/) do not look for: template injection (`{{`, `${7`, `__class__`), SSRF to loopback, link-local and cloud metadata addresses or through `gopher://`/`dict://`/`file://`, out-of-band callback domains (Burp Collaborator, interactsh, `oast.*`, `webhook.site`), XXE and XInclude, NoSQL operators (`[$ne]`, `$where`), LDAP filter and XPath injection, serialized Java/.NET/PHP/Python objects and JSON type gadgets, prototype pollution, mass assignment of role fields, CRLF injection, double and overlong encoding and null bytes, PHP stream wrappers and log inclusion, open redirects, command substitution and format strings, and spreadsheet formulas. Scored: +1 per class, +2 for the classes that usually mean a targeted attacker (SSRF, callbacks, deserialization, SSTI, XXE), +3 when a matching request got a 2xx, +1 for a 5xx, +1 for 20 or more hits.

**Reading the output.** Run it next to AIA-04 (or LIA-02 on Linux): a client in both is working through a list of payloads. `hits_2xx` and `sample_2xx` matter most; a callback domain or a metadata address answered 200 means the server may have fetched it, so look for the outbound connection (VPC flow, firewall) at that minute. A 5xx to a deserialization or template payload is often the moment the payload ran or broke the parser. Expected noise: `%00` and backticks in some search forms, `=//` in legitimate protocol-relative redirect parameters, `role=admin` in an admin's own requests. Request bodies are not in access logs, so POSTed payloads (most XXE, JSON gadget and mass-assignment attacks) are invisible here; WAF logs ([AIA-06](../../../aws/TA0001-initial-access/AIA-06-waf-count-mode-matches/)) carry some of them.

**If it errors or looks empty.** `httpdlog-*` also matches SOF-ELK's own `httpdlog-YYYY.MM` indexes when web logs went through its Logstash pipeline; their strings are `text`, the toolkit's `keyword`. If ES|QL reports a type conflict, name the toolkit indexes instead (`FROM httpdlog-web01, httpdlog-123456789012`). No rows: no web logs were loaded, or nothing crossed the thresholds marked `// EDIT:`.

**Next.** [WPE-01](../../TA0003-persistence/WPE-01-malicious-uploads-and-the-files-requested-after/) and [APE-03](../../../aws/TA0003-persistence/APE-03-web-shell-requests/) for what was planted, [WIM-01](../../TA0040-impact/WIM-01-request-floods-and-server-error-bursts/) for the 5xx bursts.
