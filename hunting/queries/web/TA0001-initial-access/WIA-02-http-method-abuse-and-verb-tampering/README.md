# WIA-02 HTTP method abuse: PUT/DELETE/WebDAV writes that succeeded, TRACE/TRACK/DEBUG, unknown verbs and method-override parameters, per client and method

| | |
|---|---|
| Tactic | TA0001 Initial Access |
| ATT&CK | T1190 Exploit Public-Facing Application, T1505.003 Web Shell |
| OWASP WSTG | WSTG-CONF-06 HTTP Methods, WSTG-INJT-03 HTTP Verb Tampering |
| Indexes | `httpdlog-*` |
| Needs | web access logs in `httpdlog-*`: ALB/ELB (`alb2sofelk.py`), CloudFront (`cloudfrontaccess2sofelk.py`), Apache/nginx/lighttpd (`httpd2sofelk.py`) |
| Applies to | every web server; IIS and Tomcat with WebDAV or PUT enabled first |

**What it finds.** Requests with any method other than GET, POST, HEAD and OPTIONS, and requests with a method-override parameter (`_method=`, `x-http-method-override`), grouped by client and method. Scored: a write method (PUT, DELETE, PATCH, MOVE, COPY, MKCOL) that got a 2xx +3, a script file (`.php`, `.jsp`, `.aspx`, `.war`, `.htaccess`, ...) written with a 2xx +3, WebDAV methods +1, TRACE/TRACK/DEBUG/CONNECT +1 (+2 when answered 2xx), a method no RFC defines +2, method override +2.

**Reading the output.** `script_writes_ok` is the strongest lead: `PUT /shell.jsp` answered 201 or 204 is a web shell upload (the CVE-2017-12615 Tomcat pattern), and `MOVE` or `COPY` renaming a `.txt` to `.asp` is the IIS WebDAV variant; take `ok_paths` to [APE-03](../../../aws/TA0003-persistence/APE-03-web-shell-requests/) or [PE-17](../../../windows/TA0003-persistence/PE-17-web-shell-files/). An invented verb (`FOO`, `JEFF`) answered 2xx where GET was refused is an access-control bypass; see [WPR-01](../../TA0004-privilege-escalation/WPR-01-access-control-bypass-denied-then-allowed/). REST APIs use PUT, PATCH and DELETE normally: compare those rows with the API's routes and the client's usual behaviour. `CONNECT` on a non-proxy server is someone testing for an open proxy.

**If it errors or looks empty.** `httpdlog-*` also matches SOF-ELK's own `httpdlog-YYYY.MM` indexes when web logs went through its Logstash pipeline; their strings are `text`, the toolkit's `keyword`. If ES|QL reports a type conflict, name the toolkit indexes instead (`FROM httpdlog-web01, httpdlog-123456789012`). No rows: no web logs were loaded, or nothing crossed the thresholds marked `// EDIT:`.

**Next.** [WPR-01](../../TA0004-privilege-escalation/WPR-01-access-control-bypass-denied-then-allowed/), [WPE-01](../../TA0003-persistence/WPE-01-malicious-uploads-and-the-files-requested-after/).
