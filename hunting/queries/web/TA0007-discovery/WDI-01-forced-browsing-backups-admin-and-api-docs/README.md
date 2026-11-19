# WDI-01 Forced browsing: 404 bursts, backup and source files, VCS and config files, admin and management consoles, API docs and GraphQL introspection, and which of them were served, per client

| | |
|---|---|
| Tactic | TA0007 Discovery |
| ATT&CK | T1595.003 Wordlist Scanning, T1083 File and Directory Discovery, T1552.001 Credentials In Files |
| OWASP WSTG | WSTG-CONF-04, WSTG-CONF-05, WSTG-INFO-03, WSTG-INFO-05, WSTG-APIT-01, WSTG-APIT-99 |
| Indexes | `httpdlog-*` |
| Needs | web access logs in `httpdlog-*`: ALB/ELB (`alb2sofelk.py`), CloudFront (`cloudfrontaccess2sofelk.py`), Apache/nginx/lighttpd (`httpd2sofelk.py`) |
| Applies to | every internet-facing web application |

**What it finds.** Per client: 404 and 401/403 counts, distinct paths and the busiest minute (directory brute forcing), and requests for old and backup copies (`.bak`, `.old`, `~`, `.swp`, `backup.zip`, `.sql` dumps, `.tfstate`, keys, source maps), version-control and deployment leftovers (`.svn`, `.hg`, `.DS_Store`, `.htpasswd`, `web.config`, `WEB-INF/`, `docker-compose.yml`, `appsettings.json`), admin, management and debug consoles (Tomcat manager, JBoss/JMX, Jenkins script console, Kibana, Portainer, `elmah.axd`, `phpinfo.php`, setup and install pages), and API documentation and GraphQL introspection (`swagger`, `openapi`, `__schema`, `?wsdl`). `.git`, `.env`, Actuator and phpMyAdmin are left to AIA-04/LIA-02. Scored: what was actually served (2xx) counts most: backup or config file +3, admin console +2, API docs +1; probes that got 4xx +1; 30/100 or more 404s +1/+2; 60 or more requests in a minute +1.

**Reading the output.** `served` lists what the client got back. A backup archive, `.sql` dump, `.tfstate` or config file answered 200 is a data exposure regardless of who asked; check `served_bytes` and the file's content in the web root. An admin console answered 200 to an outside address means it is exposed (and may still have default credentials: run WCA-01 for the same client). Introspection answered 200 hands the attacker the whole API. A pure 404 burst with a scanner user agent is background noise unless the same client shows up in WIA-01 or WCO-01.

**If it errors or looks empty.** `httpdlog-*` also matches SOF-ELK's own `httpdlog-YYYY.MM` indexes when web logs went through its Logstash pipeline; their strings are `text`, the toolkit's `keyword`. If ES|QL reports a type conflict, name the toolkit indexes instead (`FROM httpdlog-web01, httpdlog-123456789012`). No rows: no web logs were loaded, or nothing crossed the thresholds marked `// EDIT:`.

**Next.** [WCA-01](../../TA0006-credential-access/WCA-01-login-brute-force-stuffing-and-reset-abuse/) for logins on the consoles found, [WCO-01](../../TA0009-collection/WCO-01-object-id-enumeration-and-scraping/) for API endpoints walked after the docs were read.
