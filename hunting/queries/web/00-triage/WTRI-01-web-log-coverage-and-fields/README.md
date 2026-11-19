# WTRI-01 Web access log coverage per index and source: time range, status mix and which fields are filled

| | |
|---|---|
| Tactic | Triage (first cut) |
| ATT&CK | n/a |
| OWASP WSTG | WSTG-INFO-02, WSTG-INFO-10 (what the logs can and cannot show) |
| Indexes | `httpdlog-*` |
| Needs | web access logs in `httpdlog-*`: ALB/ELB (`alb2sofelk.py`), CloudFront (`cloudfrontaccess2sofelk.py`), Apache/nginx/lighttpd (`httpd2sofelk.py`) |
| Applies to | every web evidence source; run before the other web checks |

**What it finds.** One row per `httpdlog-*` index and `event.dataset` (`aws.alb`, `aws.elb_classic`, `aws.cloudfront`, `apache.access`, `nginx.access`, ...): the time range, client count, 2xx/3xx/4xx/5xx counts, and how many events have a method, path, query string, user agent, referrer, request and response size, plus request lines the importer could not parse (`unparsed_requests`).

**Reading the output.** Compare `first_seen`/`last_seen` with the incident window; logs that stop early were rotated or deleted. The `with_*` columns decide which checks can work: WIA-01 and WCA-02 need `with_query`, AEXF-03/LEXF-03 need `with_response_bytes`, WCA-01's user column needs HTTP authentication in Apache/nginx logs. Error-log datasets (`*.error`) appear with no status codes; the other web checks skip them.

**If it errors or looks empty.** `httpdlog-*` also matches SOF-ELK's own `httpdlog-YYYY.MM` indexes when web logs went through its Logstash pipeline; their strings are `text`, the toolkit's `keyword`. If ES|QL reports a type conflict, name the toolkit indexes instead (`FROM httpdlog-web01, httpdlog-123456789012`). No rows: no web logs were loaded, or nothing crossed the thresholds marked `// EDIT:`.

**Next.** [WIA-01](../../TA0001-initial-access/WIA-01-injection-classes-beyond-sqli-and-traversal/) onwards, as the [web access log checklist](../../../../checklists/web-access-logs.md) orders them.
