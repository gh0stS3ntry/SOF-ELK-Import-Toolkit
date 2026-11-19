# WIM-01 Request floods and server-error bursts per client and minute: application-layer DoS, ReDoS and fuzzing that breaks the application (5xx), rate limits hit (429)

| | |
|---|---|
| Tactic | TA0040 Impact |
| ATT&CK | T1499.002 Service Exhaustion Flood, T1499.003 Application Exhaustion Flood, T1499.004 Application or System Exploitation |
| OWASP WSTG | WSTG-INJT-28 Regular Expression Denial of Service, WSTG-ERRH-01 Improper Error Handling, WSTG-BUSL-05, WSTG-BUSL-07 |
| Indexes | `httpdlog-*` |
| Needs | web access logs in `httpdlog-*`: ALB/ELB (`alb2sofelk.py`), CloudFront (`cloudfrontaccess2sofelk.py`), Apache/nginx/lighttpd (`httpd2sofelk.py`) |
| Applies to | every web application; outages and slowdowns the client reported first |

**What it finds.** Requests per client per minute, against the median per-minute rate of all clients of that index. Rows are minutes with 300 or more requests, 20 or more 5xx answers, or 60 or more requests and 20 times the median. Per client: busy minutes, peak rate, total, 5xx answers and the paths that produced them, 429 answers. Scored on the peak (300/600 per minute), the peak against the median, 5xx volume (20/50), rate limiting and ten or more busy minutes.

**Reading the output.** A flood shows as a high `peak_rpm` from one or a few clients; a distributed flood shows as many rows with the same user agents in the same minutes (sort by `first_minute`). `paths_5xx` is often the more useful column: a handful of requests that each produce a 500 on one search or validation endpoint can be a ReDoS or an exploit being tuned, and the first 500 on a path that never failed before is worth a look in the application's error log (stack traces, WSTG-ERRH-02). Monitoring, load tests and the client's own batch jobs score too.

**If it errors or looks empty.** `httpdlog-*` also matches SOF-ELK's own `httpdlog-YYYY.MM` indexes when web logs went through its Logstash pipeline; their strings are `text`, the toolkit's `keyword`. If ES|QL reports a type conflict, name the toolkit indexes instead (`FROM httpdlog-web01, httpdlog-123456789012`). No rows: no web logs were loaded, or nothing crossed the thresholds marked `// EDIT:`.

**Next.** [WIA-01](../../TA0001-initial-access/WIA-01-injection-classes-beyond-sqli-and-traversal/) for the payloads of the clients that caused 5xx.
