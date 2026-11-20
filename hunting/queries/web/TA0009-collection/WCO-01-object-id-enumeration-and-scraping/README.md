# WCO-01 Object ID enumeration and scraping (IDOR / BOLA): one client walking many object IDs on the same endpoint, compared with the other clients of that endpoint

| | |
|---|---|
| Tactic | TA0009 Collection |
| ATT&CK | T1213 Data from Information Repositories, T1119 Automated Collection |
| OWASP WSTG | WSTG-ATHZ-04 Insecure Direct Object References, WSTG-APIT-02 Broken Object Level Authorization, WSTG-APIT-03 Excessive Data Exposure, WSTG-BUSL-05 |
| Indexes | `httpdlog-*` |
| Needs | web access logs in `httpdlog-*`: ALB/ELB (`alb2sofelk.py`), CloudFront (`cloudfrontaccess2sofelk.py`), IIS (`iisgeolocate2sofelk.py`), Apache/nginx/lighttpd (`httpd2sofelk.py`) |
| Applies to | web applications and APIs that address records by ID (accounts, orders, invoices, documents) |

**What it finds.** Every path is reduced to an endpoint template (numbers, long hex strings and UUIDs replaced, so `/api/users/1017` and `/api/users/1018` are both `/api/users/{n}`); requests with a digit in the query string count too. Per client, endpoint and method: how many distinct objects were requested, how many answered 2xx, 401/403 and 404, the bytes returned, and the speed. `median_objects` and `ratio` compare the client with everyone else on that endpoint. Rows need 50 or more objects. Scored: 10 times the median +2, 50 or more 2xx +2, a mix of 2xx and 401/403 +2 (authorization enforced for some objects, not others), mostly 404 +1 (guessing IDs), a write method +2, 30 or more requests per minute +1.

**Reading the output.** A customer reads their own handful of orders; a client reading thousands of sequential order IDs with 200s is scraping through an IDOR. `sample_objects` shows whether the IDs are sequential. Many 403s followed by 200s on other IDs is someone mapping which objects the authorization check misses. Crawlers and the application's own back-end jobs also walk IDs: check the user agent and whether the address belongs to the client. The data volume is in `mb_sent` (needs response sizes, see WTRI-01).

**If it errors or looks empty.** `httpdlog-*` also matches SOF-ELK's own `httpdlog-YYYY.MM` indexes when web logs went through its Logstash pipeline; their strings are `text`, the toolkit's `keyword`. If ES|QL reports a type conflict, name the toolkit indexes instead (`FROM httpdlog-web01, httpdlog-123456789012`). No rows: no web logs were loaded, or nothing crossed the thresholds marked `// EDIT:`.

**Next.** [AEXF-03](../../../aws/TA0010-exfiltration/AEXF-03-web-large-responses/) / [LEXF-03](../../../linux/TA0010-exfiltration/LEXF-03-large-transfers-served-by-web-and-ftp/) for the client's total data volume.
