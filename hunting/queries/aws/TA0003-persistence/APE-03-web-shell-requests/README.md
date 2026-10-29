# APE-03 Possible web shells: script pages reached by very few clients (ALB/ELB and other web servers)

| | |
|---|---|
| Tactic | TA0003 Persistence |
| ATT&CK | T1505.003 Web Shell |
| Indexes | `httpdlog-*` |
| Needs | web access logs: ALB or Classic ELB (`alb2sofelk.py`), or other web servers in `httpdlog-*` |
| Applies to | internet-facing applications: behind an ALB or ELB, or on IIS/NGINX/Apache |

**What it finds.** Script pages (`.php`, `.jsp`, `.aspx` and similar) that answered 2xx to at most three distinct clients. Scored: POST requests +2, a single client +1, ten or more requests +1, the script sits in an upload, image, cache or static folder +2.

**Reading the output.** A web shell is a page nobody but the attacker uses, usually POSTed to repeatedly, often in a folder where uploads land. Legitimate rarely used pages (health checks, admin consoles reached from one office address) score too; check `client_ips` against the client's ranges. Take a suspect path's `first_seen` to the file system of the targets: its creation time dates the compromise.

**If it errors or looks empty.** `httpdlog-*` also matches SOF-ELK's own `httpdlog-YYYY.MM` indexes when web logs were loaded through its Logstash pipeline. Their string fields are `text` with a `.keyword` sub-field, where the toolkit's are `keyword`; if ES|QL reports a type conflict on one of the fields here, name the indexes instead (`FROM httpdlog-123456789012, httpdlog-web01`) or wrap the field in `TO_STRING()`.

**Next.** [AIA-04](../../TA0001-initial-access/AIA-04-web-exploitation-attempts/) for how it got there.
