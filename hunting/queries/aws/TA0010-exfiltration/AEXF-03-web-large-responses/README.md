# AEXF-03 Clients that pulled the most data from the web front end (ALB/ELB and other web servers)

| | |
|---|---|
| Tactic | TA0010 Exfiltration |
| ATT&CK | T1530 Data from Cloud Storage, T1567 Exfiltration Over Web Service |
| Indexes | `httpdlog-*` |
| Needs | web access logs with response sizes: ALB or Classic ELB (`alb2sofelk.py`), or other web servers in `httpdlog-*` |
| Applies to | internet-facing applications: behind an ALB or ELB, or on IIS/NGINX/Apache |

**What it finds.** Per client and index: megabytes sent back (`destination.bytes`, the response size, as in SOF-ELK's web log parsing), how many responses were 10 MB or larger and for which paths, compared with the median client of the same index.

**Reading the output.** Look for clients far above `median_mb` that pulled export, backup, report or API list endpoints, especially the same clients [AIA-04](../../TA0001-initial-access/AIA-04-web-exploitation-attempts/) flagged. A single large download of `/backup.zip` or `/.git/` content is a misconfiguration that was found; many medium responses walking an API with incrementing IDs is scraping (an IDOR).

**If it errors or looks empty.** `httpdlog-*` also matches SOF-ELK's own `httpdlog-YYYY.MM` indexes when web logs were loaded through its Logstash pipeline. Their string fields are `text` with a `.keyword` sub-field, where the toolkit's are `keyword`; if ES|QL reports a type conflict on one of the fields here, name the indexes instead (`FROM httpdlog-123456789012, httpdlog-web01`) or wrap the field in `TO_STRING()`. IIS writes `sc-bytes` only when that field is enabled in its logging settings.
