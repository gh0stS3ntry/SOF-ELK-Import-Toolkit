# WIA-03 Malformed, desynced and smuggled requests: unparsed request lines, ALB desync classifications, CloudFront edge errors, 400/414/431/505 bursts, per client

| | |
|---|---|
| Tactic | TA0001 Initial Access |
| ATT&CK | T1190 Exploit Public-Facing Application, T1595.002 Vulnerability Scanning |
| OWASP WSTG | WSTG-INJT-16 HTTP Request Smuggling, WSTG-INJT-15 HTTP Response Splitting, WSTG-CONF-16 Web Cache Poisoning |
| Indexes | `httpdlog-*` |
| Needs | web access logs in `httpdlog-*`: ALB/ELB (`alb2sofelk.py`), CloudFront (`cloudfrontaccess2sofelk.py`), Apache/nginx/lighttpd (`httpd2sofelk.py`) |
| Applies to | applications behind an ALB, ELB or CloudFront first; any web server for unparsed request lines |

**What it finds.** Clients that sent requests the server or load balancer could not parse or classified as dangerous: request lines the importer kept only as `sof-elk.rawrequest` (binary, TLS on a plain HTTP port, broken framing), ALB HTTP desync mitigation `Ambiguous` and `Severe` classifications with their reason codes, CloudFront `Error` edge results, unusual HTTP versions, and bursts of 400/405/408/411/413/414/431/501/505. Scored: Severe +4, Ambiguous +2, unparsed +2, odd version +1, 20 or more bad-status answers +1, 20 or more CloudFront errors +1.

**Reading the output.** A `Severe` classification is a request ALB considers a smuggling risk (conflicting `Content-Length`/`Transfer-Encoding`, bad header characters); `desync_reasons` gives AWS's code. Several Ambiguous or Severe requests from one client, followed by odd responses to other clients at the same time, point at smuggling or cache poisoning. Unparsed request lines from scanners (`\x16\x03\x01` TLS hellos, SSH banners) are noise; long ones with headers inside them are not. Request smuggling leaves little in access logs by design: this check shows the attempts, not their success.

**If it errors or looks empty.** `httpdlog-*` also matches SOF-ELK's own `httpdlog-YYYY.MM` indexes when web logs went through its Logstash pipeline; their strings are `text`, the toolkit's `keyword`. If ES|QL reports a type conflict, name the toolkit indexes instead (`FROM httpdlog-web01, httpdlog-123456789012`). The `aws.elb.*` and `aws.cloudfront.*` columns exist only when ALB or CloudFront logs were loaded. `SOF-ELK_RunChecklists.py` reads them as empty when they are missing. By hand, add `| EVAL `aws.elb.classification` = TO_STRING(NULL)` (and the same for each column the error names) after `FROM`. No rows: no web logs were loaded, or nothing crossed the thresholds marked `// EDIT:`.

**Next.** [WIA-01](../../TA0001-initial-access/WIA-01-injection-classes-beyond-sqli-and-traversal/) for the same clients' payloads.
