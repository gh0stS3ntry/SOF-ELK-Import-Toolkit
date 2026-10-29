# Checklist: AWS web application (ALB and WAF)

Internet-facing applications behind an Application Load Balancer or Classic ELB and protected by AWS WAF (`aws-waf-*`). ALB logs are loaded into `httpdlog-<source>`, next to any IIS, NGINX or Apache access logs in `httpdlog-*`, so rows 2.1, 3.1 and 3.2 hunt across all web front ends at once. Run [the account checklist](aws-account-control-plane.md) for the account as well. The usual questions: was the application exploited, did a web shell or stolen session follow, and how much data left through the front door.

## 1. Application profile

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 1.1 | Which load balancers and web ACLs were loaded, and for which time range | [ATRI-01](../queries/aws/00-triage/ATRI-01-aws-data-coverage/) | 1.2.3, 2.4 | One `_index` per evidence source; the load balancer names and web ACL names in the data; gaps in the time range. |
| 1.2 | What sits behind the load balancer, and what the WAF is set to block or count |  | 1.3.1 | Ask the client for the target groups, the application stack and versions, and which WAF rules are in Count mode. Count-mode rules log a match but let the request through. |

## 2. Exploitation attempts

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 2.1 | Exploitation attempts in the web access logs (ALB/ELB and other web servers), per client | [AIA-04](../queries/aws/TA0001-initial-access/AIA-04-web-exploitation-attempts/) | 2.4, 2.4.4 | SQL injection, path traversal, Log4Shell/JNDI, template injection and scanner user agents; the clients with the highest scores and the status codes they got (2xx after many 4xx matters). |
| 2.2 | WAF blocked clients, and what the same clients got through | [AIA-05](../queries/aws/TA0001-initial-access/AIA-05-waf-blocked-and-allowed-sources/) | 2.4, 2.4.4 | Clients blocked many times that also have ALLOW requests: the WAF caught some of the attack, not all. |
| 2.3 | WAF rules that matched but did not block | [AIA-06](../queries/aws/TA0001-initial-access/AIA-06-waf-count-mode-matches/) | 2.4 | Managed rules in Count mode and labels on allowed requests (SQLi, bad inputs, known bad IPs): those requests reached the application. |

## 3. Web shells and follow-on

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 3.1 | Script pages reached by very few clients | [APE-03](../queries/aws/TA0003-persistence/APE-03-web-shell-requests/) | 2.1.4 | `.php`, `.jsp`, `.aspx` paths requested by one or two clients, especially with POST and 200, and paths in upload folders. |
| 3.2 | Large responses per client | [AEXF-03](../queries/aws/TA0010-exfiltration/AEXF-03-web-large-responses/) | 2.4.7 | Clients that downloaded far more than others: data dumps, backups or export endpoints abused. |
| 3.3 | The targets' outbound traffic after the exploitation time | [AEXF-02](../queries/aws/TA0010-exfiltration/AEXF-02-vpc-large-outbound-transfers/), [AC2-01](../queries/aws/TA0011-command-and-control/AC2-01-vpc-beaconing/) | 2.4.7 | From the VPC flow logs: the target instances connecting out to new public addresses after row 2.1's timestamps (see [the VPC checklist](aws-vpc-network.md)). |

## Not covered by these queries

- Application logs on the targets (web server access and error logs, framework logs): the request body is not in ALB logs, and WAF logs carry headers but not the body.
- CloudFront and API Gateway access logs are not loaded by this toolkit. WAF logs from CloudFront or API Gateway web ACLs are (`http_source_name` says which).
- The ALB `client:port` is the real client only when nothing sits in front of the load balancer; behind CloudFront or another proxy, use the WAF `xff.ip` or the proxy's own logs.
- Network Load Balancer access logs and ALB connection logs are skipped by the importer.
