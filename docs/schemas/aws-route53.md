# Route 53 Resolver query log schema (`aws-route53-*`)

Loaded by `AWS/route53resolver2sofelk.py`; template `AWS/index_templates/index-aws-route53.json`. Common fields: [aws-common.md](aws-common.md). `event.dataset` is `aws.route53`, `event.category` is `network`, `event.action` is `dns-query`; `@timestamp` is `query_timestamp`.

Field names follow SOF-ELK's own Route 53 parsing (`configfiles/6014-passivedns.conf`, which loads Resolver query logs into SOF-ELK's `logstash-*` indexes), so DNS queries written for SOF-ELK carry over. Where the toolkit differs:

- SOF-ELK writes one document per answer; here one query is one document, and the answers are lists (`dns.answers.data`, `.type`, `.class`).
- SOF-ELK writes each answer's type into `dns.question.type`; here the answer types are in `dns.answers.type`, and `dns.question.type` is always the query type.
- `dns.resolved_ip`, `dns.question.registered_domain` / `top_level_domain` / `subdomain` and the DNS Firewall fields are the toolkit's own additions.

| Query log field | Field | Type | Notes |
|---|---|---|---|
| `query_timestamp` | `@timestamp` | date | |
| `query_name` | `dns.question.name`, `aws.route53.query_name` | keyword | `dns.question.name` is lower case without the trailing dot; `aws.route53.query_name` is as logged |
| (derived) | `dns.question.registered_domain`, `top_level_domain`, `subdomain` | keyword | `www.evil.co.uk` → `evil.co.uk`, `co.uk`, `www`; a short list of two-label suffixes is known (`co.uk`, `com.au`, `amazonaws.com`, ...) |
| `query_type` / `query_class` | `dns.question.type` / `dns.question.class` | keyword | `A`, `AAAA`, `TXT`, ... / `IN` |
| `rcode` | `dns.response.code`, `event.outcome` | keyword | `NOERROR` is success, anything else failure |
| `answers[].Rdata` / `Type` / `Class` | `dns.answers.data` / `type` / `class` | keyword lists | trailing dot removed from names |
| `answers[].Rdata` that are addresses | `dns.answers.ip`, `dns.resolved_ip` | ip | `dns.resolved_ip` is the distinct, sorted list |
| `srcaddr` / `srcport` | `source.ip` / `source.port` | ip / integer | the instance or on-premises host that asked |
| `transport` | `network.transport` | keyword | lower case; `network.protocol` is `dns` |
| `account_id` | `aws.route53.account_id`, `cloud.account.id` | keyword | |
| `region` | `cloud.region` | keyword | |
| `vpc_id` | `aws.route53.vpc_id` | keyword | |
| `version` | `aws.route53.version` | keyword | |
| `srcids.instance` | `aws.route53.instance` | keyword | EC2 instance that asked |
| `srcids.resolver_endpoint` | `aws.route53.resolver_instance` | keyword | inbound Resolver endpoint (on-premises queries) |
| `resolver_network_interface` | `aws.route53.resolver_network_interface` | keyword | |
| `firewall_rule_action` | `aws.route53.firewall.rule_action`, `event.type` | keyword | `BLOCK` / `DENY` → `event.type: denied`, otherwise `allowed` |
| `firewall_rule_group_id` / `firewall_domain_list_id` / `firewall_protection` | `aws.route53.firewall.rule_group_id` / `domain_list_id` / `protection` | keyword | DNS Firewall |
| any other field | `aws.route53.unmapped.<snake_case>` | keyword | |

## Inputs

- Query logs delivered to S3 (`AWSLogs/<account>/vpcdnsquerylogs/<vpc>/...log.gz`) or exported from CloudWatch Logs: one JSON record per line, optionally with a timestamp in front.
- `aws logs filter-log-events` output and subscription JSON.
- [Amazon Security Lake](aws-securitylake.md) DNS Activity (class 4003) records, as JSON or Athena CSV.
- CSV: Athena results over the query log table (`answers` and `srcids` as struct text or JSON), Logs Insights or other flattened exports (`srcids.instance`, `answers.0.Rdata`), or a column holding the whole record (`@message`, `_raw`).

## Document IDs

A record has no unique ID, so the document ID is built from its time, name, type, source address and port, VPC, account and response code. Loading the same files again overwrites; two identical queries in the same millisecond from the same address and port are stored once.
