# AWS log importers

Eight standalone importers that load AWS logs straight into SOF-ELK's Elasticsearch, without Logstash or Filebeat, with field names that follow SOF-ELK's own AWS parsing. They use only the Python standard library (3.9+) and the same retrying `_bulk` client as the Windows importers (`../Windows/common/sof_elk_es_client.py`), so keep `AWS/` and `Windows/` side by side.

| Script | Log type | Index | Field reference |
|---|---|---|---|
| `cloudtrail2sofelk.py` | AWS CloudTrail | `aws-cloudtrail-<source>` | [aws-cloudtrail.md](../docs/schemas/aws-cloudtrail.md) |
| `vpcflow2sofelk.py` | VPC Flow Logs | `aws-vpcflow-<source>` | [aws-vpcflow.md](../docs/schemas/aws-vpcflow.md) |
| `alb2sofelk.py` | Application Load Balancer and Classic ELB access logs | `httpdlog-<source>` | [aws-alb.md](../docs/schemas/aws-alb.md) |
| `cloudfrontaccess2sofelk.py` | CloudFront standard access logs | `httpdlog-<source>` | [aws-cloudfront.md](../docs/schemas/aws-cloudfront.md) |
| `waf2sofelk.py` | AWS WAF (v2) web ACL logs | `aws-waf-<source>` | [aws-waf.md](../docs/schemas/aws-waf.md) |
| `route53resolver2sofelk.py` | Route 53 Resolver query logs (DNS) | `aws-route53-<source>` | [aws-route53.md](../docs/schemas/aws-route53.md) |
| `securityhub2sofelk.py` | Security Hub findings (ASFF: GuardDuty, Inspector, Macie, Config, ...) | `aws-securityhub-<source>` | [aws-securityhub.md](../docs/schemas/aws-securityhub.md) |
| `eksaudit2sofelk.py` | Amazon EKS (Kubernetes) audit logs | `kubernetes-<source>` | [aws-eks.md](../docs/schemas/aws-eks.md) |

All but the ALB and CloudFront importers also read **Amazon Security Lake** exports (OCSF records, as JSON or Athena CSV): CloudTrail management and data events (S3, Lambda), VPC Flow Logs, Route 53 Resolver, WAF, Security Hub and EKS audit records are each mapped back to their native fields and indexed with the same schema as the native log. See [Amazon Security Lake](#amazon-security-lake) below.

Common fields, index names, document IDs and the CSV rules are in [aws-common.md](../docs/schemas/aws-common.md). Hunting queries for these indexes are in [`hunting/queries/aws/`](../hunting/queries/aws/), with checklists in [`hunting/checklists/`](../hunting/checklists/) (`aws-*.md`).

## Quick start

```bash
# Look first: parse everything, show two sample documents, send nothing
python3 AWS/cloudtrail2sofelk.py /cases/IR-42/AWSLogs/123456789012/CloudTrail --source 123456789012 --dry-run

# Load into the local SOF-ELK
python3 AWS/cloudtrail2sofelk.py /cases/IR-42/AWSLogs/123456789012/CloudTrail --source 123456789012 --case IR-42
python3 AWS/vpcflow2sofelk.py    /cases/IR-42/AWSLogs/123456789012/vpcflowlogs --source 123456789012
python3 AWS/alb2sofelk.py        /cases/IR-42/AWSLogs/123456789012/elasticloadbalancing --source 123456789012
python3 AWS/cloudfrontaccess2sofelk.py /cases/IR-42/cloudfront-logs --source 123456789012
python3 AWS/waf2sofelk.py        /cases/IR-42/waf --source 123456789012
python3 AWS/route53resolver2sofelk.py /cases/IR-42/AWSLogs/123456789012/vpcdnsquerylogs --source 123456789012
python3 AWS/securityhub2sofelk.py /cases/IR-42/securityhub --source 123456789012
python3 AWS/eksaudit2sofelk.py   /cases/IR-42/eks-audit --source prod-cluster

# Amazon Security Lake: an Athena CSV or JSON export holding several sources goes to each importer
python3 AWS/cloudtrail2sofelk.py /cases/IR-42/securitylake --source 123456789012 --dry-run

# Or let the wrapper find every AWS log type in one folder; the host name is the --source
python3 SOF-ELK_ImportWrapper.py /cases/IR-42/aws 123456789012 --case IR-42

# Kibana Data Views (aws-cloudtrail-*, aws-vpcflow-*, aws-waf-*, aws-route53-*, aws-securityhub-*), once;
# ALB, CloudFront and EKS audit logs use SOF-ELK's stock httpdlog-* and kubernetes-* views
python3 SOF-ELK_CreateDataViews.py
```

Each importer takes files or folders (searched recursively; `.gz` is read whether or not the name says so), keeps only the files that look like its log type, and reports the rest as skipped. Other files in the folder, binary ones included, are skipped rather than stopping the run, and CSVs with classic Mac (bare CR) line endings are read like any other. `--source` is required: it names the index (`aws-cloudtrail-<source>`) and is stored in `labels.evidence_source`. Use the account ID, or a label such as `prod` when one account has several evidence sets. Loading the same files again overwrites instead of duplicating.

The first run installs the component template `sofelk-toolkit-aws-common` and the index template for the log type (priority 200, so it wins over SOF-ELK's `aws-*` template). An existing index that was not made with the toolkit's template is refused rather than mixed.

EKS audit logs likewise go to SOF-ELK's `kubernetes-<source>` family, next to its own Kubernetes audit indexes ([aws-eks.md](../docs/schemas/aws-eks.md)).

ALB/ELB and CloudFront access logs go to `httpdlog-<source>`, SOF-ELK's web access log family, so they can be hunted together with IIS, NGINX and Apache access logs: one `FROM httpdlog-*` query covers all of them, and `event.dataset` (`aws.alb`, `aws.elb_classic`, `aws.cloudfront`) says which rows came from a load balancer or from CloudFront. ALB and CloudFront logs of the same account can share one `httpdlog-<source>` index. For that family the importer installs no index template (it would take over SOF-ELK's own `httpdlog-YYYY.MM` indexes); it creates `httpdlog-<source>` itself with the toolkit mapping. Give each web evidence source its own `--source` (the account ID for an ALB, the host name for a web server), so each lands in its own index.

## Inputs

### Native AWS formats

| Importer | Reads |
|---|---|
| CloudTrail | S3 delivery files (`{"Records": [...]}`); Event history JSON download; JSON Lines (one event per line, from CloudTrail Lake, `aws-cloudtrail2sof-elk.py` or similar); CloudWatch Logs exports with a timestamp before each event; `aws logs filter-log-events` output. Digest files are skipped. |
| VPC Flow | S3 text delivery with its header line, for any record version (2 to 8) and custom formats; CloudWatch Logs exports without a header (default v2 format, or `--fields 'version account-id ...'` for a custom format); `filter-log-events` and subscription JSON. |
| ALB | ALB and Classic ELB access logs as AWS writes them, one request per line. Network Load Balancer logs and ALB connection logs are a different format and are reported as skipped. |
| CloudFront | Standard access logs as delivered to S3 (`<DistributionID>.YYYY-MM-DD-HH.<id>.gz`): W3C `#Version`/`#Fields` header and one tab-separated request per line. Columns are read from the `#Fields` line, so 24-, 26- and 33-field files and fields AWS adds later all load; a file with its header cut off is read in the documented order. Real-time logs and standard logging v2 JSON/Parquet output are not read. |
| WAF | S3 or Firehose delivery: JSON objects one per line or concatenated; CloudWatch Logs exports; `filter-log-events` and subscription JSON. |
| Route 53 Resolver | Query logs delivered to S3 or exported from CloudWatch Logs (JSON per line, optionally timestamp-prefixed); `filter-log-events` and subscription JSON. |
| Security Hub | `aws securityhub get-findings` output, EventBridge "Findings - Imported" events, a JSON array or one finding per line. |
| EKS audit | CloudWatch Logs exports of `/aws/eks/<cluster>/cluster` `kube-apiserver-audit-*` streams (JSON per line, optionally timestamp-prefixed); `filter-log-events` output; JSON arrays and `EventList` objects. |

### Amazon Security Lake

Security Lake stores logs as OCSF records in Parquet. Query them with Athena and download the result as CSV, or export them as JSON (one record per line, or an array); the importers cannot read Parquet. A record is recognised by its OCSF fields (`class_uid` with `metadata.product.name` or `asl_version`), both for Security Lake v1 (OCSF 1.0.0-rc.2) and v2 (`asl_version` `2_0`, OCSF 1.1.0), and goes to the importer of its source:

| Security Lake source | Importer | Index |
|---|---|---|
| CloudTrail management events, S3 and Lambda data events | `cloudtrail2sofelk.py` | `aws-cloudtrail-<source>` |
| VPC Flow Logs | `vpcflow2sofelk.py` | `aws-vpcflow-<source>` |
| Route 53 Resolver query logs | `route53resolver2sofelk.py` | `aws-route53-<source>` |
| AWS WAF logs | `waf2sofelk.py` | `aws-waf-<source>` |
| Security Hub findings | `securityhub2sofelk.py` | `aws-securityhub-<source>` |
| EKS audit logs | `eksaudit2sofelk.py` | `kubernetes-<source>` |

An export holding several sources (a lake-wide export, or a `UNION` query) can be given to each importer: each loads its own records and reports the others as skipped, naming the importer that loads them. The wrapper does this for you. Every Security Lake document also carries `aws.securitylake.*` (OCSF class, version, product). The field mapping is in [aws-securitylake.md](../docs/schemas/aws-securitylake.md).

### Logs already converted to CSV

Every importer also reads CSV (comma, tab, semicolon or pipe separated), and maps it to the same fields as the native format:

| Importer | CSV shapes |
|---|---|
| CloudTrail | Event history CSV download, with or without the `CloudTrail event` column; Athena and CloudTrail Lake query results (`useridentity` as struct text or JSON, `requestparameters` as JSON text); flattened exports with dotted columns (`userIdentity.arn`); a raw-JSON column (`@message`, `_raw`). |
| VPC Flow | Athena results (`account_id`, `log_status`); Logs Insights exports (`srcAddr`, `dstPort`, `logStatus`, or only `@message`); spreadsheet exports with descriptive headers (`Source address`, `Start time`). |
| ALB | Athena `alb_access_logs` results (`client_ip` + `client_port`, `request_verb` + `request_url` + `request_proto`) and `elb_logs` results for Classic ELB; native-name columns; a raw-line column. |
| CloudFront | Athena `cloudfront_standard_logs` results (`location`, `request_ip`, `uri`, `query_string`, `result_type`, `host_header`, ...); columns with the W3C names (`x-edge-location`, `cs-uri-stem`); a raw-line column. |
| WAF | Athena `waf_logs` results (`httprequest`, `labels` and the rule lists as struct text or JSON); Logs Insights flattened columns (`httpRequest.clientIp`, `httpRequest.headers.0.name`); a raw-JSON column. |
| Route 53 Resolver | Athena results over the query log table (`answers`, `srcids` as struct text or JSON); flattened columns (`srcids.instance`, `answers.0.Rdata`); a raw-JSON column. |
| Security Hub | A column holding the whole finding as JSON; flattened columns (`Severity.Label`, `Resources.0.Id`). |
| EKS audit | A raw-JSON column (Logs Insights `@message`); flattened columns (`objectRef.resource`, `user.username`). |

Column names are matched case-insensitively with separators ignored. Times may be ISO 8601, epoch seconds or milliseconds, or the form Excel writes when it re-saves a CSV (`10/20/2026 1:05:00 PM`, read as UTC; add `--date-order dmy` for day/month). A CSV that Excel has re-saved has usually lost the seconds, so prefer the original export when exact times matter. The details are in [aws-common.md](../docs/schemas/aws-common.md#csv-input).

## Options

All eight importers share these options; `vpcflow2sofelk.py` adds `--fields`.

| Option | Meaning |
|---|---|
| `--source NAME` | evidence source label (required), used in the index name |
| `--case ID` | case ID added to every document as `case` |
| `--index NAME` | another index name; must end in `-<source>` |
| `--es URL` | Elasticsearch URL (default `http://localhost:9200`) |
| `--user`, `--password`, `--insecure` | authentication and TLS, as for the Windows importers |
| `--batch-size N` | documents per `_bulk` request |
| `--dry-run`, `--sample-docs N` | parse and show sample documents without sending |
| `--date-order mdy\|dmy` | day/month order of spreadsheet-style dates in CSV |
| `--max-retries`, `--retry-backoff`, `--timeout`, `--log-file` | retry and logging behaviour of the shared client (see the top-level README) |

## Assumptions and limits

- Field names follow SOF-ELK's parsers: `configfiles/6901-aws.conf` for CloudTrail, `2050-netflow.conf` for VPC Flow, `6100-httpd.conf` and `8004-postprocess-httpd.conf` for ELB and CloudFront (SOF-ELK has no CloudFront parser; its web field names are used, with `aws.cloudfront.*` for the rest), `6014-passivedns.conf` for Route 53 Resolver, `6952-kubernetes.conf` for EKS audit. SOF-ELK has no WAF or Security Hub parser, so `aws.waf.*` and `aws.securityhub.*` are the toolkit's own schemas. Each field page lists where the toolkit differs from SOF-ELK (for example, account IDs are keywords rather than numbers, so leading zeros survive).
- VPC Flow documents go to `aws-vpcflow-*`, not SOF-ELK's `netflow-*`, so they can carry the AWS-specific fields; the shared field names mean NetFlow-style queries still work on them.
- EKS audit logs go to SOF-ELK's `kubernetes-*` family, like ALB logs to `httpdlog-*`: no index template is installed (it would take over SOF-ELK's own monthly indexes), and the importer creates `kubernetes-<source>` itself.
- Amazon Security Lake fills OCSF fields from the native record and drops some of it (most VPC Flow custom fields, WAF rule-group details); load the native logs when you need those.
- VPC Flow Logs and Security Lake data delivered as Parquet are not read (that needs a library outside the standard library). Choose text delivery, or convert with Athena and load the CSV result.
- NLB access logs, ALB connection logs and CloudFront real-time logs are not loaded.
- The CSV shapes above were built from the AWS and Athena documentation and tested with synthetic exports; a CSV from another tool may name its columns differently. Run `--dry-run` first: unmatched columns show up under `<namespace>.unmapped.*` in the sample documents.

## Tests

```bash
python3 AWS/tests/test_aws_importers.py -v
python3 tests/test_import_wrapper_aws.py -v   # wrapper discovery and command lines
```

The tests need no Elasticsearch. They parse every fixture in `tests/fixtures/<log>/` (native formats) and `tests/fixtures/<log>/csv/` (CSV conversions), plain and gzip-compressed, and check every document against its index template so that no field is silently dropped by the `dynamic: false` mapping. The fixtures are synthetic and dated 2026-10-20.
