# AWS log importers

Four standalone importers that load AWS logs straight into SOF-ELK's Elasticsearch, without Logstash or Filebeat, with field names that follow SOF-ELK's own AWS parsing. They use only the Python standard library (3.9+) and the same retrying `_bulk` client as the Windows importers (`../Windows/common/sof_elk_es_client.py`), so keep `AWS/` and `Windows/` side by side.

| Script | Log type | Index | Field reference |
|---|---|---|---|
| `cloudtrail2sofelk.py` | AWS CloudTrail | `aws-cloudtrail-<source>` | [aws-cloudtrail.md](../docs/schemas/aws-cloudtrail.md) |
| `vpcflow2sofelk.py` | VPC Flow Logs | `aws-vpcflow-<source>` | [aws-vpcflow.md](../docs/schemas/aws-vpcflow.md) |
| `alb2sofelk.py` | Application Load Balancer and Classic ELB access logs | `aws-alb-<source>` | [aws-alb.md](../docs/schemas/aws-alb.md) |
| `waf2sofelk.py` | AWS WAF (v2) web ACL logs | `aws-waf-<source>` | [aws-waf.md](../docs/schemas/aws-waf.md) |

Common fields, index names, document IDs and the CSV rules are in [aws-common.md](../docs/schemas/aws-common.md). Hunting queries for these indexes are in [`hunting/queries/aws/`](../hunting/queries/aws/), with checklists in [`hunting/checklists/`](../hunting/checklists/) (`aws-*.md`).

## Quick start

```bash
# Look first: parse everything, show two sample documents, send nothing
python3 AWS/cloudtrail2sofelk.py /cases/IR-42/AWSLogs/123456789012/CloudTrail --source 123456789012 --dry-run

# Load into the local SOF-ELK
python3 AWS/cloudtrail2sofelk.py /cases/IR-42/AWSLogs/123456789012/CloudTrail --source 123456789012 --case IR-42
python3 AWS/vpcflow2sofelk.py    /cases/IR-42/AWSLogs/123456789012/vpcflowlogs --source 123456789012
python3 AWS/alb2sofelk.py        /cases/IR-42/AWSLogs/123456789012/elasticloadbalancing --source 123456789012
python3 AWS/waf2sofelk.py        /cases/IR-42/waf --source 123456789012

# Kibana Data Views (aws-cloudtrail-*, aws-vpcflow-*, aws-alb-*, aws-waf-*), once
python3 SOF-ELK_CreateDataViews.py
```

Each importer takes files or folders (searched recursively; `.gz` is read whether or not the name says so), keeps only the files that look like its log type, and reports the rest as skipped. `--source` is required: it names the index (`aws-cloudtrail-<source>`) and is stored in `labels.evidence_source`. Use the account ID, or a label such as `prod` when one account has several evidence sets. Loading the same files again overwrites instead of duplicating.

The first run installs the component template `sofelk-toolkit-aws-common` and the index template for the log type (priority 200, so it wins over SOF-ELK's `aws-*` template). An existing index that was not made with the toolkit's template is refused rather than mixed.

## Inputs

### Native AWS formats

| Importer | Reads |
|---|---|
| CloudTrail | S3 delivery files (`{"Records": [...]}`); Event history JSON download; JSON Lines (one event per line, from CloudTrail Lake, `aws-cloudtrail2sof-elk.py` or similar); CloudWatch Logs exports with a timestamp before each event; `aws logs filter-log-events` output. Digest files are skipped. |
| VPC Flow | S3 text delivery with its header line, for any record version (2 to 8) and custom formats; CloudWatch Logs exports without a header (default v2 format, or `--fields 'version account-id ...'` for a custom format); `filter-log-events` and subscription JSON. |
| ALB | ALB and Classic ELB access logs as AWS writes them, one request per line. Network Load Balancer logs and ALB connection logs are a different format and are reported as skipped. |
| WAF | S3 or Firehose delivery: JSON objects one per line or concatenated; CloudWatch Logs exports; `filter-log-events` and subscription JSON. |

### Logs already converted to CSV

Every importer also reads CSV (comma, tab, semicolon or pipe separated), and maps it to the same fields as the native format:

| Importer | CSV shapes |
|---|---|
| CloudTrail | Event history CSV download, with or without the `CloudTrail event` column; Athena and CloudTrail Lake query results (`useridentity` as struct text or JSON, `requestparameters` as JSON text); flattened exports with dotted columns (`userIdentity.arn`); a raw-JSON column (`@message`, `_raw`). |
| VPC Flow | Athena results (`account_id`, `log_status`); Logs Insights exports (`srcAddr`, `dstPort`, `logStatus`, or only `@message`); spreadsheet exports with descriptive headers (`Source address`, `Start time`). |
| ALB | Athena `alb_access_logs` results (`client_ip` + `client_port`, `request_verb` + `request_url` + `request_proto`) and `elb_logs` results for Classic ELB; native-name columns; a raw-line column. |
| WAF | Athena `waf_logs` results (`httprequest`, `labels` and the rule lists as struct text or JSON); Logs Insights flattened columns (`httpRequest.clientIp`, `httpRequest.headers.0.name`); a raw-JSON column. |

Column names are matched case-insensitively with separators ignored. Times may be ISO 8601, epoch seconds or milliseconds, or the form Excel writes when it re-saves a CSV (`10/20/2026 1:05:00 PM`, read as UTC; add `--date-order dmy` for day/month). A CSV that Excel has re-saved has usually lost the seconds, so prefer the original export when exact times matter. The details are in [aws-common.md](../docs/schemas/aws-common.md#csv-input).

## Options

All four importers share these options; `vpcflow2sofelk.py` adds `--fields`.

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

- Field names follow SOF-ELK's parsers: `configfiles/6901-aws.conf` for CloudTrail, `2050-netflow.conf` for VPC Flow, `6100-httpd.conf` and `8004-postprocess-httpd.conf` for ELB. SOF-ELK has no WAF parser, so `aws.waf.*` is the toolkit's own schema. Each field page lists where the toolkit differs from SOF-ELK (for example, account IDs are keywords rather than numbers, so leading zeros survive).
- VPC Flow documents go to `aws-vpcflow-*`, not SOF-ELK's `netflow-*`, so they can carry the AWS-specific fields; the shared field names mean NetFlow-style queries still work on them.
- VPC Flow Logs delivered as Parquet are not read (that needs a library outside the standard library). Choose text delivery, or convert with Athena and load the CSV result.
- NLB access logs and ALB connection logs are not loaded.
- The CSV shapes above were built from the AWS and Athena documentation and tested with synthetic exports; a CSV from another tool may name its columns differently. Run `--dry-run` first: unmatched columns show up under `<namespace>.unmapped.*` in the sample documents.

## Tests

```bash
python3 AWS/tests/test_aws_importers.py -v
```

The tests need no Elasticsearch. They parse every fixture in `tests/fixtures/<log>/` (native formats) and `tests/fixtures/<log>/csv/` (CSV conversions), plain and gzip-compressed, and check every document against its index template so that no field is silently dropped by the `dynamic: false` mapping. The fixtures are synthetic and dated 2026-10-20.
