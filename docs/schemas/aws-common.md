# AWS indexes: common fields and conventions

The four AWS importers in [`AWS/`](../../AWS/) share one engine (`AWS/sof_elk_aws_common.py`) and one component template:

| Template | File | Applies to |
|---|---|---|
| Component `sofelk-toolkit-aws-common` | `AWS/index_templates/component-toolkit-aws-common.json` | every AWS index |
| Index template `sofelk-toolkit-aws-cloudtrail` (priority 200) | `AWS/index_templates/index-aws-cloudtrail.json` | `aws-cloudtrail-*` ([fields](aws-cloudtrail.md)) |
| Index template `sofelk-toolkit-aws-vpcflow` (priority 200) | `AWS/index_templates/index-aws-vpcflow.json` | `aws-vpcflow-*` ([fields](aws-vpcflow.md)) |
| No index template: the importer creates each index with this mapping | `AWS/index_templates/index-httpdlog.json` | `httpdlog-<source>`, ALB/ELB access logs ([fields](aws-alb.md)) |
| Index template `sofelk-toolkit-aws-waf` (priority 200) | `AWS/index_templates/index-aws-waf.json` | `aws-waf-*` ([fields](aws-waf.md)) |

## Index names

One index per evidence source, `<prefix>-<source>`, where `<source>` is the `--source` label given on the command line (usually the AWS account ID, or a name such as `prod`), normalised the same way host names are: lower case, runs of other characters replaced by `-`. Examples: `aws-cloudtrail-123456789012`, `aws-vpcflow-prod`. `--index` may change the prefix but must still end in `-<source>`.

ALB/ELB access logs are the exception: they go to SOF-ELK's web access log family, `httpdlog-<source>` (for example `httpdlog-123456789012`), so they sit next to IIS, NGINX and Apache access logs and one `FROM httpdlog-*` query hunts across all of them; `event.dataset` (`aws.alb`, `aws.elb_classic`) tells them apart. No toolkit index template is installed for `httpdlog-*`, because one at priority 200 would also take over SOF-ELK's own `httpdlog-YYYY.MM` indexes and change their mapping. Instead the importer creates each `httpdlog-<source>` index itself with the mapping in `AWS/index_templates/index-httpdlog.json`, using SOF-ELK's types for the shared web fields (`http.response.status_code` is `short`, as in SOF-ELK's `httpdlog` template). A `--source` that looks like a month (`2026.10`) is refused, so the name cannot clash with SOF-ELK's monthly indexes.

The CloudTrail, VPC Flow and WAF prefixes start with `aws-`, so SOF-ELK's stock `aws-*` Data View shows them together, and each has its own Data View (`aws-cloudtrail-*`, ...) from `SOF-ELK_CreateDataViews.py`. SOF-ELK's own `aws` index template (pattern `aws-*`, priority 0) is overridden by the toolkit templates (priority 200) for these names. SOF-ELK's Logstash pipeline writes CloudTrail to `aws-YYYY.MM`, VPC Flow to `netflow-YYYY.MM` and ELB logs to `httpdlog-YYYY.MM`; the toolkit indexes use the same field names, so queries carry over. The ALB indexes share SOF-ELK's `httpdlog-*` pattern and Data View; the others are separate index families.

## Fields every AWS document has

| Field | Type | Content |
|---|---|---|
| `@timestamp` | date | the record's own event time (CloudTrail `eventTime`, flow `start`, ALB `time`, WAF `timestamp`) |
| `labels.evidence_source` | keyword | the `--source` label |
| `case` | keyword | `--case`, when given |
| `event.dataset` | keyword | `aws.cloudtrail`, `aws.vpcflow`, `aws.alb`, `aws.elb_classic`, `aws.waf` |
| `event.kind`, `event.category`, `event.action`, `event.outcome` | keyword | ECS categorisation where it applies (see each log type) |
| `cloud.provider` | keyword | `aws` |
| `cloud.account.id`, `cloud.region` | keyword | from the record; otherwise from an `AWSLogs/<account>/<service>/<region>/` path |
| `cloud.availability_zone` | keyword | VPC Flow `az-id` |
| `log.file.path` | keyword | input file, relative to the folder given on the command line |
| `log.offset` | long | record position within that file |

Strings are keyword (`ignore_above` 1024, or 8191 for long values); JSON objects kept whole (CloudTrail `requestParameters`, WAF headers and rule lists) are keyword with a `.text` (`match_only_text`) sub-field. The root mapping is `dynamic: false`: a field the template does not define is kept in `_source` but not indexed. Fields the parser does not know go to `<namespace>.unmapped.*` (dynamic, keyword), and values that do not fit their type go to `<namespace>.malformed` as `name=value` text.

## Document IDs and re-runs

CloudTrail documents use the record's `eventID`, so the same event loaded from two files (an S3 copy and a CloudWatch export) is stored once. VPC Flow and ALB documents use the record line, numbered when the identical line occurs more than once; WAF documents use web ACL + request ID + timestamp. Loading the same files again overwrites instead of duplicating.

The ID of a VPC Flow or ALB record read from CSV is built from its column values, not from the original log line, so loading both the native log and a CSV conversion of it into the same index stores each record twice. Load one or the other. CloudTrail (by `eventID`) and WAF (by request ID) do not have this problem.

## CSV input

Every importer also reads logs that were already converted to CSV, and maps them to the same fields as the native format. The delimiter (comma, tab, semicolon or pipe) is detected from the header row, and column names are matched case-insensitively with separators ignored, so `account_id`, `accountId` and `Account ID` are the same column.

| Shape | Examples | How it is read |
|---|---|---|
| A column holding the whole record | CloudWatch Logs Insights `@message`, Splunk `_raw`, Event history `CloudTrail event` | parsed as the native JSON record or log line |
| Native field names, any case | Athena results (`useridentity`, `log_status`, `client_ip`), Logs Insights fields (`srcAddr`, `httpRequest.clientIp`) | columns map to the record's fields; dotted (`userIdentity.arn`) or slashed names build the nested object, and numbered parts (`httpRequest.headers.0.name`) build lists |
| Descriptive export headers | Event history summary (`Event name`, `User name`, `AWS access key`), spreadsheet exports (`Source address`, `Start time`) | a per-importer alias list (see each log type's page) |

Cell values that are JSON, or Athena/Presto struct text such as `{type=IAMUser, arn=arn:aws:iam::1:user/a, sessioncontext={...}}` and `[{name=Host, value=shop.example.com}]`, are decoded into objects. Struct text has no quoting, so a value containing `, key=` is split wrongly; JSON output from Athena (`CAST(... AS JSON)`) avoids that. Empty cells and `null` are left out. Columns starting with `@` (Logs Insights `@timestamp`, `@ptr`, `@logStream`) are ignored, except `@message`. Columns that match nothing go to `<namespace>.unmapped.*`.

Times may be ISO 8601, epoch seconds or milliseconds, or the spreadsheet form Excel writes when it re-saves a CSV (`10/20/2026 1:05:00 PM`). The spreadsheet form has no time zone (read as UTC) and Excel often drops the seconds; `--date-order dmy` reads it as day/month for a European locale. The importer prints how many such dates it read, as a reminder to re-export from the source when exact times matter.
