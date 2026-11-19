# Amazon CloudFront access log schema (`httpdlog-<source>`)

Loaded by `AWS/cloudfrontaccess2sofelk.py` into `httpdlog-<source>`, SOF-ELK's web access log family, so CloudFront requests can be hunted together with ALB/ELB, IIS, NGINX and Apache logs in `httpdlog-*`. Mapping: `AWS/index_templates/index-httpdlog.json` (shared with the ALB importer), applied when the importer creates the index. No index template is installed, so SOF-ELK's own `httpdlog-YYYY.MM` indexes keep SOF-ELK's template (see [aws-common.md](aws-common.md#index-names)). Common fields: [aws-common.md](aws-common.md). `event.dataset` is `aws.cloudfront`; `event.category` is `web`.

SOF-ELK has no CloudFront parser. The names follow SOF-ELK's web log parsing (the IIS/W3C grok in `configfiles/6100-httpd.conf` and `8004-postprocess-httpd.conf`), as the ALB importer does, so the same `httpdlog-*` queries work on both. CloudFront-only values go under `aws.cloudfront.*`. `-` values are left out.

## Input

These are standard (legacy) access logs, as CloudFront delivers them to S3: one gzip file per distribution and hour, named `<DistributionID>.YYYY-MM-DD-HH.<unique>.gz`, in W3C extended format:

```
#Version: 1.0
#Fields: date time x-edge-location sc-bytes c-ip cs-method cs(Host) cs-uri-stem sc-status ...
2026-10-20	01:05:10	IAD89-C1	48211	198.51.100.23	POST	d111111abcdef8.cloudfront.net	/api/upload.jsp	200 ...
```

- **Columns come from the `#Fields` line.** Positions are not assumed, so files written before AWS added fields (24 or 26 columns), today's 33 columns, and fields added later all load. A `#Fields` line in the middle of a file (hourly files concatenated with `cat` or `zcat`) switches to that line's columns.
- **Files with the header cut off** are read in the documented field order.
- **File names don't matter.** Detection uses the `#Fields` line (it must name `x-edge-*` fields) or, without a header, the shape of the first line (date, time, edge location, tab-separated). A `.gz` file is recognised by its content, not its name.

## Fields

| Log field | Field | Type | Notes |
|---|---|---|---|
| `date` + `time` | `@timestamp` | date | UTC. A Logs Insights `timestamp` column is used only when date and time are missing |
| `x-edge-location` | `aws.cloudfront.edge_location` | keyword | edge POP; the first three letters are an IATA airport code |
| `sc-bytes` | `destination.bytes` | long | bytes sent to the viewer (response), as `sent_bytes` for ALB and `sc-bytes` for IIS |
| `c-ip` | `source.ip` | ip | the viewer, or the last proxy in front of CloudFront |
| `cs-method` | `http.request.method` | keyword | |
| `cs(Host)` | `aws.cloudfront.distribution_domain` | keyword | `dxxxx.cloudfront.net` |
| `cs-uri-stem` | `url.path`, `url.extension` | keyword | as logged (not decoded) |
| `sc-status` | `http.response.status_code` | short | `0` (logged as `000`) means the viewer closed the connection before the response |
| `cs(Referer)` | `http.request.referrer` | keyword | URL-decoded once |
| `cs(User-Agent)` | `user_agent.original` | keyword | URL-decoded once (`Mozilla/5.0%20(X11...` becomes `Mozilla/5.0 (X11...`) |
| `cs-uri-query` | `url.query` | keyword | as logged (not decoded) |
| `cs(Cookie)` | `http.request.cookie` | keyword | only logged when cookie logging is on |
| `x-edge-result-type` | `aws.cloudfront.edge_result_type` | keyword | `Hit`, `RefreshHit`, `Miss`, `LimitExceeded`, `CapacityExceeded`, `Error`, `Redirect` |
| `x-edge-request-id` | `aws.cloudfront.request_id` | keyword | also the document ID key, so reloading overwrites |
| `x-host-header` | `url.domain` | keyword | the host the viewer asked for (your CNAME); falls back to `cs(Host)` |
| `cs-protocol` | `url.scheme` | keyword | `http`, `https`, `ws`, `wss` |
| (built) | `url.original` | keyword | `<scheme>://<url.domain><url.path>[?<url.query>]` |
| `cs-bytes` | `source.bytes` | long | bytes received from the viewer (request) |
| `time-taken` | `event.duration`, `aws.cloudfront.time_taken.sec` | long / double | nanoseconds (SOF-ELK convention) and the logged seconds |
| `x-forwarded-for` | `xff.ip`, `aws.cloudfront.x_forwarded_for` | ip list / keyword | every valid IP in the header, plus the decoded header as logged; SOF-ELK's IIS grok uses `xff.ip` too |
| `ssl-protocol` / `ssl-cipher` | `tls.protocol` / `tls.cipher` | keyword | |
| `x-edge-response-result-type` | `aws.cloudfront.edge_response_result_type` | keyword | |
| `cs-protocol-version` | `http.version` | keyword | `HTTP/2.0` is stored as `2.0`, like ALB's `1.1` |
| `fle-status`, `fle-encrypted-fields` | `aws.cloudfront.fle_status`, `fle_encrypted_fields` | keyword / integer | field-level encryption |
| `c-port` | `source.port` | integer | |
| `time-to-first-byte` | `aws.cloudfront.time_to_first_byte.sec` | double | |
| `x-edge-detailed-result-type` | `aws.cloudfront.edge_detailed_result_type` | keyword | for example `OriginShieldHit`, `ClientCommError`, `AbortedOrigin` |
| `sc-content-type` | `http.response.mime_type` | keyword | ECS |
| `sc-content-len` | `http.response.body.bytes` | long | ECS |
| `sc-range-start` / `sc-range-end` | `aws.cloudfront.range_start` / `range_end` | long | byte-range requests (status 206) |
| (file name) | `aws.cloudfront.distribution_id` | keyword | from `<DistributionID>.YYYY-MM-DD-HH...`, or a `DistributionId` column |
| any other field | `aws.cloudfront.unmapped.<name>` | keyword | fields AWS adds later, by their `#Fields` name (`c-country` becomes `c_country`) |
| unreadable values | `aws.cloudfront.malformed` | keyword list | `field=value` |

`cloud.account.id` is filled only when the path has the `AWSLogs/<account>/` layout (CloudFront itself doesn't write one), and `cloud.region` stays empty, because CloudFront is a global service. `--source` names the index, and is usually the account ID or a site name.

## CSV input

Read as described in [CSV input](aws-common.md#csv-input):

- **Athena `cloudfront_standard_logs` results.** The table's column names are mapped back: `location`, `bytes`, `request_ip`, `method`, `host`, `uri`, `status`, `referrer`, `user_agent`, `query_string`, `cookie`, `result_type`, `request_id`, `host_header`, `request_protocol`, `request_bytes`, `time_taken`, `xforwarded_for`, `ssl_protocol`, `ssl_cipher`, `response_result_type`, `http_version`, `fle_status`, `fle_encrypted_fields`, `c_port`, `time_to_first_byte`, `x_edge_detailed_result_type`, `sc_content_type`, `sc_content_len`, `sc_range_start`, `sc_range_end`. Partition columns (`year`, `month`, `day`, `hour`, `dt`) are ignored.
- **Exports with the W3C names as columns** (`x-edge-location`, `cs-uri-stem`, ...). Dates that Excel re-saved (`10/20/2026` with `5:15:00 AM`) are read with `--date-order`.
- **A column holding the raw log line** (Logs Insights `@message`, `_raw`), read in the documented field order.

## Not read

- CloudFront **real-time logs** (Kinesis Data Streams). The fields are chosen per configuration and the lines have no header.
- **Standard logging v2** output in JSON or Parquet (to CloudWatch Logs, Firehose or S3). v2 output in the W3C text format to S3 should read like the legacy logs, with its extra fields under `aws.cloudfront.unmapped.*`, but it has not been tested.
