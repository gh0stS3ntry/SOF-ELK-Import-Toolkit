# AWS ALB / Classic ELB access log schema (`httpdlog-<source>`)

Loaded by `AWS/alb2sofelk.py` into `httpdlog-<source>`, SOF-ELK's web access log family, so ALB requests can be hunted together with IIS, NGINX and Apache logs in `httpdlog-*`. Mapping: `AWS/index_templates/index-httpdlog.json`, applied when the importer creates the index (no index template is installed, so SOF-ELK's own `httpdlog-YYYY.MM` indexes keep SOF-ELK's template; see [aws-common.md](aws-common.md#index-names)). Common fields: [aws-common.md](aws-common.md). `event.dataset` is `aws.alb` (Application Load Balancer) or `aws.elb_classic`; `event.category` is `web`; `@timestamp` is `time`.

Names follow SOF-ELK's ELB grok in `configfiles/6100-httpd.conf` and the clean-up in `8004-postprocess-httpd.conf`. `-` values are left out.

| Log field (position) | Field | Type | Notes |
|---|---|---|---|
| `type` (ALB) | `aws.elb.type` | keyword | `http`, `https`, `h2`, `grpcs`, `ws`, `wss`; not in SOF-ELK |
| `time` | `@timestamp` | date | |
| `elb` | `aws.elb.name` | keyword | `app/<name>/<id>` |
| `client:port` | `source.ip`, `source.port` | ip / integer | |
| `target:port` (`backend:port` on CLB) | `backend.ip`, `backend.port` | ip / integer | SOF-ELK's non-ECS `backend.*` |
| `request_processing_time` | `aws.elb.request_processing_time.sec` | double | `-1` when the request never reached a target |
| `target_processing_time` (`backend_processing_time`) | `aws.elb.backend_processing_time.sec` | double | |
| `response_processing_time` | `aws.elb.response_processing_time.sec` | double | |
| `elb_status_code` | `http.response.status_code` | short | `short`, as in SOF-ELK's `httpdlog` template |
| `target_status_code` (`backend_status_code`) | `aws.elb.backend.http.response.status_code` | integer | |
| `received_bytes` / `sent_bytes` | `source.bytes` / `destination.bytes` | long | |
| `request` | `http.request.method`, `url.original`, `url.scheme`, `url.domain`, `destination.port`, `url.path`, `url.query`, `url.extension`, `http.version` | | unparseable request lines go to `sof-elk.rawrequest`, as SOF-ELK |
| `user_agent` | `user_agent.original` | keyword | |
| `ssl_cipher` / `ssl_protocol` | `tls.cipher` / `tls.protocol` | keyword | |
| `target_group_arn` | `aws.elb.target_group.arn` | keyword | also gives `cloud.region` and `cloud.account.id` |
| `trace_id`, `domain_name`, `chosen_cert_arn` | `aws.elb.trace_id`, `domain_name`, `chosen_cert_arn` | keyword | |
| `matched_rule_priority` | `aws.elb.matched_rule_priority` | integer | |
| `request_creation_time` | `aws.elb.request_creation_time` | date | |
| `actions_executed` | `aws.elb.action_executed` | keyword list | split on `,` |
| `redirect_url`, `error_reason` | `aws.elb.redirect_url`, `aws.elb.error.reason` | keyword | |
| `target:port_list` / `target_status_code_list` | `aws.elb.target_port` / `aws.elb.target_status_code` | keyword list | split on spaces |
| `classification`, `classification_reason` | `aws.elb.classification`, `classification_reason` | keyword | desync mitigation |
| `conn_trace_id` | `aws.elb.conn_trace_id` | keyword | |
| `transformed_host`, `transformed_uri`, `request_transform_status` | `aws.elb.transformed_host`, `transformed_uri`, `request_transform_status` | keyword | added by AWS after SOF-ELK's grok; not in SOF-ELK |
| fields AWS adds later | `aws.elb.unmapped.field_<n>` | keyword | by position |

Network Load Balancer (TLS) logs and ALB connection logs have different layouts; their lines are reported as skipped.

## CSV input

Read as described in [CSV input](aws-common.md#csv-input). The Athena `alb_access_logs` table splits fields that the log keeps together, and the importer joins them back: `client_ip` + `client_port` to `client:port`, `target_ip` + `target_port` to `target:port`, `request_verb` + `request_url` + `request_proto` to `request`. `lambda_error_reason` maps to `error_reason` and `target_port_list` to `target:port_list`. The Classic ELB table (`elb_logs`: `request_timestamp`, `elb_name`, `request_ip`, `backend_ip`, `elb_response_code`, `backend_response_code`, `client_response_time`, `url`, `protocol`) is recognised by its backend columns and indexed as `aws.elb_classic`. Columns with the native names (`client:port`, `request`) and a raw-line column (`@message`) work too.
