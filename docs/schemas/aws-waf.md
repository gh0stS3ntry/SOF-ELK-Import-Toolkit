# AWS WAF schema (`aws-waf-*`)

Loaded by `AWS/waf2sofelk.py`; template `AWS/index_templates/index-aws-waf.json`. Common fields: [aws-common.md](aws-common.md). `event.dataset` is `aws.waf`, `event.category` is `web`; `@timestamp` is `timestamp` (epoch milliseconds).

SOF-ELK has no WAF parser, so this schema is the toolkit's own: ECS where a field exists (the same `source.*`, `url.*`, `http.*` and `user_agent.*` names as the ALB index, so the two can be queried together), `aws.waf.*` for the rest.

| WAF log field | Field | Type | Notes |
|---|---|---|---|
| `formatVersion` | `aws.waf.format_version` | integer | |
| `webaclId` | `aws.waf.web_acl_id`, `aws.waf.web_acl_name` | keyword | the ARN also gives `cloud.region` (empty for CloudFront) and `cloud.account.id` |
| `action` | `aws.waf.action`, `event.action` (lower case) | keyword | `ALLOW`, `BLOCK`, `COUNT`, `CAPTCHA`, `CHALLENGE` |
| `terminatingRuleId` / `terminatingRuleType` | `aws.waf.terminating_rule_id` / `terminating_rule_type` | keyword | `Default_Action` when no rule decided |
| `terminatingRuleMatchDetails[]` | `aws.waf.terminating_rule_match.condition_type` / `location` / `matched_data` | keyword lists | whole array also in `aws.waf.flattened.terminating_rule_match_details` |
| `ruleGroupList[]` | `aws.waf.rule_group_ids`; terminating and non-terminating rule IDs into `aws.waf.matched_rule_ids` | keyword lists | whole array in `aws.waf.flattened.rule_group_list` |
| `nonTerminatingMatchingRules[]` (top level and in rule groups) | `aws.waf.non_terminating_rule_ids` (and `matched_rule_ids`) | keyword list | rules in Count mode |
| `rateBasedRuleList[]` | `aws.waf.rate_based_rule_names` | keyword list | |
| `labels[].name` | `aws.waf.labels` | keyword list | |
| `httpSourceName` / `httpSourceId` | `aws.waf.http_source_name` / `http_source_id` | keyword | `ALB`, `CF`, `APIGW`, `APPSYNC`, ... |
| `responseCodeSent` | `aws.waf.response_code_sent` | integer | custom block responses |
| `requestBodySize` / `requestBodySizeInspectedByWAF` | `aws.waf.request_body_size` / `request_body_size_inspected` | long | |
| `oversizeFields` | `aws.waf.oversize_fields` | keyword | |
| `captchaResponse.responseCode` / `challengeResponse.responseCode` | `aws.waf.captcha_response_code` / `challenge_response_code` | integer | whole objects in `aws.waf.flattened.*` |
| `httpRequest.clientIp` | `source.ip` | ip | |
| `httpRequest.country` | `source.geo.country_iso_code` | keyword | |
| `httpRequest.httpMethod` / `httpVersion` / `requestId` | `http.request.method` / `http.version` / `http.request.id` | keyword | `HTTP/` prefix removed from the version |
| `httpRequest.uri` / `args` / `fragment` / `scheme` / `host` | `url.path` / `url.query` / `url.fragment` / `url.scheme` / `url.domain` | keyword | `url.original` rebuilt from scheme, host, path and query; `url.extension` from the path |
| `httpRequest.headers[]` | `aws.waf.request.headers` (JSON text), `aws.waf.request.header_names` | keyword | `Host` → `url.domain` when `host` is absent, `User-Agent` → `user_agent.original`, `Referer` → `http.request.referrer`, `X-Forwarded-For` → `xff.ip` (SOF-ELK's httpd name) |
| `ja3Fingerprint` / `ja4Fingerprint` | `tls.client.ja3` / `tls.client.ja4` | keyword | |
| `requestHeadersInserted` | `aws.waf.flattened.request_headers_inserted` | keyword | |
| any other top-level field | `aws.waf.unmapped.<snake_case>` | keyword | |

## CSV input

Read as described in [CSV input](aws-common.md#csv-input). Athena `waf_logs` results carry `httprequest`, `labels`, `rulegrouplist`, `nonterminatingmatchingrules`, `ratebasedrulelist` and `terminatingrulematchdetails` as struct text or JSON; both are decoded into the native record. Logs Insights writes nested fields as `httpRequest.clientIp` and list items as `httpRequest.headers.0.name`, which are rebuilt into objects and lists. `timestamp` may be epoch milliseconds (as logged), epoch seconds or date text.
