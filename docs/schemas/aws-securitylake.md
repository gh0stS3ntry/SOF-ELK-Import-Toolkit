# Amazon Security Lake (OCSF) input

Amazon Security Lake stores AWS logs in OCSF (Open Cybersecurity Schema Framework) form. The AWS importers read Security Lake records exported as JSON (one record per line, a JSON array, or Athena's JSON output) or as Athena CSV results, turn each one back into the native AWS record it came from, and index it with the same fields as that native log. So a CloudTrail event loaded from Security Lake and the same event loaded from the S3 trail end up as the same document (same `eventID`, same fields) in `aws-cloudtrail-<source>`.

Security Lake writes Parquet. The importers use only the Python standard library, so they cannot read Parquet: query the lake with Athena and download the result as CSV, or export the records as JSON.

## Recognising a Security Lake record

A record is OCSF when it has `class_uid` together with `metadata.product.name` (or `metadata.version`) or `asl_version`. In CSV, the same is true of the columns (`class_uid` plus `metadata` as struct text or JSON, or a dotted `metadata.product.name` column). Its AWS source is chosen as follows:

| Source | Recognised by | Importer | Index |
|---|---|---|---|
| CloudTrail management and data events (S3, Lambda, ...) | product name contains `CloudTrail`; class 6003 API Activity (v2), or 3001/3002/3005/6003 (v1 IAM, Authentication, ...) | `cloudtrail2sofelk.py` | `aws-cloudtrail-<source>` |
| VPC Flow Logs | product name contains `VPC`, or class 4001 Network Activity | `vpcflow2sofelk.py` | `aws-vpcflow-<source>` |
| Route 53 Resolver query logs | product name contains `Route 53`, or class 4003 DNS Activity | `route53resolver2sofelk.py` | `aws-route53-<source>` |
| AWS WAF | product name contains `WAF`, or class 4002 HTTP Activity | `waf2sofelk.py` | `aws-waf-<source>` |
| Security Hub findings | product name contains `Security Hub`, or a finding class (2001 Security Finding in v1; 2002 Vulnerability, 2003 Compliance, 2004 Detection Finding in v2) | `securityhub2sofelk.py` | `aws-securityhub-<source>` |
| EKS audit logs | product name contains `EKS` (class 6003 API Activity) | `eksaudit2sofelk.py` | `kubernetes-<source>` |

One export may hold several sources (a `UNION` query, or a lake-wide JSON export). Each importer loads only its own records and counts the rest as skipped ("Security Lake VPC Flow Logs record (loaded by vpcflow2sofelk.py)"). The wrapper runs every importer whose source occurs in the file, so all of them are loaded. A record of a source with no importer (a custom source) is reported as skipped.

## Fields added to every Security Lake document

| Field | Type | Content |
|---|---|---|
| `aws.securitylake.source` | keyword | `cloudtrail`, `vpcflow`, `route53`, `waf`, `securityhub` or `eks` |
| `aws.securitylake.asl_version` | keyword | `asl_version` (`2_0`), absent in v1 |
| `aws.securitylake.ocsf_version` | keyword | `metadata.version` (`1.0.0-rc.2` for v1, `1.1.0` for v2) |
| `aws.securitylake.class_uid`, `category_uid`, `type_uid` | integer / long | OCSF class, category and type IDs |
| `aws.securitylake.class_name`, `activity_name`, `severity` | keyword | as in the record |
| `aws.securitylake.product_name`, `product_feature` | keyword | `metadata.product.name`, `metadata.product.feature.name` (`Management`, `Data`, ...) |
| `aws.securitylake.event_day` | keyword | Security Lake `eventday` partition |

## How OCSF fields go back to native fields

Native field names that OCSF has no place for are kept by Security Lake under `unmapped`; they are put back where the native record had them (for CloudTrail `additionalEventData`, `sharedEventID`, `resources`, `requestParameters.*`, ...). The rest:

| Source | OCSF | Native field |
|---|---|---|
| CloudTrail | `metadata.uid`, `time`, `api.operation`, `api.service.name`, `api.request.uid` | `eventID`, `eventTime`, `eventName`, `eventSource`, `requestID` |
| | `api.request.data`, `api.response.data`, `api.response.error` / `message` | `requestParameters`, `responseElements`, `errorCode` / `errorMessage` |
| | `actor.user.type` / `uid` / `uid_alt` / `name` / `account.uid` / `credential_uid` | `userIdentity.type` / `arn` / `principalId` / `userName` / `accountId` / `accessKeyId` |
| | `actor.session.issuer`, `created_time`, `is_mfa`; `actor.invoked_by` | `userIdentity.sessionContext.sessionIssuer.arn`, `attributes.creationDate`, `mfaAuthenticated`; `userIdentity.invokedBy` |
| | `src_endpoint.ip` (or `domain`), `src_endpoint.uid`, `http_request.user_agent` | `sourceIPAddress`, `vpcEndpointId`, `userAgent` |
| | `cloud.region`, `cloud.account.uid`, `resources[]`, `tls.*` | `awsRegion`, `recipientAccountId`, `resources[]`, `tlsDetails.*` |
| | `metadata.product.feature.name`, `status` = Failure | `eventCategory` / `managementEvent`; `errorCode` when none is given |
| VPC Flow | `src_endpoint` / `dst_endpoint` `.ip`, `.port`, `.interface_uid`, `.vpc_uid`, `.subnet_uid`, `.instance_uid` | `srcaddr`, `dstaddr`, `srcport`, `dstport`, `interface-id`, `vpc-id`, `subnet-id`, `instance-id` |
| | `connection_info.protocol_num`, `tcp_flags`, `direction`, `boundary_id`; `traffic.packets` / `bytes` | `protocol`, `tcp-flags`, `flow-direction`, `traffic-path`; `packets` / `bytes` |
| | `start_time`, `end_time`, `action`/`disposition`, `status_code`, `cloud.zone` | `start`, `end`, `action` (`ACCEPT`/`REJECT`), `log-status`, `az-id` |
| Route 53 | `query.hostname` / `type` / `class`, `rcode`, `answers[].rdata` / `type` / `class` | `query_name` / `query_type` / `query_class`, `rcode`, `answers[].Rdata` / `Type` / `Class` |
| | `src_endpoint.ip` / `port` / `vpc_uid` / `instance_uid`, `dst_endpoint.instance_uid` / `interface_uid` | `srcaddr` / `srcport` / `vpc_id` / `srcids.instance`, `srcids.resolver_endpoint` / `resolver_network_interface` |
| | `connection_info.protocol_name`, `firewall_rule.uid` / `condition`, `disposition` | `transport`, `firewall_rule_group_id` / `firewall_domain_list_id`, `firewall_rule_action` |
| WAF | `metadata.product.feature.uid`, `disposition`, `firewall_rule.uid` / `type` | `webaclId`, `action`, `terminatingRuleId` / `terminatingRuleType` |
| | `src_endpoint.ip` / `location.country`, `http_request.*` (method, url, headers, version, uid) | `httpRequest.clientIp` / `country`, `httpRequest.*` |
| Security Hub | `finding_info.uid` / `title` / `desc` / `types` / `created_time` / `modified_time` / `first_seen_time` / `last_seen_time` (`finding.*` in v1) | `Id`, `Title`, `Description`, `Types`, `CreatedAt`, `UpdatedAt`, `FirstObservedAt`, `LastObservedAt` |
| | `finding_info.product_uid`, `analytic.uid`, `severity`, `status`, `state`, `compliance.status` / `control`, `remediation.*`, `resources[]` | `ProductArn`, `GeneratorId`, `Severity.Label`, `Workflow.Status`, `RecordState`, `Compliance.*`, `Remediation.Recommendation.*`, `Resources[]` |
| EKS audit | `api.request.uid` (or `metadata.uid`), `api.operation`, `http_request.url.path`, `http_request.user_agent` | `auditID`, `verb`, `requestURI`, `userAgent` |
| | `actor.user.name` / `uid` / `groups`, `actor.invoked_by`, `src_endpoint.ip` (+ `intermediate_ips`) | `user.username` / `uid` / `groups`, `impersonatedUser.username`, `sourceIPs` |
| | `resources[0].type` / `name` / `namespace` / `uid`, `api.response.code` / `message`, `api.request.data` / `api.response.data` | `objectRef.*`, `responseStatus.code` / `message`, `requestObject` / `responseObject` |

## Limits

- Parquet is not read (see above).
- Fields Security Lake drops when it normalises a record (for example most of a VPC Flow v5 record's custom fields, or WAF rule-group details) cannot be recovered; load the native logs when you need them.
- Athena prints OCSF objects as struct text (`{uid=..., name=...}`). Struct text has no quoting, so a value containing `, key=` splits wrongly; `CAST(... AS JSON)` in the query avoids that.
- The mapping was built from the Security Lake and OCSF documentation and tested with synthetic records (`AWS/tests/fixtures/securitylake/`). Run `--dry-run` first on a real export: fields that did not map show up under `<namespace>.unmapped.*`.
