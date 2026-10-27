# AWS VPC Flow Logs schema (`aws-vpcflow-*`)

Loaded by `AWS/vpcflow2sofelk.py`; template `AWS/index_templates/index-aws-vpcflow.json`. Common fields: [aws-common.md](aws-common.md). `event.dataset` is `aws.vpcflow`, `event.category` is `network`; `@timestamp` is `start` (also `netflow.flow_start`).

Records are read by field name, from the header line of S3 text deliveries, from `--fields` for header-less CloudWatch exports, or the default version 2 format. Names follow SOF-ELK's grok patterns in `configfiles/2050-netflow.conf`.

| Flow log field | Field | Type | Notes |
|---|---|---|---|
| `version` | `aws.vpcflow.version` | integer | |
| `account-id` | `aws.vpcflow.account_id`, `cloud.account.id` | keyword | `unknown` dropped (as SOF-ELK). SOF-ELK converts it to an integer; the toolkit keeps it as text so leading zeros survive |
| `interface-id` | `aws.vpcflow.interface_id` | keyword | |
| `srcaddr` / `dstaddr` | `source.ip` / `destination.ip` | ip | |
| `srcport` / `dstport` | `source.port` / `destination.port` | integer | |
| `protocol` | `network.iana_number` | integer | plus `network.transport` (`tcp`, `udp`, `icmp`, ...) |
| `packets` / `bytes` | `source.packets` / `source.bytes` | long | `destination.packets`/`bytes` are 0, as in SOF-ELK |
| `start` / `end` | `netflow.flow_start` / `netflow.flow_end` | date | `netflow.flow_duration` = end - start (seconds, double) |
| `action` | `aws.vpcflow.action` | keyword | `ACCEPT`/`REJECT`; also `event.action` (lower case) and `event.outcome` |
| `log-status` | `aws.vpcflow.log_status` | keyword | `NODATA` and `SKIPDATA` records are not loaded (as SOF-ELK) |
| `vpc-id` / `subnet-id` / `instance-id` | `aws.vpcflow.vpc_id` / `subnet_id` / `instance_id` | keyword | |
| `tcp-flags` | `netflow.tcp_control_bits`, `network.tcp_flags`, `network.tcp_flags_hex` | integer / keyword | TCP only, as SOF-ELK's `tcp_flags_expand.rb` |
| `type` | `aws.vpcflow.type` | keyword | `IPv4`, `IPv6`, `EFA` |
| `pkt-srcaddr` / `pkt-dstaddr` | `original_source.ip` / `original_destination.ip` | ip | |
| `region` / `az-id` | `cloud.region` / `cloud.availability_zone` | keyword | |
| `sublocation-type` / `sublocation-id` | `aws.vpcflow.sublocation.type` / `id` | keyword | |
| `pkt-src-aws-service` / `pkt-dst-aws-service` | `aws.vpcflow.source.service` / `aws.vpcflow.destination_service` | keyword | SOF-ELK's names |
| `flow-direction` | `network.direction` | keyword | `ingress`/`egress` |
| `traffic-path` | `aws.vpcflow.traffic_path` | keyword | |
| `reject-reason` | `aws.vpcflow.reason` | keyword | |
| `ecs-*` | `aws.vpcflow.ecs.<name>` | keyword | e.g. `ecs-task-arn` → `aws.vpcflow.ecs.task_arn` |
| (derived) | `network.community_id` | keyword | Community ID v1, to join with Zeek/NetFlow |
| (derived) | `netflow.delta_flow_count` | long | 1, as SOF-ELK |
| any other field | `aws.vpcflow.unmapped.<snake_case>` | keyword | |

`-` values are left out. A record whose number of values does not match the field list is reported and skipped.

## CSV input

Read as described in [CSV input](aws-common.md#csv-input). Columns are matched to flow log field names (`account_id`, `accountId` and `account-id` all work), plus these descriptive headers: `Source address`/`Source IP`, `Destination address`/`Destination IP`, `Source port`, `Destination port`, `Start time`, `End time`, `Log status`/`Status`, `Interface ID`/`ENI`, `Account ID`, `TCP flags`, `Flow direction`. A Logs Insights export with only `@message` is read as raw flow lines (default v2 format, or `--fields`). `start` and `end` may be epoch seconds or date text; `netflow.flow_duration` is computed from whichever was given. Athena partition columns (`day`, `region` when not a flow field) go to `aws.vpcflow.unmapped.*`.
