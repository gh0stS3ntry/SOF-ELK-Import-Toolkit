# Security Hub findings schema (`aws-securityhub-*`)

Loaded by `AWS/securityhub2sofelk.py`; template `AWS/index_templates/index-aws-securityhub.json`. Common fields: [aws-common.md](aws-common.md). `event.dataset` is `aws.securityhub`, `event.kind` is `alert`; `@timestamp` is the finding's `UpdatedAt` (else `CreatedAt`).

SOF-ELK has no Security Hub parser, so this schema is the toolkit's own: ECS where a field exists, `aws.securityhub.*` (snake_case of the AWS Security Finding Format name) for the rest. Findings from GuardDuty, Inspector, Macie, IAM Access Analyzer, Config and the Security Hub controls all arrive in this format.

| ASFF field | Field | Type | Notes |
|---|---|---|---|
| `UpdatedAt` / `CreatedAt` / `FirstObservedAt` / `LastObservedAt` / `ProcessedAt` | `aws.securityhub.updated_at` / `created_at` / `first_observed_at` / `last_observed_at` / `processed_at` | date | `CreatedAt` also in `event.created` |
| `Title` | `message`, `aws.securityhub.title` | keyword (+ text) | |
| `Description` | `aws.securityhub.description` | keyword (+ text) | |
| `Id`, `ProductArn`, `ProductName`, `CompanyName`, `GeneratorId`, `SchemaVersion` | `aws.securityhub.id`, `product_arn`, `product_name`, `company_name`, `generator_id`, `schema_version` | keyword | |
| `Types[]` | `aws.securityhub.types`, `event.action` (first type) | keyword | `TTPs/Initial Access/...`, `Software and Configuration Checks/...` |
| `Severity.Label` / `Normalized` / `Original` | `aws.securityhub.severity.label` / `normalized` / `original` | keyword / integer / keyword | |
| (derived) | `event.severity` | long | `Severity.Normalized`, else from the label (INFORMATIONAL 0, LOW 1, MEDIUM 40, HIGH 70, CRITICAL 90) |
| `Confidence`, `Criticality` | `aws.securityhub.confidence`, `criticality` | integer | |
| `Compliance.Status` / `SecurityControlId` | `aws.securityhub.compliance.status` / `security_control_id`, `event.outcome` | keyword | `PASSED` is success, `FAILED` failure |
| `Workflow.Status`, `RecordState`, `VerificationState`, `WorkflowState` | `aws.securityhub.workflow_status`, `record_state`, `verification_state`, `workflow_state` | keyword | |
| `Remediation.Recommendation.Text` / `Url` | `aws.securityhub.remediation.text` / `url` | keyword | |
| `AwsAccountId` / `Region` | `cloud.account.id` / `cloud.region` | keyword | `AwsAccountName` → `aws.securityhub.aws_account_name` |
| `Resources[].Id` / `Type` / `Region` / `Partition` | `aws.securityhub.resource.id` / `type` / `region` / `partition` | keyword lists | |
| `Network.SourceIpV4`/`V6`, `SourcePort`, `SourceDomain` | `source.ip`, `source.port`, `source.domain` | ip / integer / keyword | |
| `Network.DestinationIpV4`/`V6`, `DestinationPort`, `DestinationDomain` | `destination.ip`, `destination.port`, `destination.domain` | ip / integer / keyword | |
| `Network.Direction` / `Protocol` | `network.direction` (`ingress`/`egress`) / `network.transport` | keyword | |
| `Process.Name` / `Path` / `Pid` / `ParentPid` | `process.name` / `executable` / `pid` / `parent.pid` | keyword / long | |
| `Malware[].Name`, `ThreatIntelIndicators[].Value` | `aws.securityhub.malware_names`, `threat_intel_values` | keyword lists | |
| `Vulnerabilities[].Id` | `vulnerability.id` | keyword list | CVE IDs |
| `Resources`, `ProductFields`, `UserDefinedFields`, `Network`, `Process`, `Malware`, `ThreatIntelIndicators`, `Action`, `Vulnerabilities`, `FindingProviderFields` | `aws.securityhub.flattened.<snake_case>` | keyword (+ text) | whole object as JSON text, for the details above that have no field of their own (GuardDuty's `ProductFields`, `Action.AwsApiCallAction`, ...) |
| any other top-level field | `aws.securityhub.unmapped.<snake_case>` | keyword | |

## Inputs

- `aws securityhub get-findings` output (`{"Findings": [...]}`), EventBridge "Security Hub Findings - Imported" events (`{"detail": {"findings": [...]}}`), a JSON array of findings, or one finding per line.
- [Amazon Security Lake](aws-securitylake.md) finding records (class 2001 in v1; 2002 to 2004 in v2), as JSON or Athena CSV.
- CSV: a column holding the whole finding as JSON, or flattened columns (`Severity.Label`, `Resources.0.Id`, ...).

## Document IDs and re-runs

The document ID is product ARN + finding ID + `UpdatedAt`. A finding Security Hub updated later (new `UpdatedAt`) becomes a new document, so the history of a finding is kept; `FROM aws-securityhub-* | STATS ... BY aws.securityhub.id` gives its latest state. Loading the same files again overwrites instead of duplicating.
