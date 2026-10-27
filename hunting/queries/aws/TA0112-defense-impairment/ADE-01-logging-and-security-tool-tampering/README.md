# ADE-01 Logging and security services stopped, deleted or weakened

| | |
|---|---|
| Tactic | TA0112 Defense Impairment |
| ATT&CK | T1562.008 Disable or Modify Cloud Logs, T1562.001 Disable or Modify Tools |
| Indexes | `aws-cloudtrail-*` |
| Needs | CloudTrail management events |
| Applies to | every AWS account |

**What it finds.** Every attempt (successful or not) to stop, delete or weaken CloudTrail, VPC Flow Logs, GuardDuty (including suppression filters and trusted IP lists), Security Hub, AWS Config, CloudWatch logs and alarms, WAF rules and logging, load balancer and S3 access logging, Macie, IAM Access Analyzer, Inspector, default EBS encryption and organization SCPs.

**Reading the output.** `StopLogging`, `DeleteTrail`, `DeleteDetector` and `DeleteFlowLogs` are rare enough that each row needs an explanation. Quieter variants matter as much: `PutEventSelectors` that drops data or management events, a GuardDuty `CreateIPSet` (trusted IP list) or `CreateFilter` with auto-archive that hides the attacker's findings, `PutRetentionPolicy` with a short retention, `UpdateWebACL` that switches a rule to Count. Failed attempts (`event.outcome` failure) show intent and the principal that tried. A gap in [ATRI-01](../../00-triage/ATRI-01-aws-data-coverage/) right after a row here is the logging outage.

**Next.** [ADE-02](../ADE-02-rare-regions/) for activity in regions nobody watches.
