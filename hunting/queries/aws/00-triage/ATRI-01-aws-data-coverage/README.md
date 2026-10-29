# ATRI-01 AWS data coverage per index: log types, accounts, regions, time range

| | |
|---|---|
| Group | Triage (run first) |
| Indexes | `aws-cloudtrail-*`, `aws-vpcflow-*`, `httpdlog-*`, `aws-waf-*` |
| Needs | nothing |
| Applies to | every AWS evidence source |

**What it finds.** One row per index and log type (`aws.cloudtrail`, `aws.vpcflow`, `aws.alb`, `aws.elb_classic`, `aws.waf`; ALB logs are in `httpdlog-<source>` next to other web server logs, which show up here with their own dataset): record count, files loaded, the first and last event, and the accounts and regions seen. It tells you which of the AWS queries can return anything, and whether the logs cover the incident window.

**Reading the output.** A `span_days` shorter than the incident window means logs are missing (CloudTrail S3 lifecycle rules, flow logs enabled late, ALB logging turned off). Regions you did not expect in CloudTrail are worth [ADE-02](../../TA0112-defense-impairment/ADE-02-rare-regions/). An empty `accounts` for VPC Flow rows means the custom format had no `account-id` and the files were not under an `AWSLogs/<account>/` path.

**If it errors or looks empty.** ES|QL fails only if none of the four patterns match an index. Remove the patterns you did not load if your cluster still rejects one.

**Next.** [ATRI-02](../ATRI-02-cloudtrail-principal-inventory/) for who did what in the account.
