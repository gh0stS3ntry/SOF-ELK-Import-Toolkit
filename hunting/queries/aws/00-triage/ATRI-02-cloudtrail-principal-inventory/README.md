# ATRI-02 CloudTrail principals: who called what, from where, and how often it failed

| | |
|---|---|
| Group | Triage (run first) |
| Indexes | `aws-cloudtrail-*` |
| Needs | CloudTrail management events |
| Applies to | every AWS account |

**What it finds.** One row per principal (IAM user, assumed-role session, root, or the AWS service that acted): event counts, write events, failures, how many distinct APIs and services it called, from how many source addresses and access keys, in which regions. Assumed-role sessions appear as `arn:aws:sts::<account>:assumed-role/<role>/<session>`, so each session of a role is its own row.

**Reading the output.** Start with principals that have a high `failed_pct` (permission probing, see [ADI-02](../../TA0007-discovery/ADI-02-access-denied-probing/)), many `distinct_apis` with mostly reads (enumeration, [ADI-01](../../TA0007-discovery/ADI-01-enumeration-bursts/)), `Root` in `identity_types`, or a `first_seen` inside the incident window. Compare `source_count` with what you know of the principal: a CI user should call from a handful of build addresses.

**Next.** [AIA-01](../../TA0001-initial-access/AIA-01-console-logins/) for console logins, [AIA-03](../../TA0001-initial-access/AIA-03-access-key-sources/) for access keys.
