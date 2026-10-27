# AIA-03 Long-term access keys: source addresses, user agents and tooling per key

| | |
|---|---|
| Tactic | TA0001 Initial Access |
| ATT&CK | T1078.004 Valid Accounts: Cloud Accounts, T1552.001 Credentials In Files (leaked keys) |
| Indexes | `aws-cloudtrail-*` |
| Needs | CloudTrail events signed with IAM user keys (`AKIA...`) |
| Applies to | every AWS account with IAM user access keys |

**What it finds.** One row per IAM user access key: how many source addresses and user agents used it, how often it failed, whether it called `GetCallerIdentity` (the first thing a stolen key is used for), and whether any user agent looks like offensive or ad-hoc tooling (Kali/Parrot builds, Pacu, ScoutSuite, Prowler, CloudFox, TruffleHog, curl, Postman, S3 Browser, rclone).

**Reading the output.** A key normally used by one application from a few addresses, suddenly seen from a residential or VPS address with a different SDK, is the typical leaked key (committed to Git, left in a CI log or an AMI). `tooling_events` also catches the client's own security scans, so check who owns the key before escalating. Follow a suspect key's activity with `WHERE aws.cloudtrail.user_identity.access_key_id == "AKIA..."` and drop the `STATS`.

**Next.** [ADI-01](../../TA0007-discovery/ADI-01-enumeration-bursts/) for what the key enumerated; [APE-01](../../TA0003-persistence/APE-01-iam-user-and-key-persistence/) for keys it created.
