# AIM-01 Destructive actions, ransom-style encryption and resource hijacking, per principal and hour

| | |
|---|---|
| Tactic | TA0040 Impact |
| ATT&CK | T1485 Data Destruction, T1490 Inhibit System Recovery, T1486 Data Encrypted for Impact, T1496 Resource Hijacking |
| Indexes | `aws-cloudtrail-*` |
| Needs | CloudTrail management events (S3 `DeleteObjects` needs data events) |
| Applies to | every AWS account |

**What it finds.** Write events that destroy data or infrastructure (buckets, databases, instances, volumes, stacks, secrets), inhibit recovery (snapshots, AMIs, AWS Backup vaults and recovery points deleted, S3 versioning suspended, lifecycle rules that expire data), encrypt data with a KMS key or disable and schedule deletion of keys (cloud ransomware), launch GPU or large instances (cryptomining), or lock the owner out. Grouped per principal and hour, scored by how many kinds of impact, how many events and how many regions.

**Reading the output.** Ransomware in AWS usually copies or re-encrypts S3 objects with an attacker-controlled KMS key, or deletes data and backups, after a ransom note is uploaded; mining starts large GPU instances in many regions at once. Teardown pipelines also delete a lot, but from a known role and on a schedule.

**If it errors or looks empty.** `DeleteObjects` and `CopyObject` only appear with S3 data events enabled. The instance-type test uses the curated `instance_type` field and a text match on the request for spot and fleet requests.

**Next.** [ADE-01](../../TA0112-defense-impairment/ADE-01-logging-and-security-tool-tampering/) for logging switched off first.
