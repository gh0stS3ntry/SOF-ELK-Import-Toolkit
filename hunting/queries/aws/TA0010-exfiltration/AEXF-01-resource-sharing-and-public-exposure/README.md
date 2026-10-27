# AEXF-01 Snapshots, images, buckets and keys shared with other accounts or made public

| | |
|---|---|
| Tactic | TA0010 Exfiltration |
| ATT&CK | T1537 Transfer Data to Cloud Account, T1567 Exfiltration Over Web Service |
| Indexes | `aws-cloudtrail-*` |
| Needs | CloudTrail management events |
| Applies to | every AWS account |

**What it finds.** Changes that let data leave the account without a download: EBS and RDS snapshots and AMIs shared with another account or with everyone, bucket policies and ACLs granting public or cross-account access, S3 Block Public Access removed, cross-account replication, KMS key policies and grants, resource policies on secrets and ECR repositories, RAM shares, and copies or exports of snapshots and images. Scored: public +3, another account +3, Block Public Access removed or disabled +2, copy or export +1.

**Reading the output.** Sharing a snapshot with an unknown account (`other_account`) is the fastest way to steal a whole disk; the attacker copies it on their side and the only trace in the victim account is this event. Check `other_account` against the client's AWS Organization. `CopySnapshot` to another region on its own is often backup automation; followed by a share it is staging.

**If it errors or looks empty.** `other_account` is the first account ID found in the request. Policies are JSON inside JSON, so quotes in `request` appear escaped.

**Next.** [ACO-01](../../TA0009-collection/ACO-01-s3-data-access-volume/) for object-level reads.
