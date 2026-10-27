# ACO-01 S3 object reads and listings per principal, bucket and hour

| | |
|---|---|
| Tactic | TA0009 Collection |
| ATT&CK | T1530 Data from Cloud Storage, T1619 Cloud Storage Object Discovery |
| Indexes | `aws-cloudtrail-*` |
| Needs | CloudTrail S3 data events (must be enabled on the trail for the buckets) |
| Applies to | every AWS account holding data in S3 |

**What it finds.** Per principal, bucket and hour: object reads and copies, distinct objects, megabytes sent (`bytesTransferredOut`), bucket listings and failures.

**Reading the output.** Bulk collection looks like a listing followed by thousands of `GetObject` calls on distinct keys within the hour, from a principal that does not normally read that bucket, often with `aws-cli` or `rclone`/`s3browser` user agents. `CopyObject`/`UploadPartCopy` to a bucket in another account is exfiltration without download ([AEXF-01](../../TA0010-exfiltration/AEXF-01-resource-sharing-and-public-exposure/)).

**If it errors or looks empty.** Without S3 data events on the trail there are no `GetObject` rows at all; then use S3 server access logs or the bucket's CloudWatch request metrics instead.
