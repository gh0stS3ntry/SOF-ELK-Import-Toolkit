# ACA-01 Secrets Manager, Parameter Store and EC2 password retrieval, per principal

| | |
|---|---|
| Tactic | TA0006 Credential Access |
| ATT&CK | T1555.006 Cloud Secrets Management Stores, T1552.005 Cloud Instance Metadata API |
| Indexes | `aws-cloudtrail-*` |
| Needs | CloudTrail management read events (the trail must log read events) |
| Applies to | every AWS account |

**What it finds.** Per principal: reads of Secrets Manager secrets and SSM parameters (with or without decryption), Windows administrator password retrieval (`GetPasswordData`), IAM credential reports, ECR tokens, ACM certificate exports, and temporary credential minting. Calls made by AWS services on their own behalf are excluded.

**Reading the output.** Applications read the same few secrets from the same role all day. An IAM user or a new role session reading many distinct secrets (`distinct_secrets`), listing them first (`ListSecrets`, `DescribeParameters`), or failing on many (`failed`), is harvesting. `GetPasswordData` returns the encrypted Windows administrator password of an EC2 instance; anyone with the launch key pair can decrypt it.

**If it errors or looks empty.** Read events are only in CloudTrail if the trail logs them (the default trail does). KMS `Decrypt` is deliberately not included: it is too noisy without a known key ID; add it with a `WHERE` on the key when you have one.
