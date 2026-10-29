# ACA-02 EC2 instance role credentials used from several source addresses

| | |
|---|---|
| Tactic | TA0006 Credential Access |
| ATT&CK | T1552.005 Cloud Instance Metadata API, T1078.004 Valid Accounts: Cloud Accounts |
| Indexes | `aws-cloudtrail-*` |
| Needs | CloudTrail events from EC2 instance-profile sessions |
| Applies to | every AWS account with EC2 instances |

**What it finds.** EC2 instance-profile sessions (`assumed-role/<role>/i-<instance id>`) that called AWS from more than one source address. Credentials an instance gets from its metadata service should only be used from that instance (its public IP, its NAT gateway, or a VPC endpoint).

**Reading the output.** A second source that is not the instance's NAT or public address means the credentials were stolen, typically through SSRF to `169.254.169.254` (check [AIA-04](../../TA0001-initial-access/AIA-04-web-exploitation-attempts/) for requests carrying that address) or from a compromised host, and replayed elsewhere. Private addresses in `sources` are VPC endpoint traffic from inside the VPC; several of them are normal. Note the attacker's address and user agent and search for them across all principals.
