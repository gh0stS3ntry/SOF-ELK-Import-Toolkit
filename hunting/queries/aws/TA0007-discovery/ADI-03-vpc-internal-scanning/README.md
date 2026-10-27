# ADI-03 Internal scanning inside the VPC: one source reaching many hosts or ports

| | |
|---|---|
| Tactic | TA0007 Discovery |
| ATT&CK | T1046 Network Service Discovery |
| Indexes | `aws-vpcflow-*` |
| Needs | VPC Flow Logs (all traffic, or rejected) |
| Applies to | every VPC with flow logs |

**What it finds.** Private addresses that, within an hour, sent flows to 25 or more internal hosts or 25 or more distinct ports below 32768, with the share of flows the security groups or NACLs rejected.

**Reading the output.** Many ports on few hosts is a port scan; one or two ports on many hosts is a sweep for a service (SMB 445, SSH 22, RDP 3389, Redis 6379). A high `rejected_pct` means the scan mostly hit closed security groups, which is how scans look in AWS. Load balancers, monitoring agents, service meshes and NAT instances talk to many hosts legitimately: identify the `interfaces` (ENI IDs) in the EC2 console or in CloudTrail before calling it a scan.

**If it errors or looks empty.** Flow logs aggregate traffic per 1 or 10 minutes, so `flows` counts aggregated records, not packets.

**Next.** [ALM-02](../../TA0008-lateral-movement/ALM-02-vpc-east-west-admin-protocols/) for what the scanning host connected to afterwards.
