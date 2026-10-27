# ADE-03 Security groups, network ACLs and routes opened to the internet

| | |
|---|---|
| Tactic | TA0112 Defense Impairment |
| ATT&CK | T1562.007 Disable or Modify Cloud Firewall |
| Indexes | `aws-cloudtrail-*` |
| Needs | CloudTrail EC2 and RDS management events |
| Applies to | every AWS account with VPCs |

**What it finds.** Changes that open the network: security group rules (ingress and egress), network ACL entries, routes and internet gateways, VPC peering, security groups swapped on an instance, RDS instances made publicly accessible, and Elastic IPs attached. Scored: open to `0.0.0.0/0` or `::/0` +3, all protocols +2, an administrative or database port +2, a public database +3.

**Reading the output.** SSH or RDP opened to the world, a database made public, or an `ipProtocol -1` egress rule added just before a large transfer are the usual findings. Match the times with [ADI-04](../../TA0007-discovery/ADI-04-vpc-inbound-scans-and-exposure/): accepted inbound traffic to the opened port right after the change shows who used it.

**If it errors or looks empty.** `aws.cloudtrail.request_parameters.cidr_ip` holds every CIDR in the request, so it can be a list.
