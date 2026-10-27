# Checklist: AWS network (VPC Flow Logs)

VPC Flow Logs (`aws-vpcflow-*`) for the VPCs, subnets or interfaces in scope. The usual questions: was something scanned or reached from the internet, did the attacker move between instances, and is anything beaconing out or sending data out. Flow logs carry addresses, ports, byte counts and accept/reject only, so every row is a lead to confirm on the hosts.

## 1. Coverage

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 1.1 | Which interfaces, accounts and time range the flow logs cover | [ATRI-01](../queries/aws/00-triage/ATRI-01-aws-data-coverage/) | 1.2.3, 2.4 | Whether the flow logs capture ALL traffic or only REJECT, and the aggregation interval (1 or 10 minutes); gaps in the time range. |
| 1.2 | Internal address ranges, NAT gateways and known-good destinations |  | 1.3.1, 1.3.5 | Ask the client for the VPC CIDRs, NAT gateway and load balancer interfaces, and expected external services (update servers, SaaS, partners). |

## 2. Inbound

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 2.1 | Inbound traffic from the internet: scanners and what they reached | [ADI-04](../queries/aws/TA0007-discovery/ADI-04-vpc-inbound-scans-and-exposure/) | 2.4.4 | Public sources touching many ports or hosts; accepted inbound connections on management ports (22, 3389, 5985, databases). |

## 3. Inside the VPC

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 3.1 | Internal scanning | [ADI-03](../queries/aws/TA0007-discovery/ADI-03-vpc-internal-scanning/) | 2.4.6 | One internal source reaching many hosts or ports, especially a web or jump host. |
| 3.2 | East-west administrative connections | [ALM-02](../queries/aws/TA0008-lateral-movement/ALM-02-vpc-east-west-admin-protocols/) | 2.4.13 | SSH, RDP, SMB, WinRM and database connections between instances that do not normally talk. |

## 4. Outbound

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 4.1 | Beacon-like outbound connections | [AC2-01](../queries/aws/TA0011-command-and-control/AC2-01-vpc-beaconing/) | 2.4.7 | One instance reaching one rare public address in most hours, with small, regular byte counts. |
| 4.2 | Uncommon and known-bad outbound ports | [AC2-02](../queries/aws/TA0011-command-and-control/AC2-02-vpc-uncommon-outbound-ports/) | 2.4.7 | Tor, mining-pool and reverse-shell ports; anything outbound from instances that should only answer requests. |
| 4.3 | Large outbound transfers to public addresses | [AEXF-02](../queries/aws/TA0010-exfiltration/AEXF-02-vpc-large-outbound-transfers/) | 2.4.7 | Byte totals far above the instance's usual; compare the time with S3 access (ACO-01) and ALB downloads (AEXF-03). |

## Not covered by these queries

- Packet contents, DNS queries and TLS server names: flow logs do not have them. Route 53 Resolver query logs and Traffic Mirroring are outside this toolkit.
- Flow logs in Parquet format are not read; deliver them as text or convert them first.
- Traffic to and from the instance metadata service, Amazon DNS and the time service is never logged by AWS.
