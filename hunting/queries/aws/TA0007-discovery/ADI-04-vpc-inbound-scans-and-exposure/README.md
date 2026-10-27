# ADI-04 Inbound traffic from the internet: scanners, and what they reached

| | |
|---|---|
| Tactic | TA0007 Discovery |
| ATT&CK | T1595.001 Scanning IP Blocks, T1046 Network Service Discovery |
| Indexes | `aws-vpcflow-*` |
| Needs | VPC Flow Logs (all traffic) |
| Applies to | every VPC with internet-facing instances or load balancers |

**What it finds.** Public addresses that scanned the VPC (10 or more ports or targets), and every public address whose traffic to an administrative or database port (SSH, RDP, SMB, WinRM, SQL Server, MySQL, PostgreSQL, Redis, Elasticsearch, MongoDB, Docker) was accepted.

**Reading the output.** Rejected scans are background noise. What matters is `accepted_admin_ports`: a security group open to the internet on SSH, RDP or a database port, and who reached it. Take those `accepted_targets` and times to [ADE-03](../../TA0112-defense-impairment/ADE-03-network-exposure-changes/) (when was the port opened, and by whom) and to the host's own logs (logons from that address).

**If it errors or looks empty.** For inbound traffic, `destination.ip` is the private address of the network interface, even when the client connected to its public or Elastic IP.
