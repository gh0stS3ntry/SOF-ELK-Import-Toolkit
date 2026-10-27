# AC2-02 Outbound connections on uncommon and known-bad ports (Tor, mining pools, reverse shells)

| | |
|---|---|
| Tactic | TA0011 Command and Control |
| ATT&CK | T1571 Non-Standard Port, T1090.003 Multi-hop Proxy, T1496 Resource Hijacking |
| Indexes | `aws-vpcflow-*` |
| Needs | VPC Flow Logs (accepted traffic) |
| Applies to | every VPC with flow logs |

**What it finds.** Accepted outbound traffic to public addresses on ports outside the usual web, DNS, NTP and mail set, one row per port, with how many internal sources and external destinations used it. Ports associated with Metasploit and reverse shells (4444, 1337, 31337), IRC (6667), Tor (9001, 9030, 9050) and cryptocurrency mining pools (3333, 5555, 7777, 14444, 45700) are marked `known_bad`.

**Reading the output.** A port used by one or two instances to a few destinations is more interesting than one used fleet-wide. Mining shows as steady outbound traffic from GPU or large instances (compare with `RunInstances` in [AIM-01](../../TA0040-impact/AIM-01-destructive-and-resource-hijacking-actions/)). Edit the excluded ports to the client's normal egress (proxies, SSH to Git hosting, database replication) to shrink the list.
