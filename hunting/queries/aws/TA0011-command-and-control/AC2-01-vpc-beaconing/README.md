# AC2-01 Beacon-like outbound connections: one instance, one rare destination, every hour

| | |
|---|---|
| Tactic | TA0011 Command and Control |
| ATT&CK | T1071 Application Layer Protocol, T1573 Encrypted Channel |
| Indexes | `aws-vpcflow-*` |
| Needs | VPC Flow Logs (accepted traffic) over at least a day |
| Applies to | every VPC with flow logs |

**What it finds.** Outbound connections from one private address to one public address and port, seen in 12 or more distinct hours, to a destination no more than two internal hosts talk to. `coverage_pct` is the share of hours between the first and last flow that had traffic; `steady_size` is true when the per-flow byte counts barely vary.

**Reading the output.** Implants call home on a timer with small, similar-sized requests: high `coverage_pct`, `steady_size` true, small `bytes_median`. Update agents, monitoring and licence checks look the same, so resolve the destination (passive DNS, threat intel, the client's software inventory) before escalating. Flow logs aggregate per 1 or 10 minutes, so this finds hourly regularity, not exact beacon intervals.

**If it errors or looks empty.** `INLINE STATS` needs ES 9.x.
