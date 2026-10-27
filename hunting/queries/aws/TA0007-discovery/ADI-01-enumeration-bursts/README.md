# ADI-01 Enumeration bursts: many List, Describe and Get calls across services in a few minutes

| | |
|---|---|
| Tactic | TA0007 Discovery |
| ATT&CK | T1580 Cloud Infrastructure Discovery, T1526 Cloud Service Discovery, T1087.004 Cloud Account, T1069.003 Cloud Groups |
| Indexes | `aws-cloudtrail-*` |
| Needs | CloudTrail management read events |
| Applies to | every AWS account |

**What it finds.** Ten-minute windows in which one principal made read-only `List*`, `Describe*` and `Get*` calls to 20 or more distinct APIs, or to 6 or more services. That breadth is what enumeration tools (Pacu, ScoutSuite, Prowler, CloudFox, `enumerate-iam`) produce.

**Reading the output.** Security scanners and the AWS console itself also enumerate: console sessions call many `Describe*` APIs when a user opens dashboards, and CSPM tools run on a schedule from a known role. Suspicious is a burst from a principal that does not normally do this, with `whoami` (`GetCallerIdentity`) at the start, many regions, and a high `denied_pct` (brute-forcing permissions, see [ADI-02](../ADI-02-access-denied-probing/)).
