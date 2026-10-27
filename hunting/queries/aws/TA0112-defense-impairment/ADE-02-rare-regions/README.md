# ADE-02 Activity in regions the account rarely uses

| | |
|---|---|
| Tactic | TA0112 Defense Impairment |
| ATT&CK | T1535 Unused/Unsupported Cloud Regions |
| Indexes | `aws-cloudtrail-*` |
| Needs | CloudTrail management events from all regions (a multi-region trail) |
| Applies to | every AWS account |

**What it finds.** Per account and region: the share of the account's (non-service) API activity in that region, with the write APIs called and who called them. Regions sorted from least used.

**Reading the output.** Attackers launch miners and stash resources in regions the client never uses, because nobody looks there. A region with a tiny `region_pct` but `writes` such as `RunInstances`, `CreateKeyPair`, `ImportKeyPair` or `CreateSecurityGroup` is the lead. Global services (IAM, STS without regional endpoints, Organizations, CloudFront, Route 53) log in `us-east-1`, so that region always appears even for clients that never deploy there. Enumeration tools also touch every region once with read-only calls; `writes` separates them.

**If it errors or looks empty.** `INLINE STATS` needs ES 9.x.
