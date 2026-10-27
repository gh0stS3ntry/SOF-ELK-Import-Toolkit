# ADI-02 Permission probing: AccessDenied and UnauthorizedOperation errors per principal

| | |
|---|---|
| Tactic | TA0007 Discovery |
| ATT&CK | T1580 Cloud Infrastructure Discovery, T1069.003 Cloud Groups |
| Indexes | `aws-cloudtrail-*` |
| Needs | CloudTrail events with an error code |
| Applies to | every AWS account |

**What it finds.** Per principal: denied calls, how many distinct APIs and services were denied, and the error codes. `InvalidClientTokenId` and `SignatureDoesNotMatch` are attempts with a revoked or wrong key; `ExpiredToken` is a stolen session used after it expired.

**Reading the output.** Applications fail on the same one or two APIs repeatedly (a missing permission). An attacker testing what a stolen credential can do fails on many different APIs across services (`distinct_apis`, `services`). Take the principal to [ADI-01](../ADI-01-enumeration-bursts/) and [ATRI-02](../../00-triage/ATRI-02-cloudtrail-principal-inventory/), and look at what it did succeed at.
