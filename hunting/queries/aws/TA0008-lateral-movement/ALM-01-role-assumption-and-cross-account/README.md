# ALM-01 Role assumption: who assumed which role, cross-account access and failures

| | |
|---|---|
| Tactic | TA0008 Lateral Movement |
| ATT&CK | T1550.001 Application Access Token, T1078.004 Valid Accounts: Cloud Accounts |
| Indexes | `aws-cloudtrail-*` |
| Needs | CloudTrail STS events (`AssumeRole*`, `GetFederationToken`) |
| Applies to | every AWS account, and organizations with several accounts |

**What it finds.** Every caller and role pair from STS: how often the role was assumed, failures, the session names used, and whether the caller's account differs from the role's (`cross_account`). Assumptions made by AWS services for themselves are excluded.

**Reading the output.** Rare pairs (`events` of 1 or 2) and failures are the leads: an attacker with a foothold tries the roles they found during discovery, often in other accounts of the organization (`OrganizationAccountAccessRole` is the usual target). A session name that differs from the client's naming (an attacker's handle, `test`, a tool name) is a good pivot: search it in `aws.cloudtrail.user_identity.arn` to see what the session did. `AssumeRoot` is the newer centralized root access and should be rare.

**If it errors or looks empty.** In the account that owns the role, cross-account `AssumeRole` is logged with the caller's details; in the caller's account it appears only if both accounts' trails are loaded.
