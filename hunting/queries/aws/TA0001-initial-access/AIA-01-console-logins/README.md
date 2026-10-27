# AIA-01 Console sign-ins: root use, missing MFA and failures, per user and source

| | |
|---|---|
| Tactic | TA0001 Initial Access |
| ATT&CK | T1078.004 Valid Accounts: Cloud Accounts, T1110 Brute Force |
| Indexes | `aws-cloudtrail-*` |
| Needs | CloudTrail `ConsoleLogin` events (signin.amazonaws.com; logged in us-east-1 for most sign-ins) |
| Applies to | every AWS account |

**What it finds.** Every combination of console user and source address, with successes, failures, successful sign-ins without MFA and root sign-ins. Scored: root use +3, success without MFA +2, failures +1 (5 or more: +2), failures and a success from the same source +2.

**Reading the output.** Root should almost never sign in; any root row needs an owner. A success after failures from the same source is the classic guessed password. Failed sign-ins for users that do not exist show `user.name` as `HIDDEN_DUE_TO_SECURITY_REASONS`. Federated (SSO) sign-ins report `MFAUsed: No` because MFA happened at the identity provider, so read `success_without_mfa` together with the user type. Compare `source.address` with the client's office and VPN ranges.

**Next.** [AIA-02](../AIA-02-console-brute-force/) for spraying across many users; then follow the user in [ATRI-02](../../00-triage/ATRI-02-cloudtrail-principal-inventory/).
