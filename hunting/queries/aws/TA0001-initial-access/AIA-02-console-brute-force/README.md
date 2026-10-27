# AIA-02 Console brute force and password spraying, per source and hour

| | |
|---|---|
| Tactic | TA0001 Initial Access |
| ATT&CK | T1110.001 Password Guessing, T1110.003 Password Spraying |
| Indexes | `aws-cloudtrail-*` |
| Needs | CloudTrail `ConsoleLogin` events |
| Applies to | every AWS account with IAM users |

**What it finds.** Source addresses with 5 or more failed console sign-ins in an hour, whether they tried one user (guessing) or many (spraying), and which users then signed in successfully from the same source in the same hour.

**Reading the output.** Any row with `successes` above 0 is a probable compromise: take the users in `users_signed_in` to [ATRI-02](../../00-triage/ATRI-02-cloudtrail-principal-inventory/) and follow their session. Spraying from cloud hosting ranges is usually commodity; spraying that names real users means the attacker has a user list. Widen `time_bucket` to `1 day` for slow sprays.
