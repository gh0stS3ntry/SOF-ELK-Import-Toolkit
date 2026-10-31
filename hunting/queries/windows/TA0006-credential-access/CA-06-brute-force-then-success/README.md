# CA-06 Brute force against an account followed by a successful logon, and account lockouts

| | |
|---|---|
| Tactic | TA0006 Credential Access |
| ATT&CK | T1110.001 Password Guessing, T1078 Valid Accounts |
| Indexes | `evtxlogs-*` |
| Needs | Security 4624 and 4625; 4740 (locked out) and 4767 (unlocked) are logged on domain controllers |
| Roles | all internet-facing or RDP-exposed hosts, domain controllers |

**What it finds.** Per host and account with 10 or more failed logons (or a lockout): failure count and time range, the failing sources, any successful interactive/network/RDP logons, whether one came after the failures began and from a failing source, and lockouts with the caller computer (`TargetDomainName` on 4740 is the machine the lockout came from).

**Reading the output.** `f_success_after` with `f_same_source` (score 5 or more) means the guessing probably worked: take `account` and `success_sources` to [LM-03](../../TA0008-lateral-movement/LM-03-logon-sessions-with-duration/) for the session. `success_sources` lists every successful source for the account, not only those after the failures, so check `last_success` against the failure window.
