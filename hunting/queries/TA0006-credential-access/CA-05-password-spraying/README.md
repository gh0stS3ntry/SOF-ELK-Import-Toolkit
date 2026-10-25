# CA-05 Password spraying: one source failing against many accounts

| | |
|---|---|
| Tactic | TA0006 Credential Access |
| ATT&CK | T1110.003 Password Spraying, T1110.001 Password Guessing |
| Indexes | `evtxlogs-*` |
| Needs | Security 4625 on the targeted hosts; on domain controllers 4771 (Kerberos pre-auth failed, status 0x18) and 4776 (NTLM, bad password or unknown user) |
| Roles | all internet-facing or RDP-exposed hosts, domain controllers |

**What it finds.** Sources (IP address, else the workstation name the client sent) with 10 or more failures against 5 or more accounts in a 30-minute window, per host that logged them.

**Reading the output.** `sub_status` explains 4625 failures: `0xc000006a` bad password, `0xc0000064` no such user (the attacker is guessing names), `0xc0000072` disabled, `0xc0000234` locked out. Many unknown users from a public IP on an RDP-exposed server is internet scanning; a spray from an internal workstation means a foothold. Check whether the same source later logged on successfully ([CA-06](../CA-06-brute-force-then-success/), [IA-01](../../TA0001-initial-access/IA-01-logons-from-public-ip/)). Lower the thresholds for slow sprays (one attempt per account per hour) and widen the bucket to `1 day`.
