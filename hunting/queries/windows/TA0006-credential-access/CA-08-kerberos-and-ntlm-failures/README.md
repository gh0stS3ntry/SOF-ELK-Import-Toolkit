# CA-08 Kerberos and NTLM authentication failures by source and reason

| | |
|---|---|
| Tactic | TA0006 Credential Access |
| ATT&CK | T1110 Brute Force, T1087.002 Domain Account Discovery |
| Indexes | `evtxlogs-*` |
| Needs | Security 4768 / 4771 (Kerberos) and 4776 (NTLM credential validation). Domain controllers log them for domain accounts; member hosts log 4776 for local accounts |
| Roles | domain controller; all hosts for local-account NTLM |

**What it finds.** Failed Kerberos TGT requests, pre-authentication failures and NTLM validations, translated to a reason and grouped by source and reason, with how many accounts each source tried.

**Reading the output.** Many "unknown user" failures from one source is username enumeration (`kerbrute userenum` uses 4768 with status 0x6); many "bad password" across accounts is spraying ([CA-05](../CA-05-password-spraying/)). A single account with a burst of "bad password" from many sources is usually a stale saved password (phone, mapped drive, service), not an attack. 4776 gives a workstation name instead of an IP.
