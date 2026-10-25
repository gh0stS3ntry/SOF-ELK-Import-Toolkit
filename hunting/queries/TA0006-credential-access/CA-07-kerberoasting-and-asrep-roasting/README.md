# CA-07 Kerberoasting and AS-REP roasting

| | |
|---|---|
| Tactic | TA0006 Credential Access |
| ATT&CK | T1558.003 Kerberoasting, T1558.004 AS-REP Roasting |
| Indexes | `evtxlogs-*` |
| Needs | Security 4768/4769 from domain controllers (policies "Audit Kerberos Authentication Service" and "Audit Kerberos Service Ticket Operations"). RD01 is a workstation and has neither |
| Roles | domain controller |

**What it finds.** Per source IP and hour: successful service tickets encrypted with RC4 or DES for user service accounts (machine accounts and `krbtgt` excluded), and TGTs issued without pre-authentication. One source asking for RC4 tickets to many services in an hour is Kerberoasting (`Rubeus kerberoast`, `GetUserSPNs.py`).

**Reading the output.** In domains where AES is the norm, any RC4 ticket for a user SPN stands out; in domains with legacy clients, rely on `distinct_services`. For AS-REP roasting, the accounts listed have "Do not require Kerberos preauthentication" set; see when it was set in [PR-02](../../TA0004-privilege-escalation/PR-02-ad-sensitive-changes/).

**If it errors.** `Unknown column` on `TicketEncryptionType` or `PreAuthType` means no 4768/4769 events were loaded (no domain controller logs).
