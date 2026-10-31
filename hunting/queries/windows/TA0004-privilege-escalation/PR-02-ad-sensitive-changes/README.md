# PR-02 Sensitive Active Directory and account-control changes

| | |
|---|---|
| Tactic | TA0004 Privilege Escalation |
| ATT&CK | T1098 Account Manipulation, T1484 Domain or Tenant Policy Modification, T1558.004 AS-REP Roasting, T1134.005 SID-History Injection, T1556 Modify Authentication Process |
| Indexes | `evtxlogs-*` |
| Needs | Security 4720/4738/4741/4742 with `OldUacValue`/`NewUacValue`, `AllowedToDelegateTo` and `SidHistory`. The other event IDs (4739, 4765/4766, 4780, 4794, trusts 4706/4707/4716, 4713, 4717/4718) are added when present |
| Roles | domain controller (member servers and workstations log the local-account part) |

**What it finds.** Changes that hand an attacker durable privilege: DSRM password set, AdminSDHolder ACL changes, SID History, new or changed trusts, Kerberos and domain policy changes, logon rights granted, and account-control flags switched on (pre-authentication disabled, unconstrained or protocol-transition delegation, constrained delegation targets, password not required, password never expires). The flags are read from the hex `NewUacValue` and counted only when they were off in `OldUacValue`.

**Reading the output.** Time order, so changes made in one session read together; `SubjectLogonId` links them to the logon ([LM-03](../../TA0008-lateral-movement/LM-03-logon-sessions-with-duration/)). Directory Service Changes (5136) are not used here because few environments enable them; if yours does, search `ObjectDN` and `AttributeLDAPDisplayName` for `gPLink`, `msDS-AllowedToActOnBehalfOfOtherIdentity` and `servicePrincipalName`.
