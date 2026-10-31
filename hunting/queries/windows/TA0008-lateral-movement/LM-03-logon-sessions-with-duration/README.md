# LM-03 Logon sessions with start, end, duration and admin rights

| | |
|---|---|
| Tactic | TA0008 Lateral Movement |
| ATT&CK | T1078 Valid Accounts, T1021 Remote Services |
| Indexes | `evtxlogs-*` |
| Needs | Security 4624 and 4634/4647 ("Audit Logon" / "Audit Logoff", on by default); 4672 for admin sessions |
| Roles | all |

**What it finds.** One row per logon session (host + logon ID): logon and logoff time, duration in minutes, account, logon type in words, whether the session got admin privileges (4672), source IP and workstation, authentication package (NTLM vs Kerberos), elevated token, Restricted Admin mode (RDP pass-the-hash), and whether the user logged off themselves (4647).

**Reading the output.** Filter to one account or source IP to read its sessions in order: `| WHERE MV_CONTAINS(accounts, "DOMAIN\\user")` or `| WHERE MV_CONTAINS(source_ip, "10.1.2.3")`. A blank `logoff_time` means the session was still open at collection, the logoff record rolled off, or the host shut down. Type 3 sessions lasting a second are normal for SMB and PsExec; long type 10 sessions from an unusual IP are the attacker's desk. `linked_logon` pairs the elevated and non-elevated sessions UAC creates for an admin. Logon IDs restart after a reboot, so very old and new sessions can share an ID; check the dates when a row looks odd.

**Tuning.** Remove the machine-account filter to follow `HOST$` logons (used by some lateral movement tools, and by DCSync).
