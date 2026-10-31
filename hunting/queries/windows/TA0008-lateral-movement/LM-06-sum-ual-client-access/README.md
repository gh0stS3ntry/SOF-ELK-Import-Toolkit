# LM-06 Server client access from User Access Logging (SUM database)

| | |
|---|---|
| Tactic | TA0008 Lateral Movement |
| ATT&CK | T1021 Remote Services, T1078 Valid Accounts |
| Indexes | `sum-*` |
| Needs | SumECmd output from `C:\Windows\System32\LogFiles\Sum` (Windows Server 2012 and later) |
| Roles | file server, domain controller, web server, any Windows Server |

**What it finds.** Which accounts reached this server from which client IPs, for which server role (File Server, Active Directory Domain Services, Web Server, DHCP...), how many times, and the first and last access, plus how many loaded servers each client IP reached. UAL keeps up to three years of data (current year plus two), far longer than the Security log.

**Reading the output.** New `first_seen` values in the incident window, admin accounts used from workstations, and a client IP that reached many servers (`servers_for_client`) are the leads. UAL records a day's access per client and account, not individual logons.

**Unverified field names.** The `sum-*` index uses SumECmd's CSV column names with inferred types, and no SUM sample was available while writing this query (RD01 is a workstation). It assumes the `Clients` output's `AuthenticatedUserName`, `IpAddress`, `ClientName`, `RoleDescription`, `TotalAccesses`, `InsertDate` and `LastAccess`. If your columns differ, rename them in the query; `FROM sum-* | LIMIT 5` shows them.
