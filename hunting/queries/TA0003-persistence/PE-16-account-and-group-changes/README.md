# PE-16 Local and domain account creation and privileged group changes

| | |
|---|---|
| Tactic | TA0003 Persistence |
| ATT&CK | T1136.001 Local Account, T1136.002 Domain Account, T1098 Account Manipulation, T1078.003 Local Accounts |
| Indexes | `evtxlogs-*` |
| Needs | Security 4720-4767 and 4781 (policies "Audit User Account Management" and "Audit Security Group Management", on by default for success). Domain accounts and groups are logged on domain controllers |
| Roles | all; domain controllers for domain accounts and groups |

**What it finds.** Account creation, enabling, password resets, renames, deletion, computer account creation, and group creation and membership changes, kept when the score is 3 or more. Membership changes to Administrators, Domain/Enterprise/Schema Admins and other privileged groups (Backup/Server/Account Operators, RDP and Remote Management users, DnsAdmins, Exchange permission groups) score highest, as do names ending in `$`, changes to built-in accounts and look-alike names.

**Reading the output.** The list is in time order so a create, add-to-group, and later delete or disable of the same account read as one story. `SubjectLogonId` ties the change to a logon session ([LM-03](../../TA0008-lateral-movement/LM-03-logon-sessions-with-duration/)). For 4732 on a member server the member is often only a SID in `member`; resolve it on the domain controller. Sensitive AD changes beyond group membership are in [PR-02](../../TA0004-privilege-escalation/PR-02-ad-sensitive-changes/).
