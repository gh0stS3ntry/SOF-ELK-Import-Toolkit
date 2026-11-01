# Checklist: Domain controller

Active Directory domain controllers, and other tier-0 servers (ADCS, ADFS, Entra Connect) where the same rows apply. Run the [baseline](00-baseline-all-windows-hosts.md) first. DCs hold the domain-wide authentication record (Kerberos and NTLM), so they answer "which accounts were used, from where" for the whole estate, and are the target of DCSync, NTDS theft and GPO-based ransomware deployment.

## 1. Host profile

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 1.1 | Domain(s), forest, FSMO roles, other DCs | | 1.2.4, 1.3.1 | All DCs need collecting; the Security log on one DC only covers authentications it handled. |
| 1.2 | Privileged groups and their expected members, tier-0 service accounts | | 1.3.2 | Ask the client for Domain/Enterprise/Schema Admins and other privileged group members; rows 3.x compare against it. |
| 1.3 | Security log size and retention | [TRI-02](../queries/windows/00-triage/TRI-02-event-log-coverage/), [DE-04](../queries/windows/TA0112-defense-impairment/DE-04-security-tool-tampering-registry/) | 2.4 | Busy DCs roll the Security log in hours; note how far back 4624/4768/4769 reach. |
| 1.4 | Other roles on the DC (DNS, DHCP, ADCS, file shares) | [TRI-05](../queries/windows/00-triage/TRI-05-installed-software/) | 1.2.3 | Add the [file server](file-server.md) checklist if it serves shares. |

## 2. Authentication

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 2.1 | Password spraying and brute force across the domain | [CA-05](../queries/windows/TA0006-credential-access/CA-05-password-spraying/), [CA-06](../queries/windows/TA0006-credential-access/CA-06-brute-force-then-success/) | 2.4.1, 2.4.2 | One source failing against many accounts (4771/4776/4625); lockouts (4740) and who unlocked them (4767). |
| 2.2 | Kerberos and NTLM failures by source | [CA-08](../queries/windows/TA0006-credential-access/CA-08-kerberos-and-ntlm-failures/) | 2.4.24 | Bad-password and unknown-account failures from one host; NTLM from hosts that should use Kerberos. |
| 2.3 | Kerberoasting and AS-REP roasting | [CA-07](../queries/windows/TA0006-credential-access/CA-07-kerberoasting-and-asrep-roasting/) | 2.4.24 | Many 4769 RC4 service tickets from one account; 4768 without pre-authentication. |
| 2.4 | Logons from outside and odd logon sessions | [IA-01](../queries/windows/TA0001-initial-access/IA-01-logons-from-public-ip/), [LM-03](../queries/windows/TA0008-lateral-movement/LM-03-logon-sessions-with-duration/) | 2.4.3, 2.4.4 | Interactive or RDP logons to a DC by accounts that do not administer AD; logons outside office hours. |
| 2.5 | Privileged logons by rarity | [PR-01](../queries/windows/TA0004-privilege-escalation/PR-01-special-privileges-rare-accounts/) | 2.4.23 | 4672 for accounts that rarely or never have admin rights on a DC. |

## 3. Directory changes

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 3.1 | Accounts created, enabled, reset, and privileged group changes | [PE-16](../queries/windows/TA0003-persistence/PE-16-account-and-group-changes/) | 2.4.18 to 2.4.20 | New domain accounts, additions to Domain Admins and other privileged groups, password resets by an unexpected account. |
| 3.2 | Sensitive AD changes | [PR-02](../queries/windows/TA0004-privilege-escalation/PR-02-ad-sensitive-changes/) | 2.4.15 to 2.4.17 | DSRM password changes (4794), AdminSDHolder ACLs (4780), domain policy changes (4739), `DONT_REQ_PREAUTH`, unconstrained delegation, SID history. |
| 3.3 | Group Policy scripts and tasks in SYSVOL | [PE-21](../queries/windows/TA0003-persistence/PE-21-gpo-sysvol-scripts-and-tasks/) | 2.4.17 | New logon scripts, scheduled-task and service preferences in GPOs: the usual way ransomware is pushed to every host. |
| 3.4 | Audit policy changes | [DE-10](../queries/windows/TA0112-defense-impairment/DE-10-audit-policy-and-time-changes/) | 2.4.17 | Subcategories switched off by a user account, outside a GPO refresh. |

## 4. Credential theft from the DC

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 4.1 | DCSync, NTDS and LSASS access | [CA-01](../queries/windows/TA0006-credential-access/CA-01-credential-dumping-events/) | 2.4.22 | 4662 replication rights used by a non-DC account; `ntdsutil`, `vssadmin` shadow copies of `C:\Windows\NTDS`; LSASS access. |
| 4.2 | `ntds.dit` and hive copies on disk | [CA-02](../queries/windows/TA0006-credential-access/CA-02-dump-files-mft/) | 2.1.4 | `ntds.dit`, `SYSTEM` and `SECURITY` copies outside their normal folders, IFM folders. |
| 4.3 | Credential settings and LSA packages | [CA-03](../queries/windows/TA0006-credential-access/CA-03-credential-registry-settings/) | 2.1.2 | Unknown LSA notification or security packages (password filters) on a DC. |

## 5. Movement into and out of the DC

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 5.1 | Lateral movement methods | [LM-01](../queries/windows/TA0008-lateral-movement/LM-01-lateral-movement-methods/), [LM-04](../queries/windows/TA0008-lateral-movement/LM-04-executables-dropped-in-admin-share-paths/) | 2.4.13, 2.4.14 | PsExec-style services, WinRM, RDP; executables dropped through `ADMIN$`. |
| 5.2 | Share access to the DC | [LM-05](../queries/windows/TA0008-lateral-movement/LM-05-share-access/), [LM-06](../queries/windows/TA0008-lateral-movement/LM-06-sum-ual-client-access/) | 2.4.6, 2.3.7 | `C$`/`ADMIN$` from workstations; SYSVOL written to; User Access Logging shows every client and how often it came back. |
| 5.3 | Services and tasks installed on the DC | [PE-05](../queries/windows/TA0003-persistence/PE-05-service-install-events/), [PE-08](../queries/windows/TA0003-persistence/PE-08-scheduled-task-created-4698/) | 2.4.14, 2.4.25 | Anything new on a DC is rare and worth a look. |

## Not covered by these queries

- AD object state: run a collector (BloodHound, PingCastle, `Get-ADObject` exports) for current group members, delegations, `adminCount` and GPO links.
- Directory Service log and replication metadata (`repadmin /showobjmeta`) for when an attribute changed.
- ADCS issued-certificate database and ADFS/Entra Connect logs on those servers.
- DNS server debug/analytic logs.
