# PE-21 Group Policy scripts, scheduled tasks and preferences in SYSVOL

| | |
|---|---|
| Tactic | TA0003 Persistence |
| ATT&CK | T1484.001 Group Policy Modification, T1053.005 Scheduled Task, T1037.003 Network Logon Script, T1552.006 Group Policy Preferences |
| Indexes | `filesystem-*` |
| Needs | MFTECmd `$MFT` and/or `$J` from a domain controller |
| Roles | domain controller |

**What it finds.** Files in `SYSVOL\<domain>\Policies\{GUID}` and `SYSVOL\<domain>\scripts` (NETLOGON): GPP scheduled tasks (`ScheduledTasks.xml`, the common way ransomware operators push a payload to every host), startup/logon script lists and script files, GPP items that can hold a `cpassword`, `Registry.pol`, security templates, and any executable or script stored in SYSVOL. Newest first.

**Reading the output.** A GPO edit changes `gpt.ini` and the item file at the same moment; group rows by `gpo_guid` and `event_time`. Map the GUID to the GPO name with `Get-GPO -Guid` or the `gPCFileSysPath` attribute. Directory Service Changes (Security 5136) show who edited the GPO object, if that auditing is on. Read any `Groups.xml` with a `cpassword` from the collection: the key is public, so the password is effectively plain text.
