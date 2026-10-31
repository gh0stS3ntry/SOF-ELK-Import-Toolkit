# DE-10 Audit policy reduced, system time changed

| | |
|---|---|
| Tactic | TA0112 Defense Impairment |
| ATT&CK | T1562.002 Disable Windows Event Logging, T1070.006 Timestomp (system time) |
| Indexes | `evtxlogs-*` |
| Needs | Security 4719, 4912, 4715, 4906 and 4616; `auditpol` / `Set-Date` commands from 4688, Sysmon 1 or 4104 |
| Roles | all; domain controllers for policy changes pushed by GPO |

**What it finds.** Audit policy changes (4719), with removal of success or failure auditing (`%%8448` / `%%8450`) called out, per-user audit policy, audit-policy security descriptor and CrashOnAuditFail changes, `auditpol /set` and `/clear`, and system time changes (4616) other than small corrections by the time service or hypervisor tools.

**Reading the output.** A 4719 at every Group Policy refresh is normal on some estates; the same subcategory being switched off by a user account rather than `SYSTEM`, or outside a GPO refresh, is not. `SubcategoryGuid` names the subcategory; Microsoft's "Audit Policy Subcategory GUIDs" list translates it. A large time shift makes every later timestamp on that host wrong until the next sync, so note `shift_minutes` before building the timeline.

**If it errors.** `TO_DATETIME` returns `null` (with a warning) when `PreviousTime`/`NewTime` are not ISO-8601; the rows still show and `shift_minutes` is empty.
