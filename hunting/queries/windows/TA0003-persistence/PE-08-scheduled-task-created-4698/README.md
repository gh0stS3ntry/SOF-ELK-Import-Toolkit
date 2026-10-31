# PE-08 Scheduled tasks created, updated or deleted (Security 4698-4702)

| | |
|---|---|
| Tactic | TA0003 Persistence |
| ATT&CK | T1053.005 Scheduled Task |
| Indexes | `evtxlogs-*` |
| Needs | Security 4698-4702 (policy "Audit Other Object Access Events"; off by default, often on in hardened builds and on domain controllers) |
| Roles | all |

**What it finds.** Task creation, deletion, enable, disable and update events with the task XML parsed into `command`, `arguments` and `run_as`, scored for interpreter commands, user-writable paths, encoded commands, hidden tasks, tasks outside `\Microsoft\` and SYSTEM tasks.

**Reading the output.** `SubjectLogonId` ties the change to a logon session ([LM-03](../../TA0008-lateral-movement/LM-03-logon-sessions-with-duration/)); a task created over the network shows a type 3 logon for the same account seconds before. When the XML has no `<Command>` (COM handler tasks), `command` holds the whole XML.

**If it errors.** `Unknown column` on `TaskContent` or `TaskContentNew` means no loaded host has 4698 (created) or 4702 (updated) events; replace that field with `null` in the `COALESCE`. RD01 had none of these events.
