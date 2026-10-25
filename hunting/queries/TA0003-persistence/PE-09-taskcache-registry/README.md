# PE-09 Scheduled tasks in the TaskCache registry key, scored by their actions

| | |
|---|---|
| Tactic | TA0003 Persistence |
| ATT&CK | T1053.005 Scheduled Task |
| Indexes | `registry-*` |
| Needs | RECmd batch CSV that dumps the values of `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{GUID}` (the RD01 DFIRBatch does) |
| Roles | all |

**What it finds.** One row per task GUID with its path, author, description, creation date and action bytes, kept when the score is 3 or more: interpreters or LOLBins in the action (matched as text and as UTF-16LE hex, because RECmd shows the binary `Actions` value as hex), user-writable paths, URLs, tasks outside `\Microsoft\`, tasks at the root of the tree and tasks authored by a user account.

**Reading the output.** The registry copy survives deletion of the task XML file, so a task here with no file in [PE-11](../PE-11-task-xml-files-mft/) was removed from disk or never written there. The RECmd `TaskCache` plugin (`event.dataset: registry.taskcache`) adds `registry.plugin.created_on`, `last_start`, `last_stop` and `last_action_result` per task; search it by the same GUID (`registry.plugin.key_name`).
