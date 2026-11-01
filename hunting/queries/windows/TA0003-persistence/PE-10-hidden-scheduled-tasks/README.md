# PE-10 Hidden scheduled tasks: TaskCache\Tree entries with no security descriptor

| | |
|---|---|
| Tactic | TA0003 Persistence |
| ATT&CK | T1053.005 Scheduled Task, T1564 Hide Artifacts |
| Indexes | `registry-*` |
| Needs | RECmd batch CSV that dumps `TaskCache\Tree\<task>` values (`Id`, `Index`, `SD`). The RD01 DFIRBatch did not, so this returns nothing there |
| Roles | all |

**What it finds.** Tasks whose `Tree` key has an `Id` but no `SD` value, or `Index` set to 0. Deleting `SD` (the Tarrask technique Microsoft described in 2022) keeps the task running but hides it from `schtasks /query` and the Task Scheduler console; it needs SYSTEM.

**Reading the output.** Put `task_id` (the task GUID) into [PE-09](../PE-09-taskcache-registry/) to see its actions, and `task_name` into [PE-07](../PE-07-task-scheduler-per-task/) for its run history.
