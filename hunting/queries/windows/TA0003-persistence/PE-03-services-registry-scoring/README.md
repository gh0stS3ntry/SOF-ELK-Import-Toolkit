# PE-03 Services in the SYSTEM hive, scored (RECmd Services plugin)

| | |
|---|---|
| Tactic | TA0003 Persistence |
| ATT&CK | T1543.003 Windows Service, T1569.002 Service Execution |
| Indexes | `registry-*` |
| Needs | RECmd `Services` plugin CSV (`event.dataset: registry.services`) |
| Roles | all; servers and domain controllers especially |

**What it finds.** Every service and driver with an ImagePath or ServiceDll, scored for drivers outside `System32\drivers`, ServiceDlls outside system folders, remote-execution/RMM/attack tool names (PsExec, PAExec, RemCom, AnyDesk, ScreenConnect, mimidrv...), interpreters in the ImagePath, user-writable paths, encoded commands, URLs, UNC paths, automatic start, missing display name and description, and random-looking names.

**Reading the output.** `registry.plugin.name_key_last_write` is when the service key last changed, which for a new service is close to its installation time. Service creation is also in the event logs: [PE-05](../PE-05-service-install-events/). Remove the `RLIKE` in `f_random` if it flags too many vendor services.

**If it errors.** `Unknown column` on `registry.plugin.service_dll` (or another plugin field) means no loaded host has a service with that value; replace it with `""` in the query.
