# EX-09 Suspicious WMI execution

| | |
|---|---|
| Tactic | TA0002 Execution |
| ATT&CK | T1047 Windows Management Instrumentation, T1546.003 WMI Event Subscription, T1220 XSL Script Processing |
| Indexes | `evtxlogs-*` |
| Needs | WMI-Activity Operational (5858 failures, 5860 temporary and 5861 permanent subscriptions) and PowerShell 4104 on at least one loaded host. Security 4688 and Sysmon 1/19/20/21 are added when present |
| Roles | all |

**What it finds.** WMI used to run code: `wmic process call create` and `Win32_Process` creation, remote WMI (`/node:`, `-ComputerName`, CIM sessions), `wmic /format:` XSL loading, shadow copy deletion through WMI, `wmic` reconnaissance, shells spawned by `WmiPrvSE.exe`, `scrcons.exe`, and permanent or temporary event subscriptions.

**Reading the output.** A 5861 (permanent binding) with a command-line or script consumer is persistence; see [PE-15](../../TA0003-persistence/PE-15-wmi-event-subscriptions/). A 5858 failure records the client machine, user and the operation that failed (`wmi_client`, `wmi_user`), which often exposes an attacker's WMI query; a remote `wmi_client` on a 5858 or 5860 is remote WMI. The WMI text comes from the events' UserData: `Operation_ESStoConsumerBinding.CONSUMER` (5861), `Operation_TemporaryEssStarted.Query` (5860) and `Operation_ClientFailure.Operation` (5858).

**Pivot.** For a hit at time T, re-run with `| WHERE @timestamp >= "T-10m" AND @timestamp <= "T+10m"` on the same `_index`, and add `Microsoft-Windows-WinRM/Operational` 91/169 to see the remote session that drove it.

**If it errors.** `Unknown column` on a `winlog.payload.user_data.Operation_*` or `ScriptBlockText` field means no loaded host has that event ID; delete the matching `COALESCE` line (and the `wmi_client` / `wmi_user` parts for 5858/5860).
