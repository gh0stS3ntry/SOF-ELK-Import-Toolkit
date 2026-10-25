# PE-15 Permanent WMI event subscriptions

| | |
|---|---|
| Tactic | TA0003 Persistence |
| ATT&CK | T1546.003 Windows Management Instrumentation Event Subscription |
| Indexes | `evtxlogs-*` |
| Needs | `Microsoft-Windows-WMI-Activity/Operational` 5861 (Windows 10 / Server 2016+). Sysmon 19/20/21 are added when present |
| Roles | all |

**What it finds.** Every permanent filter-to-consumer binding, with its consumer type, the filter name and the consumer definition (the `CommandLineTemplate` or `ScriptText` the attacker set). Scored for command-line and script consumers, interpreters, user-writable paths, encoded commands, URLs, script files and timer/boot/logon triggers. The default Windows binding (`SCM Event Log Filter` to `SCM Event Log Consumer`) scores 0 and is listed last.

**Reading the output.** 5861 is logged when the binding is created and again at each WMI service start while it exists, so the earliest `@timestamp` per `filter_name` is the creation. WMI subscriptions run as SYSTEM in `WmiPrvSE.exe` / `scrcons.exe`; [EX-09](../../TA0002-execution/EX-09-wmi-execution/) shows what they launched. On disk the subscription lives in `C:\Windows\System32\wbem\Repository\OBJECTS.DATA`, which this pack does not parse.

**If it errors.** `Unknown column` on `winlog.payload.user_data.Operation_ESStoConsumerBinding.*` means no loaded host has a 5861 event; there is nothing to find in the event logs then.
