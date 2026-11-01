# DE-02 Event logs cleared, event log service stopped or disabled

| | |
|---|---|
| Tactic | TA0112 Defense Impairment |
| ATT&CK | T1070.001 Clear Windows Event Logs, T1562.002 Disable Windows Event Logging |
| Indexes | `evtxlogs-*` |
| Needs | Security 1102/1100, System 104/7036/7040; command lines from 4688, Sysmon 1 or 4104 |
| Roles | all |

**What it finds.** Security log cleared (1102), any other log cleared (System 104, the cleared channel is in the event text), the Event Log service stopped or its start type changed, event logging shut down (1100), and `wevtutil cl`, `Clear-EventLog`, `auditpol /clear` and similar commands.

**Reading the output.** The earlier engagement's query, with 1100, 7036 and the command-line sources added. 1100 also appears at every normal shutdown, so it matters only when there is no matching reboot (System 6006/6008/12/13). A 1102 is the start of a gap: whatever happened before it on that log is gone, so check the other channels and the `$MFT` for the time before. `winlog.user.name` on a 1102 is the account that cleared the log.

**If it errors.** `Unknown column` on `param1`, `param2` or `winlog.payload.event_data.string` means no System events with those fields were loaded; replace them with `""`.
