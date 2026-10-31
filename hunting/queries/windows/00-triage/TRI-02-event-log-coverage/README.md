# TRI-02 Event log sources per host

| | |
|---|---|
| Group | Triage (run first) |
| Indexes | `evtxlogs-*` |
| Needs | nothing |
| Roles | all |

**What it finds.** For each host, which event log sources were collected (process creation, PowerShell, logons, Kerberos, WFP, shares, RDP, Defender, SQL Server, IIS, ...), how many events each has, and over what time span. Everything else lands in `Other: <channel>`.

**Reading the output.** This is the answer to "which queries will work for this host". No `Process creation: Security 4688` row means the EX/PE queries built on 4688 have nothing to search; no `Sysmon` row means the same for the Sysmon variants. `no_event_time` counts events whose `TimeCreated` could not be parsed, so their `@timestamp` is the load time (for example a CSV that was opened and re-saved in Excel). Treat those hosts' event times as unusable and re-export.

**Why it matters for the other queries.** ES|QL fails with `Unknown column` when a query names a field that exists in none of the indexes it reads. Event-data fields such as `winlog.payload.event_data.CommandLine` only exist once at least one loaded event carries them. The README of each query lists what it needs, and this query tells you whether you have it.
