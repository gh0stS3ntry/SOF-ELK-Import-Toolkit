# TRI-01 Data coverage per index

| | |
|---|---|
| Group | Triage (run first) |
| Indexes | every toolkit index family |
| Needs | nothing |
| Roles | all |

**What it finds.** One row per index: document count and the earliest and latest `@timestamp`. It tells you, before you hunt, which artifact families each host has, so you know which queries in this pack can return anything for that host.

**Reading the output.** `host` is the part of the index name after the prefix, so `srum-dps-web-1` is host `dps-web-1`. `ingest_time_docs` counts documents whose `@timestamp` fell back to the load time because the row had no usable date (toolkit custom indexes only). A high `ingest_time_pct`, or a `first_event`/`last_event` equal to the day you loaded the data, means that index has no usable timeline. For event logs, check `no_event_time` in [TRI-02](../TRI-02-event-log-coverage/).

**If it errors.** ES|QL skips wildcard patterns that match nothing, but fails if none of them match. If your cluster still rejects a pattern, remove it from `FROM`.

**Next.** Run [TRI-02](../TRI-02-event-log-coverage/) to see which event log sources each host has.
