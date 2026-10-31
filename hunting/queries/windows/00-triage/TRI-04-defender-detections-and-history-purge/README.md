# TRI-04 Defender detections per host per day, with history purges

| | |
|---|---|
| Group | Triage (run first) |
| ATT&CK | T1070 (purging detection history after the fact) |
| Indexes | `evtxlogs-*` |
| Needs | Defender Operational 1116/1117; 1013 if you want the purge correlation |
| Roles | all |

**What it finds.** One row per host, day, path and threat: how many detections (1116) and actions (1117) there were, the first detection time, and whether the Defender history was purged (1013) within 24 hours after that first detection.

**Reading the output.** Defender also purges its history on a schedule, so a 1013 on its own means little. A `deletions_1013_within_24h` above zero right after a detection, especially by a user rather than SYSTEM (open the 1013 event in [TRI-03](../TRI-03-defender-events/)), suggests someone cleaning up. `DATE_TRUNC(1 day, ...)` buckets in UTC; use `@timestamp + 8 hours` (or your offset) to bucket by local day.

**Syntax note.** Uses `INLINE STATS` (ES 9.x). Older builds spell it `INLINESTATS`.
