# TRI-03 Microsoft Defender detections, failures and tampering

| | |
|---|---|
| Group | Triage (run first) |
| ATT&CK | detections of any technique; T1562.001 for the tampering events |
| Indexes | `evtxlogs-*` |
| Needs | `Microsoft-Windows-Windows Defender/Operational` |
| Roles | all |

**What it finds.** Every Defender event that matters in a first pass: detections (1006/1116), actions and failed actions (1007/1117, 1008/1118/1119), quarantine restores (1009), behaviour and ASR / Controlled Folder Access / Network Protection hits, protection being turned off (5001/5010/5012), Tamper Protection blocks (5013), history purges (1013), and configuration changes (5007) that touch exclusions.

**Reading the output.** `severity` is High for failures, protection disabled, tamper blocks and history purges. A detection whose `Action Name` failed, or an exclusion added just before a detection disappears, is a strong lead. `Path` and `Process Name` give the file and the process that touched it; pivot on them in [EX-15](../../TA0002-execution/EX-15-execution-evidence-pivot/) and the `$MFT`.

**Tuning.** Remove the `WHERE eid != "5007" ...` line to see every configuration change. If a column errors with `Unknown column`, no loaded host has that Defender field; drop it from `KEEP`.

**Next.** [TRI-04](../TRI-04-defender-detections-and-history-purge/) puts detections per host per day next to any history purge.
