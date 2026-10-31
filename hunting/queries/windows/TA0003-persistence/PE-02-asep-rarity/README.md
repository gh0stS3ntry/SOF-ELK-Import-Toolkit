# PE-02 Autostart (ASEP) registry values by rarity across hosts

| | |
|---|---|
| Tactic | TA0003 Persistence |
| ATT&CK | T1547.001 Registry Run Keys, T1546.012 IFEO, T1546.015 COM Hijacking |
| Indexes | `registry-*` |
| Needs | RECmd batch CSV for two or more hosts (same batch file on each) |
| Roles | all; most useful across a fleet of similar workstations or servers |

**What it finds.** The same ASEP locations as [PE-01](../PE-01-asep-registry-scoring/), grouped by type, value name and value data (with user profile names collapsed to `<user>`), sorted by how many hosts have the entry. An entry on one or two hosts out of many is the long tail.

**Reading the output.** `reasons` lists PE-01's flags for that entry. A rare entry with no flags is still worth a look on standard-build fleets; on a single host this query is just PE-01 grouped.
