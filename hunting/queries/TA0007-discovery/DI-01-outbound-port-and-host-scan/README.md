# DI-01 Outbound scanning from a host: many ports or many internal hosts

| | |
|---|---|
| Tactic | TA0007 Discovery |
| ATT&CK | T1046 Network Service Discovery, T1018 Remote System Discovery |
| Indexes | `evtxlogs-*` |
| Needs | Security 5156 (allowed) / 5157 (blocked) from policy "Audit Filtering Platform Connection" (off by default; very noisy when on). Not in RD01 |
| Roles | all |

**What it finds.** Per host, program and 5 minutes: outbound connections to private addresses touching 10 or more ports, or 10 or more hosts, with at least 20 connections. `pattern` says which.

**Reading the output.** `app` is the program that made the connections (`\device\harddiskvolume3\users\public\netscan.exe`). Backup, monitoring and inventory agents sweep the network legitimately; a user-path program or `powershell.exe` doing it is not. `blocked` counts 5157 drops, which during a scan are often most of the traffic.

**Correction to the earlier engagement's query.** That query used `RemoteAddress` and `RemotePorts`, which 5156/5157 do not have. The WFP fields are `SourceAddress`/`SourcePort` (this host), `DestAddress`/`DestPort` (the other side), `Direction` (`%%14592` inbound, `%%14593` outbound), `Protocol` and `Application`. The old query could never have returned rows.

**If it errors.** `Unknown column` on `DestAddress` or `Direction` means no 5156/5157 events were loaded.
