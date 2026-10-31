# C2-06 Outbound connections to public addresses, per application (WFP 5156)

| | |
|---|---|
| Tactic | TA0011 Command and Control |
| ATT&CK | T1071 Application Layer Protocol, T1571 Non-Standard Port, T1095 Non-Application Layer Protocol |
| Indexes | `evtxlogs-*` |
| Needs | Security 5156 ("Audit Filtering Platform Connection"), outbound direction |
| Roles | all |

**What it finds.** Per host and program: connections to public IP addresses, how many distinct destinations and which ports, the time range, and on how many hosts that program talks to the internet. Interpreters and LOLBins (`powershell`, `rundll32`, `regsvr32`, `mshta`, `dllhost`, `notepad`...), programs in user-writable folders, ports other than 80/443/53/123, programs on one host only and many connections to few destinations (beaconing) score higher.

**Reading the output.** `dests` are IPs only; WFP does not log names. Look them up in DNS-Client or proxy logs and threat intel. Field names are the WFP ones (`DestAddress`, `DestPort`, `Direction`, `Application`); see the note in [DI-01](../../TA0007-discovery/DI-01-outbound-port-and-host-scan/).

**If it errors.** `Unknown column` on `DestAddress` or `Direction` means no 5156 events were loaded.
