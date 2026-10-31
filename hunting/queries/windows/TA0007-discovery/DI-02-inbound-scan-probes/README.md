# DI-02 Inbound scan probes: one remote address hitting many local ports

| | |
|---|---|
| Tactic | TA0007 Discovery |
| ATT&CK | T1046 Network Service Discovery |
| Indexes | `evtxlogs-*` |
| Needs | Security 5156/5157 ("Audit Filtering Platform Connection") |
| Roles | all; most useful on servers and domain controllers, which see every internal scanner |

**What it finds.** Remote addresses that connected, or tried to connect, to 10 or more local ports of a host within 5 minutes. `scope` marks internal versus external sources.

**Reading the output.** An internal source here is usually the machine the attacker is working from; run [DI-01](../DI-01-outbound-port-and-host-scan/) on that host if it was collected. Vulnerability scanners do the same thing on a schedule, so check the source against the client's scanner list. Field meanings are explained in DI-01, including the correction to the earlier `RemoteAddress`/`RemotePorts` query.
