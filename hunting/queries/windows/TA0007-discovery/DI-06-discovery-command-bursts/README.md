# DI-06 Bursts of discovery commands from one account

| | |
|---|---|
| Tactic | TA0007 Discovery |
| ATT&CK | T1082 System Information, T1016 Network Configuration, T1049 Network Connections, T1057 Process Discovery, T1033, T1087, T1018 |
| Indexes | `evtxlogs-*` |
| Needs | Security 4688 or Sysmon 1. Works without command-line auditing because it counts image names |
| Roles | all |

**What it finds.** Ten-minute windows in which one (non-machine) account ran four or more different discovery tools: `whoami`, `systeminfo`, `ipconfig`, `netstat`, `net`, `nltest`, `tasklist`, `quser`, `klist`, `dsquery`, AdFind, `setspn`, `gpresult` and others. Hands-on-keyboard intrusions almost always start with such a burst within minutes of the first logon.

**Reading the output.** `account` is the 4688 subject (for Sysmon, the event's user SID). Logon scripts and IT tooling also run several of these at once; they repeat daily at the same time and on many hosts, an intruder's burst does not. Take `first_seen` as a timeline anchor and look at logons just before it ([LM-03](../../TA0008-lateral-movement/LM-03-logon-sessions-with-duration/)).
