# DI-03 Port scanning and network probing with PowerShell or command-line tools

| | |
|---|---|
| Tactic | TA0007 Discovery |
| ATT&CK | T1046 Network Service Discovery, T1018 Remote System Discovery, T1059.001 PowerShell |
| Indexes | `evtxlogs-*` |
| Needs | PowerShell Operational 4104 on at least one loaded host; Security 4688 and Sysmon 1 add scanner command lines |
| Roles | all |

**What it finds.** `Test-NetConnection`, raw `TcpClient` sockets, `Test-Connection` sweeps, ranges like `1..254` / `1..1024`, `Invoke-Portscan`, and scanner tools (`nmap`, `masscan`, Advanced IP Scanner, SoftPerfect NetScan, Angry IP Scanner, `portqry`, netcat) in script blocks and process command lines.

**Reading the output.** `f_loop` with a socket or connection test is a hand-written scanner. The network result is in [DI-01](../DI-01-outbound-port-and-host-scan/) when WFP auditing is on. Tool use without command lines shows up in [EX-10](../../TA0002-execution/EX-10-amcache-long-tail/) and [EX-13](../../TA0002-execution/EX-13-prefetch-rare-executables/).

**If it errors.** `Unknown column` on `ScriptBlockText` means no 4104 events were loaded; delete that line.
