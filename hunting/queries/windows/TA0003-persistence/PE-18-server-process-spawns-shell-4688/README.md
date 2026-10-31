# PE-18 Web, database or mail server process starting shells and tools (Security 4688)

| | |
|---|---|
| Tactic | TA0003 Persistence |
| ATT&CK | T1505.003 Web Shell, T1190 Exploit Public-Facing Application, T1059.003 Windows Command Shell |
| Indexes | `evtxlogs-*` |
| Needs | Security 4688 with `ParentProcessName` (Windows 10 / Server 2016+); command lines need "Include command line in process creation events" |
| Roles | web server, database server, Exchange, any application server |

**What it finds.** Child processes of IIS (`w3wp.exe`), Apache/nginx/PHP, Tomcat/Java, Node, SQL Server (`sqlservr.exe`, `sqlagent.exe`), Oracle, PostgreSQL, MySQL, Exchange (`UMWorkerProcess.exe`, `EdgeTransport.exe`), ColdFusion and WebLogic. Shells, reconnaissance commands, LOLBins, binaries in user-writable or web folders and encoded commands score highest. ASP.NET's own `csc.exe` compilations under `w3wp.exe` are removed.

**Reading the output.** A `cmd.exe` or `whoami.exe` under `w3wp.exe` is a web shell until proven otherwise; under `sqlservr.exe` it is `xp_cmdshell` ([PE-20](../PE-20-sql-server-config-and-xp-cmdshell/)). `SubjectUserName` is the application pool or service account. Sysmon 1 is in [PE-19](../PE-19-server-process-spawns-shell-sysmon/).
