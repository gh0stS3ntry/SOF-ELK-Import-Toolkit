# EX-06 PowerShell commands in time order, with user and host application

| | |
|---|---|
| Tactic | TA0002 Execution |
| ATT&CK | T1059.001 PowerShell |
| Indexes | `evtxlogs-*` |
| Needs | `Windows PowerShell` 400/403/600/800 or PowerShell Operational 4103 |
| Roles | all |

**What it finds.** A timeline of PowerShell engine and pipeline events: the host application (`HostApplication=`, the full `powershell.exe ...` command), the pipeline command (`CommandLine=`, event 800/4103), the user (`UserId=`, event 800) and how PowerShell was hosted (`HostName=`: `ConsoleHost`, `ServerRemoteHost` for remoting, `Default Host` for embedded runspaces).

**Reading the output.** `ServerRemoteHost` is PowerShell remoting into this host: correlate with [LM-01](../../TA0008-lateral-movement/LM-01-lateral-movement-methods/). `user_account` is only present on 800 events; 400/600 do not carry it.

**Tuning.** The exclusions remove a bare `powershell.exe`, SQL Server Agent's SQLPS, Server Manager, a CrowdStrike RTR artefact and KAPE collection. Change the `KAPE` lines to match the collection tooling of your engagement.
