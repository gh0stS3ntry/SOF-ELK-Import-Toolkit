# CA-09 SQL Server failed logins (Application 18456), by client and login

| | |
|---|---|
| Tactic | TA0006 Credential Access |
| ATT&CK | T1110.001 Password Guessing, T1110.003 Password Spraying |
| Indexes | `evtxlogs-*` |
| Needs | Application log from the SQL Server host. Failed logins are logged by default; successful logins (18453/18454/18455) only when "Login auditing" is set to "Both failed and successful logins" |
| Roles | database server; any host with SQL Server Express exposed to the network |

**What it finds.** SQL logins per client IP and hour: failures, successes, the login names tried (`sa` is the classic target) and the failure reasons, flagging bursts of 20+ failures and clients with failures followed by a success.

**Reading the output.** A success from a client that was failing is the moment to start the timeline: next look for `xp_cmdshell` being enabled ([PE-20](../../TA0003-persistence/PE-20-sql-server-config-and-xp-cmdshell/)) and shells under `sqlservr.exe` ([PE-18](../../TA0003-persistence/PE-18-server-process-spawns-shell-4688/)). If `client` or `login` shows the whole message, the message text did not match the expected English format; read it in `reasons`.

**If it errors.** `Unknown column` on `winlog.payload.event_data.string` means no loaded event has an unnamed data payload, so no SQL Server Application events were loaded.
