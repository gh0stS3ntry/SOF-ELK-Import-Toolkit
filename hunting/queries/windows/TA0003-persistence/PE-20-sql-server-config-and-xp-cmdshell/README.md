# PE-20 SQL Server configuration changes, xp_cmdshell and CLR use

| | |
|---|---|
| Tactic | TA0003 Persistence |
| ATT&CK | T1505.001 SQL Stored Procedures, T1059.003 Windows Command Shell, T1562.001 Disable or Modify Tools |
| Indexes | `evtxlogs-*` |
| Needs | Application log from the SQL Server host (provider `MSSQLSERVER` or `MSSQL$<instance>`). Event 33205 only exists when SQL Server Audit writes to the Application log |
| Roles | database server; any host with a SQL Server Express instance |

**What it finds.** `sp_configure` changes (15457) with `xp_cmdshell`, OLE Automation, CLR, ad hoc distributed queries and external scripts switched from 0 to 1 scored highest; attempts to use a disabled component (15281); the `xp_cmdshell` DLL being loaded (8128); and audited statements (33205) that run commands, load assemblies, add jobs or create logins and sysadmins.

**Reading the output.** The typical sequence is `show advanced options` 0 to 1, `xp_cmdshell` 0 to 1, the 8128 DLL load, then `cmd.exe` under `sqlservr.exe` in [PE-18](../PE-18-server-process-spawns-shell-4688/) / [PE-19](../PE-19-server-process-spawns-shell-sysmon/), and often both options set back to 0 afterwards. Brute force against SQL logins is [CA-09](../../TA0006-credential-access/CA-09-sql-server-failed-logins/). The SQL Server `ERRORLOG` text files hold the same messages and are not in this pack.

**If it errors.** `Unknown column` on `winlog.payload.event_data.string` means no loaded event has an unnamed data payload, which also means no SQL Server events were loaded.
