# Checklist: Database server

SQL Server hosts, and other database servers running on Windows. Run the [baseline](00-baseline-all-windows-hosts.md) first. The questions are whether the database was reached directly (exposed port, weak `sa` password, abused application credentials), whether it was used to run commands (`xp_cmdshell`, CLR, agent jobs), and whether data was taken or destroyed.

## 1. Host profile

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 1.1 | Database engine, version and instances | [TRI-05](../queries/00-triage/TRI-05-installed-software/) | 1.2.1, 1.2.3 | Unsupported SQL Server versions, Express instances installed by other software. |
| 1.2 | Which applications and hosts connect, and with which logins | | 1.3.1, 1.3.2 | Ask the client; needed to judge rows 2.1 and 3.1. |
| 1.3 | Data sensitivity and where backups go | | 1.2.5, 1.2.6 | Decides the exfiltration and impact priority; backup targets are often encrypted too. |
| 1.4 | Service account of the database engine | [PE-03](../queries/TA0003-persistence/PE-03-services-registry-scoring/) | 1.3.2 | Its rights decide what `xp_cmdshell` gives an attacker. |

## 2. Access to the database

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 2.1 | Failed SQL logins by client and login | [CA-09](../queries/TA0006-credential-access/CA-09-sql-server-failed-logins/) | 2.4.2, 2.4.4 | Brute force against `sa` or other SQL logins, from public or unexpected internal addresses. |
| 2.2 | Windows logons from outside and brute force | [IA-01](../queries/TA0001-initial-access/IA-01-logons-from-public-ip/), [CA-06](../queries/TA0006-credential-access/CA-06-brute-force-then-success/), [CA-05](../queries/TA0006-credential-access/CA-05-password-spraying/) | 2.4.1, 2.4.2 | RDP or SMB logons from addresses that are not the application servers. |
| 2.3 | Inbound scans | [DI-02](../queries/TA0007-discovery/DI-02-inbound-scan-probes/) | 2.4.4 | Probes on 1433/1434 and other ports. |

## 3. Command execution through the database

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 3.1 | `xp_cmdshell`, CLR and configuration changes | [PE-20](../queries/TA0003-persistence/PE-20-sql-server-config-and-xp-cmdshell/) | 2.4 | `sp_configure` enabling `xp_cmdshell`, `clr enabled`, `Ole Automation Procedures`; new CLR assemblies. Agent jobs are in `msdb`, outside the pack. |
| 3.2 | `sqlservr.exe` starting shells and tools | [PE-18](../queries/TA0003-persistence/PE-18-server-process-spawns-shell-4688/), [PE-19](../queries/TA0003-persistence/PE-19-server-process-spawns-shell-sysmon/) | 2.4.5 | `sqlservr.exe` or `sqlagent.exe` starting `cmd`, PowerShell, `certutil`, `bitsadmin`. |
| 3.3 | Tools dropped and run by the service account | [EX-10](../queries/TA0002-execution/EX-10-amcache-long-tail/), [EX-11](../queries/TA0002-execution/EX-11-shimcache-long-tail/), [LM-04](../queries/TA0008-lateral-movement/LM-04-executables-dropped-in-admin-share-paths/) | 2.1.1 | Executables in `\Windows\Temp`, `C:\ProgramData` or the SQL `Binn`/`Backup` folders. |

## 4. Data theft and destruction

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 4.1 | Database backups, exports and archives created | [CO-01](../queries/TA0009-collection/CO-01-archives-and-staged-files/), [CO-02](../queries/TA0009-collection/CO-02-mass-copy-bursts/) | 2.1.4 | `.bak`, `.bacpac`, `.csv`, `.zip`/`.7z` files outside the normal backup schedule or folder. |
| 4.2 | Exfiltration tools and large uploads | [EXF-04](../queries/TA0010-exfiltration/EXF-04-exfil-and-cloud-sync-tools/), [EXF-03](../queries/TA0010-exfiltration/EXF-03-srum-network-usage/), [C2-06](../queries/TA0011-command-and-control/C2-06-outbound-connections-by-application-wfp/) | 2.4.7 | rclone, WinSCP, `curl`; `sqlservr.exe` or a tool with public destinations. |
| 4.3 | Services stopped and shadow copies deleted before encryption | [IM-01](../queries/TA0040-impact/IM-01-inhibit-system-recovery/) | 2.4.9 | `net stop` of SQL services, `vssadmin delete shadows`, backup catalog deleted. |
| 4.4 | Encryption | [IM-02](../queries/TA0040-impact/IM-02-mass-file-renames/), [IM-03](../queries/TA0040-impact/IM-03-ransom-notes/) | 2.1.10 | `.mdf`/`.ldf`/`.bak` renamed to a locker extension; ransom notes in the data folders. |

## Not covered by these queries

- SQL Server `ERRORLOG` files, the default trace (`log_*.trc`), SQL Server Audit (`.sqlaudit`) and Extended Events files: they hold the logins, `sp_configure` calls and executed statements in more detail than the Application log. Collect them from the instance's `Log` folder.
- `msdb` job history and backup history tables.
- Database-level auditing and application logs of the software using the database.
