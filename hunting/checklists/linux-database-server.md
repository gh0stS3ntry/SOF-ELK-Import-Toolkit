# Checklist: Linux database server

MySQL/MariaDB, PostgreSQL, MongoDB, Redis and Elasticsearch servers running on Linux. Run the [Linux baseline](linux-baseline-all-hosts.md) first. The questions are whether the database was reached directly (an exposed port, a weak or missing password, application credentials reused), whether the database was used to run commands or write files, and whether data was dumped, taken or destroyed. Database engines' own logs are not loaded by the toolkit, so most rows read the host's view of what happened. The `IR ref` column is approximate, because the IR checklist is written for Windows hosts.

## 1. Host profile

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 1.1 | Database engine, version and how it was installed | [LTRI-04](../queries/linux/00-triage/LTRI-04-software-installed-and-removed/), [LPE-09](../queries/linux/TA0003-persistence/LPE-09-repositories-and-local-packages/) | 1.2.1, 1.2.3 | Unsupported versions, engines installed from vendor repositories or tarballs, Redis or MongoDB on a host that should not run them. |
| 1.2 | Which applications and hosts connect, and with which accounts | | 1.3.1, 1.3.2 | Ask the client; needed to judge rows 2.1 and 2.2. Whether the port was reachable from the internet decides how much of section 2 matters. |
| 1.3 | Data sensitivity and where backups go | | 1.2.5, 1.2.6 | Decides the exfiltration and impact priority; dump folders and backup targets are often hit too. |

## 2. Access

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 2.1 | SSH logins and brute force | [LIA-01](../queries/linux/TA0001-initial-access/LIA-01-remote-logins-from-public-addresses/), [LCA-01](../queries/linux/TA0006-credential-access/LCA-01-brute-force-and-password-spraying/), [LLM-01](../queries/linux/TA0008-lateral-movement/LLM-01-inbound-sessions-with-duration/) | 2.4.1 to 2.4.4 | Logins from addresses that are not the DBAs' or the application servers', success after failures. |
| 2.2 | Scans of the database ports | [LDI-03](../queries/linux/TA0007-discovery/LDI-03-port-scans-in-firewall-and-audit-records/), [LC2-02](../queries/linux/TA0011-command-and-control/LC2-02-outbound-destinations-firewall-audit-vpn/) | 2.4.4 | Probes on 3306, 5432, 6379, 27017, 9200 in firewall logs and audited connections; outbound connections from the engine's account. |

## 3. Command execution through the database

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 3.1 | Commands run as the database account | [LEX-02](../queries/linux/TA0002-execution/LEX-02-programs-in-temp-hidden-and-user-writable-locations/), [LEX-04](../queries/linux/TA0002-execution/LEX-04-suspicious-command-lines/), [LDI-01](../queries/linux/TA0007-discovery/LDI-01-discovery-command-bursts/) | 2.1.1, 2.4.5 | `mysql`, `postgres`, `redis` or `mongodb` running shells, downloads or discovery commands (PostgreSQL `COPY ... FROM PROGRAM`, MySQL UDFs); programs in `/tmp` or the data folder. |
| 3.2 | Files written by the engine into persistence locations | [LPE-02](../queries/linux/TA0003-persistence/LPE-02-cron-and-at-jobs-configured-and-run/), [LPE-04](../queries/linux/TA0003-persistence/LPE-04-ssh-authorized-keys-and-their-logins/), [LPE-01](../queries/linux/TA0003-persistence/LPE-01-systemd-units-defined-started-and-changed/) | 2.4.14, 2.4.25 | Cron files and `authorized_keys` changed with no matching admin session (the Redis `CONFIG SET dir` abuse writes them as the `redis` user), new units. |
| 3.3 | Miners | [LIM-03](../queries/linux/TA0040-impact/LIM-03-cryptominers/) | 2.1.10 | Exposed Redis, MongoDB and PostgreSQL are mass-exploited for mining: miner binaries, pools, OOM kills. |
| 3.4 | Reverse shells and tunnels | [LC2-01](../queries/linux/TA0011-command-and-control/LC2-01-reverse-shells-tunnels-and-proxies/), [LC2-03](../queries/linux/TA0011-command-and-control/LC2-03-tool-and-payload-downloads/) | 2.4.7 | Shells back to the attacker started by the database account, tools downloaded into `/tmp` or `/dev/shm`. |

## 4. Data theft and destruction

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 4.1 | Dumps and archives created | [LCO-01](../queries/linux/TA0009-collection/LCO-01-archives-dumps-and-staging/), [LCO-02](../queries/linux/TA0009-collection/LCO-02-file-creation-bursts/) | 2.1.4 | `mysqldump`, `pg_dump`, `mongodump`, `redis-cli --rdb` runs and their output outside the normal backup schedule or folder. |
| 4.2 | Exfiltration tools and destinations | [LEXF-01](../queries/linux/TA0010-exfiltration/LEXF-01-exfiltration-tools-and-commands/), [LEXF-02](../queries/linux/TA0010-exfiltration/LEXF-02-file-sharing-and-paste-sites/), [LC2-02](../queries/linux/TA0011-command-and-control/LC2-02-outbound-destinations-firewall-audit-vpn/) | 2.4.7 | `rclone`, `curl -T`, `scp` to outside hosts; file-sharing sites; rare outbound destinations. |
| 4.3 | Databases dropped, services stopped, data wiped | [LIM-01](../queries/linux/TA0040-impact/LIM-01-destructive-commands/) | 2.4.9 | `DROP DATABASE`, database services stopped or masked, data folders deleted; often followed by a ransom note in a new table or database. |
| 4.4 | Encryption | [LIM-02](../queries/linux/TA0040-impact/LIM-02-ransomware-notes-and-encryption/) | 2.1.10 | Data files renamed to a locker extension, ransom notes in the data folders. |
| 4.5 | Logs and history removed | [LDE-01](../queries/linux/TA0112-defense-impairment/LDE-01-log-and-history-tampering/) | 2.4.21 | `.mysql_history`, `.psql_history` and `.rediscli_history` emptied or linked to `/dev/null`. |

## Not covered by these queries

- The engines' own logs and audit trails: MySQL general and error logs and the audit plugin, PostgreSQL logs (`log_statement`, `log_connections`), MongoDB and Redis logs, Elasticsearch audit logs. They hold the logins and statements; collect them from the data or log folder and read them, or load them as generic CSV where they can be exported.
- The data itself: look in the database for ransom-note tables, unknown accounts and changed grants.
