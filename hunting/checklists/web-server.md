# Checklist: Web server

IIS (including Exchange OWA/ECP and SharePoint), Tomcat, Apache/PHP and other internet-facing application servers. Run the [baseline](00-baseline-all-windows-hosts.md) first. On a web server the usual question is whether the application was exploited, whether a web shell was planted, and what the worker process ran afterwards.

## 1. Host profile

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 1.1 | Applications hosted, their versions and web roots | [TRI-05](../queries/windows/00-triage/TRI-05-installed-software/) | 1.2.3 | Product and version (Exchange CU, Confluence, MOVEit and similar) against known exploited CVEs; the web root paths for row 2.2. |
| 1.2 | What is exposed to the internet, and through what (WAF, reverse proxy, load balancer) | | 1.3.1 | Decides whether client IPs in the logs are real or the proxy's. |
| 1.3 | Application pool identities and service accounts | [PR-01](../queries/windows/TA0004-privilege-escalation/PR-01-special-privileges-rare-accounts/) | 1.3.2 | Accounts the web application runs as; their rights decide what an attacker got. |

## 2. Exploitation and web shells

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 2.1 | Exploitation signs in Application and IIS-related events | [IA-04](../queries/windows/TA0001-initial-access/IA-04-web-app-exploitation-events/) | 2.4 | ViewState validation failures, deserialization gadgets in exceptions, `w3wp.exe` crashes, IIS module changes. |
| 2.2 | Script files in web roots | [PE-17](../queries/windows/TA0003-persistence/PE-17-web-shell-files/) | 2.1.4 | New `.aspx`/`.ashx`/`.jsp`/`.php` files, especially small ones, in `aspnet_client`, OWA `auth` folders or upload directories. |
| 2.3 | Web server process starting shells and tools | [PE-18](../queries/windows/TA0003-persistence/PE-18-server-process-spawns-shell-4688/), [PE-19](../queries/windows/TA0003-persistence/PE-19-server-process-spawns-shell-sysmon/) | 2.4.5 | `w3wp.exe`, `tomcat*.exe`, `httpd.exe` or `php-cgi.exe` starting `cmd`, PowerShell, `whoami`, `certutil`, `net`. |
| 2.4 | Files written by the worker process, around the exploitation time | [CO-01](../queries/windows/TA0009-collection/CO-01-archives-and-staged-files/), [DE-01](../queries/windows/TA0112-defense-impairment/DE-01-timestomping/) | 2.1.4 | Archives of web roots or databases, tools in `\Windows\Temp` or `C:\ProgramData`, timestomped web shells. |
| 2.5 | Inbound scans and probes | [DI-02](../queries/windows/TA0007-discovery/DI-02-inbound-scan-probes/), [IA-01](../queries/windows/TA0001-initial-access/IA-01-logons-from-public-ip/) | 2.4.4 | One public address hitting many ports; logons from public addresses (the application should not need them). |

## 3. After the foothold

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 3.1 | Credential dumping from the server | [CA-01](../queries/windows/TA0006-credential-access/CA-01-credential-dumping-events/), [CA-02](../queries/windows/TA0006-credential-access/CA-02-dump-files-mft/) | 2.4.22 | LSASS dumps written by `w3wp.exe` (comsvcs.dll MiniDump, procdump). |
| 3.2 | Persistence beyond the web shell | [PE-05](../queries/windows/TA0003-persistence/PE-05-service-install-events/), [PE-08](../queries/windows/TA0003-persistence/PE-08-scheduled-task-created-4698/), [PE-16](../queries/windows/TA0003-persistence/PE-16-account-and-group-changes/) | 2.4.14, 2.4.25 | Services, tasks and local accounts created by the application pool identity. |
| 3.3 | Outbound connections from the server | [C2-06](../queries/windows/TA0011-command-and-control/C2-06-outbound-connections-by-application-wfp/), [C2-07](../queries/windows/TA0011-command-and-control/C2-07-sysmon-network-connections/), [C2-05](../queries/windows/TA0011-command-and-control/C2-05-remote-access-and-tunnel-tools/) | 2.4.7 | A web server rarely starts outbound connections; any from `w3wp.exe`, PowerShell or a tunnel tool matter. |
| 3.4 | Lateral movement from the DMZ | [LM-01](../queries/windows/TA0008-lateral-movement/LM-01-lateral-movement-methods/), [DI-01](../queries/windows/TA0007-discovery/DI-01-outbound-port-and-host-scan/) | 2.4.13 | RDP, SMB and WinRM from this server into the internal network; internal port scans. |
| 3.5 | Firewall and portproxy changes | [DE-05](../queries/windows/TA0112-defense-impairment/DE-05-firewall-rule-changes-events/), [DE-06](../queries/windows/TA0112-defense-impairment/DE-06-firewall-rules-registry/), [LM-02](../queries/windows/TA0008-lateral-movement/LM-02-portproxy-and-remote-access-settings/) | 2.4.26, 2.4.27 | Inbound allow rules and portproxy entries that turn the server into a pivot. |

## Not covered by these queries

- IIS, Apache and Tomcat access logs (`u_ex*.log`, `access_log`): the request that dropped or used the web shell. Review them separately and match the times from rows 2.1 to 2.3.
- HTTPERR logs, Exchange `HttpProxy` and `MSExchange Management` logs.
- WAF and reverse-proxy logs for the real client IP.
