# Checklist: Linux internet-facing server

Linux hosts that expose a service to the internet: web servers and applications behind them, SSH bastions, FTP servers, VPN gateways. Run the [baseline](linux-baseline-all-hosts.md) first. These rows add the attack paths that come through the exposed service. The `IR ref` column is approximate (the IR checklist is written for Windows hosts).

## 1. The exposed service

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 1.1 | Which logs exist for the exposed services | [LTRI-01](../queries/linux/00-triage/LTRI-01-linux-data-coverage/) | 1.2.3 | `apache.access`, `nginx.access`, `ftp.*`, sshd lines; the time range of each. |
| 1.2 | Web server, application and their versions | [LTRI-04](../queries/linux/00-triage/LTRI-04-software-installed-and-removed/), [LPE-09](../queries/linux/TA0003-persistence/LPE-09-repositories-and-local-packages/) | 1.2.3 | Product and version of the web server, CMS or framework against known exploited CVEs; packages installed outside the repositories. |

## 2. Initial access through the service

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 2.1 | Web exploitation attempts and what got a 2xx | [LIA-02](../queries/linux/TA0001-initial-access/LIA-02-web-exploitation-on-linux-web-servers/) | 2.4 | Traversal, injection and probes answered with 200; scanner and `curl`/`wget` user agents. |
| 2.2 | Web shells | [LPE-07](../queries/linux/TA0003-persistence/LPE-07-web-shells-files-and-requests/) | 2.1.4 | Small, new scripts in the web root owned by the web server account and requested by one or two clients, mostly by POST. |
| 2.3 | SSH and FTP brute force and logins | [LCA-01](../queries/linux/TA0006-credential-access/LCA-01-brute-force-and-password-spraying/), [LIA-01](../queries/linux/TA0001-initial-access/LIA-01-remote-logins-from-public-addresses/) | 2.4.1 to 2.4.4 | Success after failures; FTP logins from the internet. |

## 3. After exploitation

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 3.1 | What the service account ran | [LEX-02](../queries/linux/TA0002-execution/LEX-02-programs-in-temp-hidden-and-user-writable-locations/), [LEX-04](../queries/linux/TA0002-execution/LEX-04-suspicious-command-lines/), [LDI-01](../queries/linux/TA0007-discovery/LDI-01-discovery-command-bursts/) | 2.1.1, 2.4.5 | Programs in the web root or `/tmp` run as `www-data`/`apache`/`nginx`; discovery right after the first 2xx exploit. |
| 3.2 | Reverse shells, tunnels and downloads | [LC2-01](../queries/linux/TA0011-command-and-control/LC2-01-reverse-shells-tunnels-and-proxies/), [LC2-03](../queries/linux/TA0011-command-and-control/LC2-03-tool-and-payload-downloads/) | 2.4.7 | `bash -i >& /dev/tcp`, `chisel`/`ligolo` agents, payloads fetched into `/tmp` or served by this host. |
| 3.3 | Persistence beyond the web shell | [LPE-01](../queries/linux/TA0003-persistence/LPE-01-systemd-units-defined-started-and-changed/), [LPE-02](../queries/linux/TA0003-persistence/LPE-02-cron-and-at-jobs-configured-and-run/), [LPE-04](../queries/linux/TA0003-persistence/LPE-04-ssh-authorized-keys-and-their-logins/) | 2.4.14, 2.4.25 | Units, cron jobs and SSH keys added around the exploitation time. |
| 3.4 | Miners | [LIM-03](../queries/linux/TA0040-impact/LIM-03-cryptominers/) | 2.1.10 | Miner binaries, pools in command lines, OOM kills; the most common outcome of a mass-exploited web or Redis/Docker service. |
| 3.5 | Data pulled through the service | [LCO-01](../queries/linux/TA0009-collection/LCO-01-archives-dumps-and-staging/), [LEXF-03](../queries/linux/TA0010-exfiltration/LEXF-03-large-transfers-served-by-web-and-ftp/) | 2.4.7 | Archives and database dumps in the web root, and the clients that downloaded them; large FTP downloads. |
| 3.6 | Pivoting into the internal network | [LLM-02](../queries/linux/TA0008-lateral-movement/LLM-02-outbound-remote-access-from-this-host/), [LDI-03](../queries/linux/TA0007-discovery/LDI-03-port-scans-in-firewall-and-audit-records/) | 2.4.13 | SSH and SMB from this host to internal hosts, internal scans. |

## Not covered by these queries

- Application logs other than Apache, nginx, lighttpd and FTP access logs (PHP-FPM, Tomcat, application frameworks, databases), WAF and reverse-proxy logs in front of the server, and the web root's content itself (read suspicious scripts from the collection).
