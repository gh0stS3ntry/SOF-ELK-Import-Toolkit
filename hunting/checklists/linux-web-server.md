# Checklist: Linux web server

Apache, nginx and lighttpd servers and the applications behind them (PHP, CMSs, Tomcat, Node.js and Python applications behind a reverse proxy). Run the [Linux baseline](linux-baseline-all-hosts.md) first. The questions are whether the application was exploited, what the web server account did afterwards, and whether data was pulled out through the site. The `IR ref` column is approximate, because the IR checklist is written for Windows hosts.

## 1. Host profile

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 1.1 | Which web logs exist and how far back they reach | [LTRI-01](../queries/linux/00-triage/LTRI-01-linux-data-coverage/) | 1.2.3, 2.4 | `apache.access`, `nginx.access` and error logs in `httpdlog-*`; their time range against the incident window. Logs that stop early were rotated away or removed. |
| 1.2 | Web server, application stack and versions | [LTRI-04](../queries/linux/00-triage/LTRI-04-software-installed-and-removed/), [LPE-09](../queries/linux/TA0003-persistence/LPE-09-repositories-and-local-packages/) | 1.2.1, 1.2.3 | Product and version of the web server, PHP, CMS or framework against known exploited CVEs; packages installed from files or outside the repositories. |
| 1.3 | Web roots, virtual hosts and the account the server runs as | | 1.3.2 | Ask the client, or read the server configuration from the collection; needed for rows 2.2 and 3.1. |

## 2. Initial access through the site

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 2.1 | Exploitation attempts and what got a 2xx | [LIA-02](../queries/linux/TA0001-initial-access/LIA-02-web-exploitation-on-linux-web-servers/) | 2.4 | Traversal, injection, upload and deserialisation probes answered with 200; scanner and `curl`/`wget`/`python-requests` user agents. |
| 2.2 | Web shells | [LPE-07](../queries/linux/TA0003-persistence/LPE-07-web-shells-files-and-requests/) | 2.1.4 | Small, new scripts in the web root owned by the web server account and requested by one or two clients, mostly by POST. |
| 2.3 | SSH and FTP logins used to upload or manage the site | [LIA-01](../queries/linux/TA0001-initial-access/LIA-01-remote-logins-from-public-addresses/), [LCA-01](../queries/linux/TA0006-credential-access/LCA-01-brute-force-and-password-spraying/) | 2.4.1 to 2.4.4 | Deploy or FTP accounts logging in from new addresses, brute force against them. |

## 3. After exploitation

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 3.1 | What the web server account ran | [LEX-02](../queries/linux/TA0002-execution/LEX-02-programs-in-temp-hidden-and-user-writable-locations/), [LEX-04](../queries/linux/TA0002-execution/LEX-04-suspicious-command-lines/), [LDI-01](../queries/linux/TA0007-discovery/LDI-01-discovery-command-bursts/) | 2.1.1, 2.4.5 | Programs in the web root or `/tmp` run as `www-data`/`apache`/`nginx`; discovery commands right after the first exploit that returned 2xx. |
| 3.2 | Reverse shells, tunnels and downloads | [LC2-01](../queries/linux/TA0011-command-and-control/LC2-01-reverse-shells-tunnels-and-proxies/), [LC2-03](../queries/linux/TA0011-command-and-control/LC2-03-tool-and-payload-downloads/) | 2.4.7 | `bash -i >& /dev/tcp`, `chisel`/`ligolo` agents, payloads fetched into `/tmp` or served by this host. |
| 3.3 | Privilege escalation from the service account | [LPR-01](../queries/linux/TA0004-privilege-escalation/LPR-01-sudo-su-pkexec-use-failures-and-rules/), [LPR-02](../queries/linux/TA0004-privilege-escalation/LPR-02-setuid-setgid-files-and-permission-changes/) | 2.4.23 | `sudo` attempts by the web account, new setuid files, kernel exploit compilers installed. |
| 3.4 | Persistence beyond the web shell | [LPE-01](../queries/linux/TA0003-persistence/LPE-01-systemd-units-defined-started-and-changed/), [LPE-02](../queries/linux/TA0003-persistence/LPE-02-cron-and-at-jobs-configured-and-run/), [LPE-04](../queries/linux/TA0003-persistence/LPE-04-ssh-authorized-keys-and-their-logins/) | 2.4.14, 2.4.25 | Units, cron jobs and SSH keys added around the time of the exploitation, above all for the web server account. |
| 3.5 | Miners | [LIM-03](../queries/linux/TA0040-impact/LIM-03-cryptominers/) | 2.1.10 | Miner binaries, pools in command lines, OOM kills; the most common outcome of a mass-exploited web application. |
| 3.6 | Data pulled through the site | [LCO-01](../queries/linux/TA0009-collection/LCO-01-archives-dumps-and-staging/), [LEXF-03](../queries/linux/TA0010-exfiltration/LEXF-03-large-transfers-served-by-web-and-ftp/) | 2.4.7 | Archives and database dumps placed in the web root, and the clients that downloaded them. |
| 3.7 | Pivoting into the internal network | [LLM-02](../queries/linux/TA0008-lateral-movement/LLM-02-outbound-remote-access-from-this-host/), [LDI-03](../queries/linux/TA0007-discovery/LDI-03-port-scans-in-firewall-and-audit-records/) | 2.4.13 | SSH and SMB from this host to internal hosts, internal scans. |

## Not covered by these queries

- Application logs (PHP-FPM, Tomcat `catalina.out`, framework logs), WAF and reverse-proxy or load-balancer logs in front of the server. Load ALB logs with the AWS importers; read the others by hand.
- The content of the web root: read suspicious scripts from the collection, and compare the site with a known-good copy from the client's repository.
