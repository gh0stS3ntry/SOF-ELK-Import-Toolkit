# Checklist: Baseline (all Windows hosts)

Run this on every host before its role checklist. Sections 1 and 2 tell you what the host is and what evidence exists, which decides how much the later rows can show. Sections 3 to 8 are the first-cut hunts that apply to any Windows host. Put every finding on the engagement timeline as you go (IR checklist: "Build Timeline Skeleton").

## 1. Host profile

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 1.1 | Hostname, IP addresses, domain and role (what is this machine used for?) | | 1.2.3, 1.2.4 | Ask the client; confirm the role from installed software and services. The role picks the extra checklist. |
| 1.2 | Operating system and patch level | [TRI-05](../queries/00-triage/TRI-05-installed-software/) | 1.2.1, 2.3.1 | Unsupported or unpatched OS versions; internet-facing software with known exploited CVEs. |
| 1.3 | Installed software, newest first | [TRI-05](../queries/00-triage/TRI-05-installed-software/) | 2.1.3 | Software installed during the incident window, remote-access tools, software on this host only. |
| 1.4 | Sensitive data stored and backups | | 1.2.5, 1.2.6 | Ask the client; decides the exfiltration and impact rows. |
| 1.5 | Privileged and service accounts, known-good and known-bad IP addresses | | 1.3.2 to 1.3.5 | Ask the client for these lists early. Put them in the `// EDIT:` lists of the pivot queries. |
| 1.6 | Antivirus/EDR product installed | [TRI-05](../queries/00-triage/TRI-05-installed-software/), [TRI-03](../queries/00-triage/TRI-03-defender-events/) | 2.3.11 | Whether Defender was the active product; third-party AV logs must be collected separately. |

## 2. Evidence coverage

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 2.1 | Which artifact families were loaded for this host, and their time range | [TRI-01](../queries/00-triage/TRI-01-data-coverage/) | | Missing families (no `$J`, no SRUM, no browser history) and the earliest date each one reaches. |
| 2.2 | Which event log channels and event IDs exist, and from when | [TRI-02](../queries/00-triage/TRI-02-event-log-coverage/) | 2.4 | Whether 4688 (and its command line), Sysmon, PowerShell 4104, 5156, 5140/5145 and 4698 are present. A Security log that starts during the incident means it rolled over or was cleared. |
| 2.3 | Event logs cleared, logging stopped or reduced | [DE-02](../queries/TA0112-defense-impairment/DE-02-event-log-clearing/), [DE-10](../queries/TA0112-defense-impairment/DE-10-audit-policy-and-time-changes/), [DE-04](../queries/TA0112-defense-impairment/DE-04-security-tool-tampering-registry/) | 2.4.21 | 1102/104, Event Log service stopped, audit subcategories switched off, channels disabled. Each one marks a gap in the evidence. |
| 2.4 | System time changes | [DE-10](../queries/TA0112-defense-impairment/DE-10-audit-policy-and-time-changes/) | | A large shift makes later timestamps on this host wrong until the next sync. |

## 3. Antivirus and security tooling

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 3.1 | Defender detections, failed actions, protection turned off | [TRI-03](../queries/00-triage/TRI-03-defender-events/), [TRI-04](../queries/00-triage/TRI-04-defender-detections-and-history-purge/) | 2.1.8 | The first detection is often the earliest attacker activity on the host. Failed remediation, history purges. |
| 3.2 | Defender exclusions and settings history | [DE-03](../queries/TA0112-defense-impairment/DE-03-defender-exclusions-and-preference-changes/), [DE-04](../queries/TA0112-defense-impairment/DE-04-security-tool-tampering-registry/) | 2.1.8 | Exclusions of user-writable folders, drives or `.exe`; real-time protection or Tamper Protection off. |
| 3.3 | Scan the disk image with an up-to-date AV engine | | 2.1.9 | Outside the pack; run on the mounted image. |

## 4. Initial access and logons

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 4.1 | Logons and failed logons from public IP addresses | [IA-01](../queries/TA0001-initial-access/IA-01-logons-from-public-ip/) | 2.4.4 | Successful logons from outside the client's ranges, especially RDP (type 10) and network (type 3) with NTLM. |
| 4.2 | Brute force, password spraying, lockouts | [CA-06](../queries/TA0006-credential-access/CA-06-brute-force-then-success/), [CA-05](../queries/TA0006-credential-access/CA-05-password-spraying/) | 2.4.1, 2.4.2 | A run of 4625 for one account followed by a 4624; one source failing against many accounts; 4740 lockouts. |
| 4.3 | Logon sessions, with duration and admin rights | [LM-03](../queries/TA0008-lateral-movement/LM-03-logon-sessions-with-duration/) | 2.4.3, 2.4.23 | Logons outside office hours (sort or filter on `@timestamp`), long admin sessions, accounts that never log on here normally. |
| 4.4 | Accounts given sensitive privileges at logon | [PR-01](../queries/TA0004-privilege-escalation/PR-01-special-privileges-rare-accounts/) | 2.4.23 | 4672 for accounts that are not normally administrators. |

## 5. Execution

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 5.1 | Suspicious process creation (when 4688 or Sysmon 1 exist) | [EX-01](../queries/TA0002-execution/EX-01-process-creation-4688/), [EX-02](../queries/TA0002-execution/EX-02-process-creation-sysmon/), [EX-03](../queries/TA0002-execution/EX-03-rare-parent-child-4688/), [EX-04](../queries/TA0002-execution/EX-04-rare-binaries-sysmon/) | 2.4.5 | Attacker tools (mimikatz, PsExec, AdFind, rclone), LOLBins with odd arguments, rare parent/child pairs. |
| 5.2 | PowerShell | [EX-07](../queries/TA0002-execution/EX-07-powershell-script-blocks/), [EX-05](../queries/TA0002-execution/EX-05-powershell-unique-commands/), [EX-06](../queries/TA0002-execution/EX-06-powershell-command-timeline/) | 2.4.12, 2.3.9 | Encoded commands, download cradles, AMSI bypasses, AD and network discovery. |
| 5.3 | Script interpreters and WMI | [EX-08](../queries/TA0002-execution/EX-08-scripting-interpreters/), [EX-09](../queries/TA0002-execution/EX-09-wmi-execution/) | 2.4.5 | `mshta`, `wscript`, Python and remote WMI process creation. |
| 5.4 | Execution artifacts by rarity | [EX-10](../queries/TA0002-execution/EX-10-amcache-long-tail/), [EX-11](../queries/TA0002-execution/EX-11-shimcache-long-tail/), [EX-12](../queries/TA0002-execution/EX-12-srum-long-tail/), [EX-13](../queries/TA0002-execution/EX-13-prefetch-rare-executables/) | 2.1.1 | Executables on one host only, in user-writable folders, with tool-like names. These work without any event logs. |
| 5.5 | .NET loaded by unusual processes | [EX-14](../queries/TA0002-execution/EX-14-clr-usage-unusual-hosts/) | 2.1.1 | In-memory .NET tooling (Cobalt Strike `execute-assembly`, SharpHound, Rubeus). |
| 5.6 | Masquerading binaries | [DE-09](../queries/TA0112-defense-impairment/DE-09-masquerading-system-binaries/) | 2.1.10 | `svchost.exe` outside System32, look-alike names. |
| 5.7 | Every artifact for a named file (pivot) | [EX-15](../queries/TA0002-execution/EX-15-execution-evidence-pivot/) | 2.1.1 | Use with each tool name found above to date its first and last run. |

## 6. Persistence

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 6.1 | Autostart registry values | [PE-01](../queries/TA0003-persistence/PE-01-asep-registry-scoring/), [PE-02](../queries/TA0003-persistence/PE-02-asep-rarity/), [PE-13](../queries/TA0003-persistence/PE-13-winlogon-userinit/), [PE-14](../queries/TA0003-persistence/PE-14-knowndlls/) | 2.1.2, 2.4.10 | Run keys, IFEO debuggers, Winlogon, LSA and other ASEPs pointing at user-writable paths, scripts or LOLBins. |
| 6.2 | Services | [PE-05](../queries/TA0003-persistence/PE-05-service-install-events/), [PE-03](../queries/TA0003-persistence/PE-03-services-registry-scoring/), [PE-04](../queries/TA0003-persistence/PE-04-services-rarity/) | 2.4.8, 2.4.9, 2.4.14 | 7045/4697 with random names, `cmd /c` or PowerShell image paths, services from user-writable folders, rare services. |
| 6.3 | Scheduled tasks | [PE-08](../queries/TA0003-persistence/PE-08-scheduled-task-created-4698/), [PE-06](../queries/TA0003-persistence/PE-06-scheduled-task-commands/), [PE-07](../queries/TA0003-persistence/PE-07-task-scheduler-per-task/), [PE-09](../queries/TA0003-persistence/PE-09-taskcache-registry/), [PE-10](../queries/TA0003-persistence/PE-10-hidden-scheduled-tasks/), [PE-11](../queries/TA0003-persistence/PE-11-task-xml-files-mft/) | 2.4.25 | Tasks created outside office hours, running scripts or binaries from user-writable folders, hidden tasks. |
| 6.4 | WMI event subscriptions | [PE-15](../queries/TA0003-persistence/PE-15-wmi-event-subscriptions/) | 2.1.2 | Any `CommandLineEventConsumer` or `ActiveScriptEventConsumer` that is not the client's management software. |
| 6.5 | Accounts created and added to groups | [PE-16](../queries/TA0003-persistence/PE-16-account-and-group-changes/) | 2.4.18 to 2.4.20, 2.3.5 | New local accounts, accounts added to Administrators or RDP users, password resets. |
| 6.6 | Startup folders | [PE-12](../queries/TA0003-persistence/PE-12-startup-folder/) | 2.1.2 | Scripts and shortcuts in the all-users Startup folder. |
| 6.7 | Remote-access tools installed | [C2-05](../queries/TA0011-command-and-control/C2-05-remote-access-and-tunnel-tools/) | 2.1.3 | Any RMM product the client does not use, and tunnels (ngrok, cloudflared, chisel). |

## 7. Credential access, discovery and lateral movement

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 7.1 | Credential dumping signs | [CA-01](../queries/TA0006-credential-access/CA-01-credential-dumping-events/), [CA-02](../queries/TA0006-credential-access/CA-02-dump-files-mft/), [CA-03](../queries/TA0006-credential-access/CA-03-credential-registry-settings/), [CA-04](../queries/TA0006-credential-access/CA-04-dump-tools-execution-evidence/) | 2.4.22 | LSASS access or dumps, `.dmp` files, WDigest enabled, unknown LSA packages (4614/4622). |
| 7.2 | Discovery | [DI-06](../queries/TA0007-discovery/DI-06-discovery-command-bursts/), [DI-05](../queries/TA0007-discovery/DI-05-powershell-user-group-discovery/), [DI-04](../queries/TA0007-discovery/DI-04-user-group-enumeration-4798-4799/), [DI-03](../queries/TA0007-discovery/DI-03-powershell-port-scan/), [DI-01](../queries/TA0007-discovery/DI-01-outbound-port-and-host-scan/), [DI-02](../queries/TA0007-discovery/DI-02-inbound-scan-probes/) | 2.4.6 | Bursts of `net`, `nltest`, `whoami`, AdFind; port scans out of this host or into it. |
| 7.3 | Lateral movement in and out | [LM-01](../queries/TA0008-lateral-movement/LM-01-lateral-movement-methods/), [LM-04](../queries/TA0008-lateral-movement/LM-04-executables-dropped-in-admin-share-paths/), [LM-02](../queries/TA0008-lateral-movement/LM-02-portproxy-and-remote-access-settings/) | 2.4.13, 2.4.22 | RDP (1149, 4624 type 10), PsExec-style services, WinRM, explicit credentials (4648), executables dropped in `ADMIN$`/`C$` paths, portproxy rules. |
| 7.4 | Share access | [LM-05](../queries/TA0008-lateral-movement/LM-05-share-access/) | 2.4.6, 2.3.6, 2.3.7 | `ADMIN$`/`C$`/`IPC$` from unexpected sources; named pipes used by PsExec and Cobalt Strike. Needs 5140/5145. |

## 8. Collection, exfiltration, command and control, impact

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 8.1 | Network connections by program | [C2-06](../queries/TA0011-command-and-control/C2-06-outbound-connections-by-application-wfp/), [C2-07](../queries/TA0011-command-and-control/C2-07-sysmon-network-connections/), [EXF-03](../queries/TA0010-exfiltration/EXF-03-srum-network-usage/) | 2.4.7, 2.3.4 | LOLBins or user-folder programs talking to the internet, beacon-like patterns, large uploads. |
| 8.2 | C2 and download indicators in the event logs | [C2-01](../queries/TA0011-command-and-control/C2-01-suspicious-destinations-event-logs/), [C2-02](../queries/TA0011-command-and-control/C2-02-motw-zone-identifier/) | 2.1.7 | Telegram/Discord/webhook callbacks, tunnels, BITS jobs, files downloaded from the internet. |
| 8.3 | Archives and staging | [CO-01](../queries/TA0009-collection/CO-01-archives-and-staged-files/), [CO-02](../queries/TA0009-collection/CO-02-mass-copy-bursts/), [CO-03](../queries/TA0009-collection/CO-03-archiver-tools-execution/) | 2.1.4 | Large archives in staging folders, mass copies, archivers run from odd paths. |
| 8.4 | Exfiltration tools | [EXF-04](../queries/TA0010-exfiltration/EXF-04-exfil-and-cloud-sync-tools/) | 2.1.1 | rclone, MEGAsync, WinSCP, `curl` uploads. |
| 8.5 | Ransomware and recovery tampering | [IM-01](../queries/TA0040-impact/IM-01-inhibit-system-recovery/), [IM-02](../queries/TA0040-impact/IM-02-mass-file-renames/), [IM-03](../queries/TA0040-impact/IM-03-ransom-notes/) | 2.1.10 | Shadow copies deleted, mass renames, ransom notes; their times bound the impact phase. |
| 8.6 | Anti-forensics on files | [DE-01](../queries/TA0112-defense-impairment/DE-01-timestomping/), [DE-07](../queries/TA0112-defense-impairment/DE-07-deleted-executables-usn/) | 2.1.4, 2.1.5 | Timestomped executables, tools deleted right after use. |
| 8.7 | Firewall changes | [DE-05](../queries/TA0112-defense-impairment/DE-05-firewall-rule-changes-events/), [DE-06](../queries/TA0112-defense-impairment/DE-06-firewall-rules-registry/) | 2.4.26, 2.4.27 | Inbound allow rules for RDP/SMB/WinRM or for tools; profiles turned off. |
| 8.8 | MFT review around each finding | | 2.1.4 | Files created in the minutes around every lead (sort `filesystem-*` by `file.filename.created`). |

## Not covered by these queries

- Memory analysis (IR 2.2): running processes, injected code, network sockets, command history in `conhost`.
- Live-response output (IR 2.3): `netstat`, `ipconfig /displaydns`, `net session`, ARP and routing tables.
- Registry value auditing (4657) and logon-process events (4610/4611); no query reads them yet.
- Third-party AV/EDR consoles and logs, firewall/VPN/proxy logs.
