# Checklist: Linux SSH jump host and admin server

Bastion hosts, jump boxes, admin and automation servers (Ansible, Salt, CI runners with deploy keys) that hold keys or credentials for other hosts. Run the [Linux baseline](linux-baseline-all-hosts.md) first. Whoever controls this host can reach everything it administers, so the questions are whether it was reached, whether keys, agents or credentials were taken or captured, and where the attacker went next. The `IR ref` column is approximate, because the IR checklist is written for Windows hosts.

## 1. Host profile

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 1.1 | Who uses the host, and which hosts it administers | [LTRI-03](../queries/linux/00-triage/LTRI-03-accounts-and-their-activity/) | 1.3.1, 1.3.2 | Accounts that log in, and the client's list of hosts reached from here; needed for rows 4.1 and 4.2. |
| 1.2 | Automation and remote-access tools installed | [LTRI-04](../queries/linux/00-triage/LTRI-04-software-installed-and-removed/) | 1.2.3 | Ansible, Salt, Terraform, cloud CLIs, `sshpass`, `proxychains`, remote desktop clients. |

## 2. Access

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 2.1 | Logins from outside and brute force | [LIA-01](../queries/linux/TA0001-initial-access/LIA-01-remote-logins-from-public-addresses/), [LCA-01](../queries/linux/TA0006-credential-access/LCA-01-brute-force-and-password-spraying/) | 2.4.1 to 2.4.4 | Logins from new addresses or countries, success after failures, logins by accounts that should use MFA. |
| 2.2 | Sessions, their length and source | [LLM-01](../queries/linux/TA0008-lateral-movement/LLM-01-inbound-sessions-with-duration/) | 2.4.13 | Sessions at unusual hours, sessions still open, accounts logging in from several sources at once. |
| 2.3 | SSH keys | [LPE-04](../queries/linux/TA0003-persistence/LPE-04-ssh-authorized-keys-and-their-logins/) | 2.4.18 | Keys added to admin accounts, logins with keys no longer on disk. |

## 3. Credential theft and capture

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 3.1 | Private keys and stored credentials | [LCA-02](../queries/linux/TA0006-credential-access/LCA-02-credential-files-and-cracking-tools/) | 2.4.22 | Private keys outside `.ssh`, cloud and Git credentials and `.env` files read or copied; other users' `/etc/shadow` entries read; credential tools and packet captures. |
| 3.2 | Wrappers that capture typed passwords | [LPE-03](../queries/linux/TA0003-persistence/LPE-03-shell-startup-files-and-init-scripts/), [LPE-06](../queries/linux/TA0003-persistence/LPE-06-ld-preload-and-dynamic-linker-hijacking/) | 2.1.2 | Aliases and functions wrapping `ssh`, `sudo` or `su` in startup files; `LD_PRELOAD` libraries; changed `ssh`/`sshd` binaries (compare with the package). |
| 3.3 | sudo use and privilege changes | [LEX-01](../queries/linux/TA0002-execution/LEX-01-commands-run-with-sudo-su-pkexec/), [LPR-01](../queries/linux/TA0004-privilege-escalation/LPR-01-sudo-su-pkexec-use-failures-and-rules/), [LPR-03](../queries/linux/TA0004-privilege-escalation/LPR-03-privileged-groups-and-sudoers-changes/) | 2.1.1, 2.4.20 | Root shells, `sudoers` changes, accounts added to `sudo`/`wheel`. |

## 4. Where the attacker went next

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 4.1 | Outbound SSH, RDP and SMB from this host | [LLM-02](../queries/linux/TA0008-lateral-movement/LLM-02-outbound-remote-access-from-this-host/) | 2.4.13 | Hosts reached from here, `known_hosts` entries added in the window, `ssh -J`/`ProxyJump` configurations. |
| 4.2 | Tunnels and proxies | [LC2-01](../queries/linux/TA0011-command-and-control/LC2-01-reverse-shells-tunnels-and-proxies/), [LC2-04](../queries/linux/TA0011-command-and-control/LC2-04-hosts-resolver-and-proxy-settings/) | 2.4.7 | `ssh -D`/`-R`, `chisel`, `socat`, proxychains configurations pointing inward. |
| 4.3 | Discovery of the internal network | [LDI-01](../queries/linux/TA0007-discovery/LDI-01-discovery-command-bursts/), [LDI-02](../queries/linux/TA0007-discovery/LDI-02-network-scanning-tools/), [LDI-03](../queries/linux/TA0007-discovery/LDI-03-port-scans-in-firewall-and-audit-records/) | 2.4.4 | Scanners, `nmap` output files, bursts of discovery commands. |
| 4.4 | History and logs removed | [LDE-01](../queries/linux/TA0112-defense-impairment/LDE-01-log-and-history-tampering/) | 2.4.21 | History disabled or emptied for the admin accounts; journald and rsyslog stopped. |

## Not covered by these queries

- Commands typed in sessions without sudo on a host without auditd, and session recordings (`tlog`, `script`, bastion products such as Teleport): read them from the collection or the product.
- Logs on the hosts reached from here: load those hosts and follow the sessions there.
