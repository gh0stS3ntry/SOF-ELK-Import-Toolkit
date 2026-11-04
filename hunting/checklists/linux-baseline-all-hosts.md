# Checklist: Baseline: all Linux hosts

Every Linux host loaded with the Linux importers (`Linux/linux2sofelk.py` on a UAC collection or a collected root filesystem), before the role checklists (web, database, backup and file servers, SSH jump hosts). The order follows an intrusion: what evidence exists, who logged in, what ran, what was left behind to come back, and what was done to hide it; section 7 adds the container checks for hosts that run Docker or Podman. Set the `since` line in the queries that have one to the start of the incident window. The `IR ref` column points to the closest item of the IR checklist, which is written for Windows hosts, and is blank where nothing fits.

## 1. Evidence and host profile

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 1.1 | Which Linux sources were loaded and how far back the logs reach | [LTRI-01](../queries/linux/00-triage/LTRI-01-linux-data-coverage/) | 1.2.3, 2.4 | No `auditd.log` means no full command-line record; no journal or syslog rows means the logs were not exported. Compare the oldest log entry with the incident window. |
| 1.2 | Boots, shutdowns, crashes and log gaps | [LTRI-02](../queries/linux/00-triage/LTRI-02-boots-shutdowns-and-log-gaps/) | 2.4.21 | Boots with no journal, journals that stop early, crashes; a kernel change outside an upgrade. |
| 1.3 | Accounts, their rights and their activity | [LTRI-03](../queries/linux/00-triage/LTRI-03-accounts-and-their-activity/) | 1.3.2, 2.4.18 | Accounts that can log in, `uid0` and empty-password flags, accounts changed by the last edit of `/etc/passwd`, service accounts with logins. |
| 1.4 | Software installed and removed | [LTRI-04](../queries/linux/00-triage/LTRI-04-software-installed-and-removed/) | 1.2.3 | Attack tools, compilers, removed security packages, local `.deb`/`.rpm` installs inside the window. |

## 2. Access

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 2.1 | Logins from the internet | [LIA-01](../queries/linux/TA0001-initial-access/LIA-01-remote-logins-from-public-addresses/) | 2.4.3, 2.4.4 | Successful logins from public addresses, above all after failures. |
| 2.2 | Brute force and spraying | [LCA-01](../queries/linux/TA0006-credential-access/LCA-01-brute-force-and-password-spraying/) | 2.4.1, 2.4.2 | Sources that failed and then succeeded; internal sources spraying. |
| 2.3 | Remote sessions in and out | [LLM-01](../queries/linux/TA0008-lateral-movement/LLM-01-inbound-sessions-with-duration/), [LLM-02](../queries/linux/TA0008-lateral-movement/LLM-02-outbound-remote-access-from-this-host/) | 2.4.13 | Logins from other servers, long or still-open sessions; SSH, RDP and SMB clients run from this host, `known_hosts` growth. |
| 2.4 | SSH keys | [LPE-04](../queries/linux/TA0003-persistence/LPE-04-ssh-authorized-keys-and-their-logins/) | 2.4.18 | Keys added to root or a service account, logins with keys no longer on disk. |

## 3. Execution and privilege

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 3.1 | Commands run with sudo, su and pkexec | [LEX-01](../queries/linux/TA0002-execution/LEX-01-commands-run-with-sudo-su-pkexec/), [LPR-01](../queries/linux/TA0004-privilege-escalation/LPR-01-sudo-su-pkexec-use-failures-and-rules/) | 2.1.1, 2.4.23 | Root shells, downloads, edits of system files, refused attempts. |
| 3.2 | Suspicious command lines | [LEX-04](../queries/linux/TA0002-execution/LEX-04-suspicious-command-lines/), [LC2-01](../queries/linux/TA0011-command-and-control/LC2-01-reverse-shells-tunnels-and-proxies/) | 2.1.1 | Download-and-run, encoded commands, interpreter one-liners, reverse shells and tunnels. |
| 3.3 | Programs in temporary, hidden and user-writable folders | [LEX-02](../queries/linux/TA0002-execution/LEX-02-programs-in-temp-hidden-and-user-writable-locations/), [LEX-03](../queries/linux/TA0002-execution/LEX-03-rare-programs-across-hosts/), [LDE-04](../queries/linux/TA0112-defense-impairment/LDE-04-hidden-masquerading-and-deleted-binaries/) | 2.1.1, 2.1.4 | Executables in `/tmp` or `/dev/shm`, processes running from deleted binaries, kernel-thread names on disk. |
| 3.4 | Executables and scripts in user-writable and world-writable folders | [LEX-06](../queries/linux/TA0002-execution/LEX-06-executables-and-scripts-in-user-writable-folders/) | 2.1.1, 2.1.4 | ELF files and scripts (`.sh`, `.py`, `.pl`, `.php` and others) in `/tmp`, `/var/tmp`, `/dev/shm`, `/run/user`, home folders and their Trash, world-writable folders and folders owned by regular accounts; executables anyone can overwrite. Setuid files, deleted entries and exploit or tool names first. Works from the bodyfile alone, whether or not the file ever ran. |
| 3.5 | Discovery and scanning | [LDI-01](../queries/linux/TA0007-discovery/LDI-01-discovery-command-bursts/), [LDI-02](../queries/linux/TA0007-discovery/LDI-02-network-scanning-tools/), [LDI-03](../queries/linux/TA0007-discovery/LDI-03-port-scans-in-firewall-and-audit-records/) | 2.4.4 | Bursts of discovery commands, enumeration scripts, scanners and their output. |
| 3.6 | Setuid files, privileged groups and sudoers | [LPR-02](../queries/linux/TA0004-privilege-escalation/LPR-02-setuid-setgid-files-and-permission-changes/), [LPR-03](../queries/linux/TA0004-privilege-escalation/LPR-03-privileged-groups-and-sudoers-changes/) | 2.4.19, 2.4.20 | Setuid shells, users added to `sudo`/`wheel`/`docker`, `NOPASSWD` rules. |
| 3.7 | Credential access | [LCA-02](../queries/linux/TA0006-credential-access/LCA-02-credential-files-and-cracking-tools/) | 2.4.22 | `/etc/shadow` read, private keys and tickets outside their place, cracking and sniffing tools. |
| 3.8 | Containers used to reach the host | [LEX-05](../queries/linux/TA0002-execution/LEX-05-container-abuse-and-escapes/), [LPR-03](../queries/linux/TA0004-privilege-escalation/LPR-03-privileged-groups-and-sudoers-changes/) | 2.1.1 | Any host can run Docker or Podman without being called a container host (web applications and databases often run in containers). Privileged or host-mounted containers, the Docker socket mounted, `nsenter -t 1` and other escapes, `dockerd` listening on TCP, members of the `docker` group. On a host that runs Docker or Podman, also work through section 7. |

## 4. Persistence

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 4.1 | systemd services and timers | [LPE-01](../queries/linux/TA0003-persistence/LPE-01-systemd-units-defined-started-and-changed/) | 2.4.14 | Admin units running from odd folders, units enabled in the window, transient `run-*` units. |
| 4.2 | Cron and at jobs | [LPE-02](../queries/linux/TA0003-persistence/LPE-02-cron-and-at-jobs-configured-and-run/) | 2.4.25 | Jobs in user crontabs, jobs that ran but are gone, downloads in jobs. |
| 4.3 | Shell startup files and init scripts | [LPE-03](../queries/linux/TA0003-persistence/LPE-03-shell-startup-files-and-init-scripts/), [LPE-10](../queries/linux/TA0003-persistence/LPE-10-desktop-autostart-and-user-level-units/) | 2.1.2 | Aliases wrapping `sudo`/`ssh`, `PROMPT_COMMAND`, network tools in `.bashrc`, autostart entries in home folders. |
| 4.4 | Accounts and groups changed | [LPE-05](../queries/linux/TA0003-persistence/LPE-05-account-and-group-changes/) | 2.4.18 to 2.4.20 | New accounts, new members of privileged groups, `/etc/shadow` changes with no log line. |
| 4.5 | Loader and kernel | [LPE-06](../queries/linux/TA0003-persistence/LPE-06-ld-preload-and-dynamic-linker-hijacking/), [LPE-08](../queries/linux/TA0003-persistence/LPE-08-kernel-modules-and-rootkit-signs/) | 2.1.2 | `/etc/ld.so.preload`, `LD_PRELOAD` in units or sudoers, out-of-tree modules, `.ko` files outside the module tree. |
| 4.6 | Package sources | [LPE-09](../queries/linux/TA0003-persistence/LPE-09-repositories-and-local-packages/) | 1.2.3 | Unsigned repositories, keys added in the window, packages installed from files. |

## 5. Command and control, collection and exfiltration

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 5.1 | Downloads and suspicious URLs | [LC2-03](../queries/linux/TA0011-command-and-control/LC2-03-tool-and-payload-downloads/), [LIA-03](../queries/linux/TA0001-initial-access/LIA-03-suspicious-urls-visited-and-fetched/) | 2.4.7 | Payload fetches by `curl`/`wget`, new executables in `/tmp` or `Downloads`, URLs on IPs or tunnelling services. |
| 5.2 | Outbound destinations and name resolution | [LC2-02](../queries/linux/TA0011-command-and-control/LC2-02-outbound-destinations-firewall-audit-vpn/), [LC2-04](../queries/linux/TA0011-command-and-control/LC2-04-hosts-resolver-and-proxy-settings/) | 2.4.7 | Rare destinations, OpenVPN endpoints, hosts-file and resolver changes, system proxies. |
| 5.3 | Staging and exfiltration | [LCO-01](../queries/linux/TA0009-collection/LCO-01-archives-dumps-and-staging/), [LCO-02](../queries/linux/TA0009-collection/LCO-02-file-creation-bursts/), [LEXF-01](../queries/linux/TA0010-exfiltration/LEXF-01-exfiltration-tools-and-commands/), [LEXF-02](../queries/linux/TA0010-exfiltration/LEXF-02-file-sharing-and-paste-sites/) | 2.1.4, 2.4.7 | Archives in temporary or web folders, `rclone`/`curl -T`/`scp` uploads, file-sharing sites. |

## 6. Impact and defense impairment

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 6.1 | Destruction, ransomware and miners | [LIM-01](../queries/linux/TA0040-impact/LIM-01-destructive-commands/), [LIM-02](../queries/linux/TA0040-impact/LIM-02-ransomware-notes-and-encryption/), [LIM-03](../queries/linux/TA0040-impact/LIM-03-cryptominers/) | 2.1.10 | Wiping commands, ransom notes and extension bursts, miner binaries and pools. |
| 6.2 | Logs and history tampered | [LDE-01](../queries/linux/TA0112-defense-impairment/LDE-01-log-and-history-tampering/) | 2.4.21 | History linked to `/dev/null`, emptied logs, journald and rsyslog stopped by hand. |
| 6.3 | Security tools disabled | [LDE-02](../queries/linux/TA0112-defense-impairment/LDE-02-security-tools-and-logging-disabled/) | 2.4.21, 2.4.26 | auditd, AppArmor, SELinux, firewalls and EDR agents stopped, masked or removed. |
| 6.4 | Timestomping and clock changes | [LDE-03](../queries/linux/TA0112-defense-impairment/LDE-03-timestomping-and-clock-changes/) | 2.1.5 | `ctime` before `mtime`, backdated files in cron and systemd folders, `touch -d`, clock set by hand. |

## 7. Containers

Work through this section on every host that runs Docker or Podman (container hosts, and the web, database and other servers whose applications run in containers). A container host runs many workloads on one kernel, so the questions are whether a container or the container API was used to reach the host, what ran on the host afterwards, and whether registry credentials were taken. Kubernetes nodes are not covered here: they will get their own importers and checklist. The toolkit loads the host, not the containers: their file systems and logs are only seen where they are on the host's disk.

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 7.1 | Runtimes and their versions | [LTRI-04](../queries/linux/00-triage/LTRI-04-software-installed-and-removed/) | 1.2.1, 1.2.3 | Docker, Podman, containerd and runc versions against container-escape CVEs; tools installed next to them. |
| 7.2 | Who can control the runtime | [LPR-03](../queries/linux/TA0004-privilege-escalation/LPR-03-privileged-groups-and-sudoers-changes/) | 1.3.2, 2.4.20 | Members of the `docker` group (root-equivalent), sudo rules for `docker` or `podman`. |
| 7.3 | Whether the API is reachable from the network | [LEX-05](../queries/linux/TA0002-execution/LEX-05-container-abuse-and-escapes/) | 1.3.1 | `dockerd` listening on TCP (2375 without TLS), `-H tcp://` in units, the Podman API served on TCP (`podman system service tcp://...`). |
| 7.4 | Privileged and host-mounted containers, escapes | [LEX-05](../queries/linux/TA0002-execution/LEX-05-container-abuse-and-escapes/) | 2.1.1 | `--privileged`, `-v /:/host`, the Docker socket mounted, `nsenter -t 1`, `release_agent` tricks, escape tools. |
| 7.5 | Exec into containers | [LEX-05](../queries/linux/TA0002-execution/LEX-05-container-abuse-and-escapes/) | 2.4.13 | `docker exec`/`cp`, `podman exec`/`cp` by unexpected users or at odd times. |
| 7.6 | Programs from container overlay folders running on the host | [LEX-02](../queries/linux/TA0002-execution/LEX-02-programs-in-temp-hidden-and-user-writable-locations/), [LDE-04](../queries/linux/TA0112-defense-impairment/LDE-04-hidden-masquerading-and-deleted-binaries/) | 2.1.1, 2.1.4 | Binaries under `/var/lib/docker` or `/var/lib/containers` overlay folders run on the host, names masquerading as kernel threads. |
| 7.7 | Miners | [LIM-03](../queries/linux/TA0040-impact/LIM-03-cryptominers/) | 2.1.10 | The most common outcome of an exposed Docker API. |
| 7.8 | Units and jobs that start containers | [LPE-01](../queries/linux/TA0003-persistence/LPE-01-systemd-units-defined-started-and-changed/), [LPE-02](../queries/linux/TA0003-persistence/LPE-02-cron-and-at-jobs-configured-and-run/) | 2.4.14, 2.4.25 | Units that start containers with `--privileged` or from unknown images, cron jobs that pull images. |
| 7.9 | Registry credentials | [LCA-02](../queries/linux/TA0006-credential-access/LCA-02-credential-files-and-cracking-tools/), [LEX-05](../queries/linux/TA0002-execution/LEX-05-container-abuse-and-escapes/) | 2.4.22 | `.docker/config.json` and Podman's `auth.json` (`~/.config/containers/`, `/run/containers/`) changed or copied. |
| 7.10 | Runtime configuration | [LEX-05](../queries/linux/TA0002-execution/LEX-05-container-abuse-and-escapes/) | 2.4.14 | Changes to `daemon.json`, the `docker.service` drop-ins, the containerd config, or `/etc/containers/` (`containers.conf`, `registries.conf`, `policy.json`). |
| 7.11 | Containers, volumes and data destroyed | [LIM-01](../queries/linux/TA0040-impact/LIM-01-destructive-commands/) | 2.4.9 | `docker rm -f`, `podman rm -f`, volume and system prunes. |

## Not covered by these queries

- Commands typed in a shell without sudo on a host without auditd: they are logged nowhere the toolkit loads. Read `.bash_history`, `.zsh_history` and similar files by hand (no timestamps unless `HISTTIMEFORMAT` was set).
- UAC `live_response` output (running processes, open connections, `lsof`, `/proc` dumps) and memory images: read them directly.
- Container logs (`docker logs`, `podman logs`, `/var/lib/docker/containers/*/*-json.log`), image contents and the writable layers in `/var/lib/docker` or `/var/lib/containers`: read them from the collection or export them from the runtime.
- Kubernetes nodes and clusters (kubelet, static pods, RBAC, API server audit logs, EKS/AKS/GKE logs): planned for their own importers and checklist.
- Application logs other than web and FTP servers.
