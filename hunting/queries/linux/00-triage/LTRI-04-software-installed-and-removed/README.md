# LTRI-04 Software installed, upgraded and removed, by hour, with the command and user

| | |
|---|---|
| Tactic | Triage (first cut) |
| ATT&CK | T1072 Software Deployment Tools, T1105 Ingress Tool Transfer |
| Indexes | `packages-*`, `logstash-*`, `auditd-*` |
| Needs | packages-*; sudo and audit commands in logstash-*, auditd-* |
| Applies to | every Linux host |

**What it finds.** Every hour in which software changed: package installs, upgrades and removals from dpkg, apt, dnf, yum and zypper logs, and the package-manager commands seen in sudo and audit logs (`apt install`, `dpkg -i local.deb`, `pip install`, `npm install -g`, `go get`). The apt and dnf history give the command line and the user; sudo and audit logs add installs the package logs do not show (pip, gem, npm, go, local `.deb` and `.rpm` files).

**Reading the output.** Look at the hours inside the incident window first. Worth a closer look: tools an attacker brings (`nmap`, `socat`, `netcat`, `proxychains`, `tor`, `gcc`, `make`, `python3-pip`, `rclone`), compilers on a server, removals of security or logging packages (`auditd`, `rsyslog`, `apparmor`, `ufw`), a `dpkg -i` or `rpm -i` of a local file, and a command run by an account that does not normally administer the host. Unattended upgrades show as large hourly batches with no user. Timestamps of dpkg and apt lines are local time converted with the evidence's time zone; lines written while the OS image was built can be off by hours.

**If it errors or looks empty.** `Unknown column [package.name]`: no `packages-*` index exists; remove it and `package.name`. The query uses no auditd-only field, so `auditd-*` can stay in `FROM` when it does not exist.

**Next.** [LPE-09](../../TA0003-persistence/LPE-09-repositories-and-local-packages/) for repositories and packages installed outside them.
