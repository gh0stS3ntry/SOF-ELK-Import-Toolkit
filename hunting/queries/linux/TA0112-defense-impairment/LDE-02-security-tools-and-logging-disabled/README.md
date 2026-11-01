# LDE-02 Security, logging and firewall tooling stopped, disabled, masked or removed, and SELinux, AppArmor and audit turned off

| | |
|---|---|
| Tactic | TA0112 Defense Impairment |
| ATT&CK | T1562.001 Disable or Modify Tools, T1562.004 Disable or Modify System Firewall, T1562.012 Disable or Modify Linux Audit System |
| Indexes | `logstash-*`, `auditd-*`, `packages-*`, `linuxconfig-*` |
| Needs | any of logstash-*, auditd-*, packages-*, linuxconfig-* |
| Applies to | every Linux host |

**What it finds.** Security and logging tools taken out of the way: `systemctl stop/disable/mask`, `service ... stop`, `kill` and `chmod -x` of auditd, rsyslog, journald, AppArmor, UFW, firewalld, nftables, ClamAV, Falco, osquery, Wazuh, Elastic, CrowdStrike, SentinelOne, Defender for Endpoint, Sysmon for Linux, fail2ban, AIDE and log shippers; `setenforce 0` and SELinux set to disabled, `aa-disable`/`aa-teardown`, `ufw disable`, flushed iptables or nftables rules, `auditctl -D`/`-e 0`; systemd stop messages for those units; audit configuration changes and daemon stops; packages of those tools removed; and their units masked (linked to `/dev/null`).

**Reading the output.** Commands (4) and masked units (3) first. Stopping a security agent right before other activity is common in hands-on intrusions and in miner scripts (Kinsing and TeamTNT kill cloud agents and AppArmor). Package removals and masks are permanent: compare their time with the incident window. Stop messages (score 1) also appear at every shutdown, so only stops in the middle of a boot matter; [LTRI-02](../../00-triage/LTRI-02-boots-shutdowns-and-log-gaps/) shows the boots.

**If it errors or looks empty.** `Unknown column [package.name]`: no `packages-*` index exists; remove it and the `is_pkg` lines. `Unknown column [linuxconfig.systemd.masked]`: no `linuxconfig-*`; remove it and the `is_masked` lines.

**Next.** [LDE-01](../LDE-01-log-and-history-tampering/) for log tampering, [LPE-08](../../TA0003-persistence/LPE-08-kernel-modules-and-rootkit-signs/) for kernel rootkits.
