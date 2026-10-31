# LDI-02 Network and service scanning tools: commands run, packages installed, binaries and scan output on disk

| | |
|---|---|
| Tactic | TA0007 Discovery |
| ATT&CK | T1046 Network Service Discovery, T1595 Active Scanning, T1018 Remote System Discovery |
| Indexes | `logstash-*`, `auditd-*`, `packages-*`, `bodyfile-*`, `linuxconfig-*` |
| Needs | any of logstash-*, auditd-*, packages-*, bodyfile-* |
| Applies to | every Linux host; on servers any hit matters |

**What it finds.** Port, host, web and directory scanners and AD enumeration tools (`nmap`, `masscan`, `rustscan`, `autorecon`, `gobuster`, `ffuf`, `nikto`, `enum4linux`, `crackmapexec`/`netexec`, `ldapsearch`, `bloodhound-python`, `kerbrute`, `nuclei`, `sqlmap`, ...): commands run through sudo, pkexec or cron and recorded by auditd, scanners in cron entries, units and startup files, the packages that install them, copies of the binaries outside `/usr`, and scan output files (`.nmap`, `.gnmap`, nmap XML).

**Reading the output.** On a server, any row is a lead: a scanner run from a compromised host maps the internal network for the next hop; `sample_commands` shows the targets. On a pentest or attacker machine this is the scope of what was scanned: the targets in `sample_commands` and the scan output files list the hosts to check next. `install_time` close to the first run means it was brought in for the job.

**If it errors or looks empty.** `Unknown column [package.name]`: no `packages-*` index exists; remove it and the `is_pkg` line. Without auditd, a scanner run without sudo leaves no command line, but its output files and package still show.

**Next.** [LDI-03](../LDI-03-port-scans-in-firewall-and-audit-records/) for scans seen in firewall and audit network records, [LLM-02](../../TA0008-lateral-movement/LLM-02-outbound-remote-access-from-this-host/) for connections that followed.
