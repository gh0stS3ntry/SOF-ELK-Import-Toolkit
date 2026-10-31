# LC2-04 Hosts file entries, DNS resolvers, proxy settings and VPN profiles, with changes to them

| | |
|---|---|
| Tactic | TA0011 Command and Control |
| ATT&CK | T1565.001 Stored Data Manipulation, T1090 Proxy, T1071.004 DNS |
| Indexes | `linuxconfig-*`, `bodyfile-*`, `logstash-*`, `auditd-*` |
| Needs | linuxconfig-*; bodyfile-*, logstash-*, auditd-* add file times and edits |
| Applies to | every Linux host |

**What it finds.** Name resolution and proxy settings that can redirect or hide traffic: `/etc/hosts` entries other than loopback (commented-out entries included, since they often name earlier targets), DNS resolvers from `resolv.conf` and `systemd-resolved`, proxy variables in `/etc/environment`, profile scripts and shell startup files; the inode-change times of those files and of `nsswitch.conf`, apt proxy settings, `proxychains`, `dnsmasq`, NetworkManager connection profiles, OpenVPN and WireGuard configuration; and commands that edited them.

**Reading the output.** A hosts entry pointing a security vendor's or update server's name at another address (or at `0.0.0.0`) blocks updates or telemetry; one pointing an internal service name at an outside address redirects credentials. An unknown DNS server, a system-wide proxy, a `proxychains` configuration or a new VPN profile changed inside the incident window is a lead. On a pentest or attacker machine, hosts entries and VPN profiles list the targets and networks. `ts` for `linux.*` rows is the file's modification time, so it dates the last edit of the whole file.

**If it errors or looks empty.** `Unknown column [linuxconfig.hosts.ip]`: no `linuxconfig-*` index exists; this query needs it for the snapshot rows. `Unknown column [file.type]`: no `bodyfile-*`; remove it.

**Next.** [LC2-02](../LC2-02-outbound-destinations-firewall-audit-vpn/) for outbound destinations, [LDE-02](../../TA0112-defense-impairment/LDE-02-security-tools-and-logging-disabled/) for security tools blocked.
