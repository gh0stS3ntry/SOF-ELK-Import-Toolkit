# LC2-01 Reverse shells, tunnels, proxies and VPNs: commands, persistence lines, tool packages and binaries

| | |
|---|---|
| Tactic | TA0011 Command and Control |
| ATT&CK | T1059.004 Unix Shell, T1572 Protocol Tunneling, T1090 Proxy, T1095 Non-Application Layer Protocol |
| Indexes | `logstash-*`, `auditd-*`, `linuxconfig-*`, `packages-*`, `bodyfile-*` |
| Needs | any of logstash-*, auditd-*, linuxconfig-*, packages-*, bodyfile-* |
| Applies to | every Linux host |

**What it finds.** Interactive and tunnelled channels in and out of the host: reverse shells (`bash -i >& /dev/tcp/...`, `nc -e`, `socat exec:`, `mkfifo` pipes, Python/Perl/PHP/Ruby socket one-liners, `pwncat`), SSH port forwards and SOCKS proxies (`ssh -R/-L/-D/-N`, `autossh`, `sshuttle`), tunnel and pivot tools (`chisel`, `ligolo`, `gost`, `frp`, `revsocks`, `proxychains`, `stunnel`), tunnelling services, DNS and ICMP tunnels and Tor (`ngrok`, `cloudflared tunnel`, `iodine`, `dnscat`, `ptunnel`), VPN clients (`openvpn`, `wg-quick`) and C2 frameworks. They are read from sudo, pkexec and cron command lines and the command line of every process that logged in the journal, audit records, cron entries, units, autostart and startup files (with the `reverse_shell` and `dev_tcp` flags), tool packages installed, and tool binaries and VPN profiles on disk.

**Reading the output.** Reverse shells (5) and C2 frameworks (4) first: the command shows the address and port; follow the address in [LC2-02](../LC2-02-outbound-destinations-firewall-audit-vpn/) and the time in [LEX-01](../../TA0002-execution/LEX-01-commands-run-with-sudo-su-pkexec/). A tunnel or proxy binary named `agent` or `proxy` in a home or temporary folder (ligolo-ng's default names) with a recent `file_created` is a pivot point. VPN rows show which `.ovpn` profiles exist and when the client ran; on an attacker's machine they name the networks it reached. Journal rows include long-running processes such as `openvpn`, so `records` counts log lines, not runs.

**If it errors or looks empty.** `Unknown column [package.name]`: no `packages-*` index exists; remove it and the `is_pkg` line. `Unknown column [bodyfile.executable]`: no `bodyfile-*`; remove it and the `is_file` terms.

**Next.** [LC2-02](../LC2-02-outbound-destinations-firewall-audit-vpn/) for the remote endpoints, [LPE-01](../../TA0003-persistence/LPE-01-systemd-units-defined-started-and-changed/) and [LPE-02](../../TA0003-persistence/LPE-02-cron-and-at-jobs-configured-and-run/) when a shell is started by a unit or cron job.
