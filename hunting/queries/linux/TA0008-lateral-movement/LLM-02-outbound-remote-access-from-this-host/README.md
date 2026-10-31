# LLM-02 Outbound remote access from this host: SSH, RDP, SMB and WinRM clients, known_hosts and SSH client files

| | |
|---|---|
| Tactic | TA0008 Lateral Movement |
| ATT&CK | T1021.004 SSH, T1021.001 Remote Desktop Protocol, T1021.002 SMB/Windows Admin Shares, T1021.006 Windows Remote Management |
| Indexes | `logstash-*`, `auditd-*`, `linuxconfig-*`, `bodyfile-*` |
| Needs | any of logstash-*, auditd-*, linuxconfig-*, bodyfile-* |
| Applies to | every Linux host |

**What it finds.** Signs that this host was used to reach others: SSH, SCP, rsync, `sshpass`, RDP clients (`xfreerdp`, `rdesktop`, Remmina), Impacket and `evil-winrm`, `smbclient`, `crackmapexec`/`netexec`, `kubectl`, `telnet` and VNC commands (sudo, pkexec, cron, audit, and in cron entries, units and startup files); each account's `known_hosts` entries (host names when not hashed) and the times of its `known_hosts`, `.ssh/config`, private keys and RDP client settings; and audited connections or firewall records to SSH, Telnet, RPC, SMB, RDP, VNC and WinRM ports.

**Reading the output.** Commands name their targets directly. `known_hosts` grows each time an account connects to a new host, so its `file_mtime` is the last new host; hashed entries (`HashKnownHosts yes`, the Debian default) hide the names, but the count is still the number of hosts the account has reached, and a hash can be tested against a candidate host name with `ssh-keygen -F <host> -f known_hosts`. A private key in a service account's or web user's home is a lead, and a key file newer than the account is worth checking. Without auditd, SSH run without sudo leaves no command line, so `known_hosts` and the target hosts' own logs ([LLM-01](../LLM-01-inbound-sessions-with-duration/) there) are the main evidence.

**If it errors or looks empty.** `Unknown column [linuxconfig.ssh.hosts]`: no `linuxconfig-*` index exists; replace the `linuxconfig.*` fields with `null`. `Unknown column [file.type]`: no `bodyfile-*`; remove it.

**Next.** [LLM-01](../LLM-01-inbound-sessions-with-duration/) on the target hosts, [LC2-01](../../TA0011-command-and-control/LC2-01-reverse-shells-tunnels-and-proxies/) for SSH tunnels and port forwards.
