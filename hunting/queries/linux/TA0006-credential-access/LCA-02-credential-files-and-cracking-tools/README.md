# LCA-02 Credential files read or copied, credential theft and cracking tools: commands, files on disk and installed packages

| | |
|---|---|
| Tactic | TA0006 Credential Access |
| ATT&CK | T1003.008 /etc/passwd and /etc/shadow, T1552.001 Credentials In Files, T1552.004 Private Keys, T1110.002 Password Cracking, T1040 Network Sniffing, T1557.001 LLMNR/NBT-NS Poisoning and SMB Relay |
| Indexes | `logstash-*`, `auditd-*`, `bodyfile-*`, `packages-*` |
| Needs | any of logstash-*, auditd-*, bodyfile-*, packages-* |
| Applies to | every Linux host |

**What it finds.** Credential access on a Linux host from four angles: commands (sudo, pkexec, cron and audit records) that read `/etc/shadow`, SSH private keys, cloud and Git credentials, `.env` and `wp-config.php` files, shell history or browser and keyring stores, that search files for passwords, attach to or read process memory, or run cracking, spraying, relaying, sniffing and dumping tools (`john`, `hashcat`, `hydra`, `responder`, `secretsdump`, `kerbrute`, `tcpdump`, `mimipenguin`, `lazagne`); audited reads of credential files; files on disk that hold stolen or captured credentials (copies of `shadow`, private keys outside `.ssh`, `.kirbi`/`.ccache`/`.keytab` tickets, packet captures, potfiles, hash lists, `ntds.dit`, `lsass` dumps); and cracking and capture packages installed.

**Reading the output.** A timeline, newest first. On a server, any cracking tool, packet capture, private key outside `.ssh`, or a command reading `/etc/shadow` from an interactive account is a lead; read the command and the folder it ran in. On an attacker's or pentester's machine (Kali, Parrot) the same rows describe what was attacked: hash files and potfiles name the target accounts, `responder` logs and NTLMv2 captures name the victim hosts. `ts` for bodyfile rows is the file's birth time (or inode-change time where the filesystem has none). The bodyfile names files but holds no content.

**If it errors or looks empty.** `Unknown column [package.name]`: no `packages-*` index exists; remove it and its `is_pkg` line. `Unknown column [file.created]`: no `bodyfile-*`; remove it and replace `file.created` with `null`.

**Next.** [LCA-01](../LCA-01-brute-force-and-password-spraying/) for password guessing against this host, [LEXF-01](../../TA0010-exfiltration/LEXF-01-exfiltration-tools-and-commands/) for what was sent out.
