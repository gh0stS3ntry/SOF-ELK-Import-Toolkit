# LPR-02 Setuid and setgid files outside the usual folders, and commands that set them

| | |
|---|---|
| Tactic | TA0004 Privilege Escalation |
| ATT&CK | T1548.001 Setuid and Setgid, T1222.002 Linux and Mac File and Directory Permissions Modification |
| Indexes | `bodyfile-*`, `logstash-*`, `auditd-*` |
| Needs | bodyfile-* (file modes); logstash-*, auditd-* for chmod/setcap commands |
| Applies to | every Linux host |

**What it finds.** Files with the setuid or setgid bit outside the folders where distributions put them, or whose inode changed inside the incident window (a `chmod u+s` changes the inode time); `chmod +s`, `chmod 4755`, `setcap` and `install -m 4755` commands from sudo and audit logs; and audited permission and extended-attribute changes (`chmod`, `fchmodat`, `setxattr`, the last being how file capabilities are set).

**Reading the output.** A setuid copy of a shell or interpreter (`/tmp/.bash`, `/var/tmp/python3`) is the classic root backdoor; any setuid file in a home, temp, web or hidden folder is a lead, all the more if it is world-writable or not owned by root. Compare `sha1` with the system binary of the same name to spot a copy. A standard setuid binary (`su`, `passwd`, `sudo`) with a recent inode change can be a package upgrade; check [LTRI-04](../../00-triage/LTRI-04-software-installed-and-removed/) for the same day. Set `since` first. File capabilities (`cap_setuid+ep` on python, perl or tar) are not in the bodyfile; only `setcap` commands and audited `setxattr` show them.

**If it errors or looks empty.** `Unknown column [bodyfile.setuid]`: no `bodyfile-*` index exists; this query needs it for the file rows (remove the bodyfile terms to keep only the command rows).

**Next.** [LPR-01](../LPR-01-sudo-su-pkexec-use-failures-and-rules/) for sudo, [LDE-04](../../TA0112-defense-impairment/LDE-04-hidden-masquerading-and-deleted-binaries/) for hidden files.
