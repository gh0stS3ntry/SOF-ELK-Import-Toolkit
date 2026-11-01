# LEX-02 Programs run from, or executables stored in, temporary, hidden and user-writable locations

| | |
|---|---|
| Tactic | TA0002 Execution |
| ATT&CK | T1059.004 Unix Shell, T1036.005 Match Legitimate Name or Location, T1564.001 Hidden Files and Directories |
| Indexes | `logstash-*`, `auditd-*`, `linuxconfig-*`, `bodyfile-*` |
| Needs | any of logstash-*, auditd-*, linuxconfig-*, bodyfile-* |
| Applies to | every Linux host |

**What it finds.** Folders under `/tmp`, `/var/tmp`, `/dev/shm`, `/run/user`, `/dev`, web roots, home directories and hidden folders that hold executables (bodyfile: any file with an execute bit) or from which a program ran: audit `execve` records, the executable of every process that wrote to the journal (`_EXE`), the first word of sudo, pkexec and cron command lines (`./tool` resolved with the working directory), and the programs systemd units, cron jobs and autostart entries start. A journal `_EXE` ending in ` (deleted)` is a process that kept running after its binary was removed.

**Reading the output.** Highest scores first: folders where something both sits and ran, in a temporary or web location, or a deleted binary. Home directories of admins and pentesters hold many tools (score 3 from `executions` alone); judge by `programs` and the first and last run. On servers, any executable in `/tmp`, `/dev/shm` or a web root is a lead; check its hash in the bodyfile (`file.hash.sha1` in [LDE-04](../../TA0112-defense-impairment/LDE-04-hidden-masquerading-and-deleted-binaries/)) and the time it appeared (`newest_file`). The journal sees only processes that logged something, and auditd sees only what its rules record, so a folder with files but no `executions` may still have run.

**If it errors or looks empty.** `Unknown column [bodyfile.executable]`: no `bodyfile-*` index exists; remove `bodyfile-*` and the first `WHERE` line. No rows: nothing matched; the bodyfile alone should always list some home-directory scripts.

**Next.** [LEX-03](../LEX-03-rare-programs-across-hosts/) for rare programs, [LDE-04](../../TA0112-defense-impairment/LDE-04-hidden-masquerading-and-deleted-binaries/) for hidden and masquerading files.
