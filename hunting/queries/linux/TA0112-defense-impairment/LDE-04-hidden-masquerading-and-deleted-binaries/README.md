# LDE-04 Hidden files and folders, binaries masquerading as kernel threads or system daemons, and processes running from deleted binaries

| | |
|---|---|
| Tactic | TA0112 Defense Impairment |
| ATT&CK | T1564.001 Hidden Files and Directories, T1036.005 Match Legitimate Name or Location, T1070.004 File Deletion |
| Indexes | `bodyfile-*`, `logstash-*`, `auditd-*` |
| Needs | bodyfile-*; journal export in logstash-* or auditd-* for running processes |
| Applies to | every Linux host |

**What it finds.** Things made to be overlooked. From the journal (`_EXE`, `_COMM`) and audit records: processes whose executable was deleted while they ran (` (deleted)`), processes named like kernel threads (`kworker`, `kthreadd`, `[...]`) that have an executable (real kernel threads have none), system daemon names running from outside system folders, and processes running from `/tmp`, `/var/tmp`, `/dev/shm` or `/dev`. From the bodyfile: executables with kernel-thread or daemon names outside system folders, regular files under `/dev`, files and folders named `...`, `. `, a space or with brackets, and hidden executables outside the usual tool caches.

**Reading the output.** A deleted binary still running (5) is the strongest lead: the program removed itself or was removed after starting. Miners and backdoors name themselves `kworker`, `kthreaddi`, `[kswapd0]`, `sshd` or `systemd-*` and live in `/tmp`, `/dev/shm`, `/var/tmp/.X*` or `/usr/lib/.x/`; a `sha1` from the bodyfile can be checked against threat intelligence, and the file's `file_created` dates the drop. Hidden executables in home folders also include harmless tool installs; the folder name decides. The journal only sees processes that logged, and auditd only what its rules record, so the bodyfile half is the reliable one.

**If it errors or looks empty.** `Unknown column [bodyfile.hidden]`: no `bodyfile-*` index exists; remove it and the bodyfile terms. If ES|QL rejects a bracket pattern, check that the backslashes survived copy and paste (`\\[` in the query).

**Next.** [LEX-02](../../TA0002-execution/LEX-02-programs-in-temp-hidden-and-user-writable-locations/) for executables in odd folders, [LIM-03](../../TA0040-impact/LIM-03-cryptominers/) for miners.
