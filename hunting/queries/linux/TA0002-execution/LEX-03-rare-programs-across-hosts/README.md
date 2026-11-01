# LEX-03 Rare programs: executables seen in the journal and audit log, stacked across hosts

| | |
|---|---|
| Tactic | TA0002 Execution |
| ATT&CK | T1059 Command and Scripting Interpreter, T1204.002 Malicious File |
| Indexes | `logstash-*`, `auditd-*` |
| Needs | journal export in logstash-* (_EXE), or auditd-* |
| Applies to | every Linux host; best across several hosts |

**What it finds.** Every executable that wrote to the journal (`_EXE`) or appears in an audit record, stacked: on how many hosts, how many times, first and last seen, under which process names, user IDs and systemd units, with sample command lines. Rare programs float to the top.

**Reading the output.** With several hosts loaded, programs seen on one host only and a handful of times come first. On a single host, read the short tail: a binary outside `/usr` (`/opt`, `/home`, `/tmp`), a vendor-looking name in an odd folder, an interpreter (`/usr/bin/python3`, `/usr/bin/perl`) whose `sample_command_lines` runs a script from a writable folder, or a `units` value you do not recognise. `run_as_uids` 0 for a program in a user folder is a privilege change. The journal records the executable of every process that logged, so daemons dominate the counts; the audit log, where present, has every `execve` its rules cover.

**If it errors or looks empty.** `Unknown column [journald.unit]`: no journal export was loaded (only text syslog or only the audit log); replace `journald.unit` with `null`. Text syslog has no `_EXE`, so a host with only `auth.log`/`syslog` contributes nothing here.

**Next.** [LEX-02](../LEX-02-programs-in-temp-hidden-and-user-writable-locations/) for program locations, [LPE-01](../../TA0003-persistence/LPE-01-systemd-units-defined-started-and-changed/) for the systemd units.
