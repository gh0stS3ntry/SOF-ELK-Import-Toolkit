# LTRI-01 Linux data coverage per index and dataset

| | |
|---|---|
| Tactic | Triage (first cut) |
| ATT&CK | n/a |
| Indexes | `logstash-*`, `auditd-*`, `bodyfile-*`, `wtmp-*`, `packages-*`, `linuxconfig-*`, `httpdlog-*`, `browsinghistory-*` |
| Needs | nothing |
| Applies to | every Linux host |

**What it finds.** Every Linux index and dataset that was loaded, with its document count, time range, how many source files fed it, and the host's OS and kernel. Run it first: the other queries only see what is listed here.

**Reading the output.** Expect one `logstash-<host>` row per dataset (`syslog.journal`, `syslog.file`, `ftp.vsftpd`, `ftp.xferlog`), and `bodyfile`, `wtmp`, `packages.*` and `linux.*` rows from a UAC collection. A missing family narrows the hunt: no `auditd.log` means no command-line audit trail (Debian, Ubuntu and Kali do not install auditd by default), no `syslog.journal` and no `syslog.file` means the logs were not collected or not exported (the journal needs `journalctl -o json`). `first_event` of the log datasets shows how far back the logs reach; compare it with the incident window. `bodyfile` and `linux.*` times are file times, so their `first_event` is old and means nothing.

**If it errors or looks empty.** No rows: nothing was loaded with the Linux importers (`Linux/linux2sofelk.py`), or the documents predate the host profile (`host.os.type`). Every Linux query filters on `host.os.type == "linux"`, which keeps SOF-ELK's own `logstash-YYYY.MM` and `httpdlog-YYYY.MM` indexes and Windows browser history out.

**Next.** [LTRI-02](../LTRI-02-boots-shutdowns-and-log-gaps/) for boots and log gaps, [LTRI-03](../LTRI-03-accounts-and-their-activity/) for the accounts.
