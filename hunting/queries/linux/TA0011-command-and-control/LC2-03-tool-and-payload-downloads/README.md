# LC2-03 Tool and payload downloads: download commands, browser downloads, new executables and scripts in download and temp folders, files served to download tools

| | |
|---|---|
| Tactic | TA0011 Command and Control |
| ATT&CK | T1105 Ingress Tool Transfer, T1204.002 Malicious File |
| Indexes | `logstash-*`, `auditd-*`, `linuxconfig-*`, `browsinghistory-*`, `bodyfile-*`, `httpdlog-*` |
| Needs | any of logstash-*, auditd-*, linuxconfig-*, browsinghistory-*, bodyfile-* |
| Applies to | every Linux host |

**What it finds.** How tools and payloads arrived, and left again: download commands with a URL (`curl`, `wget`, `aria2c`, `tftp`, `git clone`, `pip install git+...`, `go install`, `scp`) from sudo, pkexec, cron and audit records and from cron entries, units and startup files; Firefox and Chromium downloads; executables, scripts, packages and archives created in `Downloads`, `/tmp`, `/var/tmp` and `/dev/shm` since the start of the incident window; and scripts and binaries this host's own web server handed out (a compromised server used to host payloads).

**Reading the output.** A timeline, newest first. Match download commands and browser downloads to the new files around the same time (same name, `Downloads` or `/tmp`), then look for those files running in [LEX-02](../../TA0002-execution/LEX-02-programs-in-temp-hidden-and-user-writable-locations/). A web server serving `.sh` or ELF files to `curl`/`wget` clients is being used as a staging point; the client addresses are the next victims. Set `since` first; the bodyfile shows only files still present at collection.

**If it errors or looks empty.** `Unknown column [bodyfile.executable]`: no `bodyfile-*` index exists; remove it and the `is_new_file` lines. `httpdlog-*` and `browsinghistory-*` are optional: the query uses no field that only they have.

**Next.** [LIA-03](../../TA0001-initial-access/LIA-03-suspicious-urls-visited-and-fetched/) for the URLs, [LEX-04](../../TA0002-execution/LEX-04-suspicious-command-lines/) for download-and-run one-liners.
