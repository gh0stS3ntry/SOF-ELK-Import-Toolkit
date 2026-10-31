# Linux importers

Importers that load a Linux evidence collection straight into SOF-ELK's Elasticsearch, without Logstash or Filebeat. Like the rest of the toolkit they use only the Python standard library (3.9+) and the retrying `_bulk` client in `../Windows/common/sof_elk_es_client.py`, so keep `Linux/` and `Windows/` side by side. They run on Windows as well as Linux.

| Script | Evidence | Index | `event.dataset` |
|---|---|---|---|
| `journal2sofelk.py` | systemd journal, as a `journalctl -o json` export | `logstash-<hostname>` | `syslog.journal` |
| `syslog2sofelk.py` | text syslog files under `/var/log` (current and rotated) | `logstash-<hostname>` | `syslog.file` |
| `httpd2sofelk.py` | Apache httpd, nginx and lighttpd access and error logs | `httpdlog-<hostname>` | `apache.access`, `apache.error`, `nginx.access`, `nginx.error`, `lighttpd.*` |
| `browser2sofelk.py` | Firefox and Chromium-family history and downloads (`places.sqlite`, `History`) | `browsinghistory-<hostname>` | `browsinghistory`, `browsinghistory.download` |
| `vsftpd2sofelk.py` | FTP server logs: `vsftpd.log`, `xferlog` | `logstash-<hostname>` | `ftp.vsftpd`, `ftp.xferlog` |
| `linux2sofelk.py` | runs all of the above on one collection | all of the above | all of the above |

Field reference: [`docs/schemas/linux-logstash.md`](../docs/schemas/linux-logstash.md) (system and FTP logs), [`docs/schemas/linux-httpdlog.md`](../docs/schemas/linux-httpdlog.md) (web logs), [`docs/schemas/browsinghistory.md`](../docs/schemas/browsinghistory.md) (browser history, shared with BrowsingHistoryView on Windows).

Both importers write to `logstash-<hostname>`, SOF-ELK's own syslog index family, so SOF-ELK's stock `logstash-*` Data View and its syslog field names work unchanged. A host that runs rsyslog on top of journald has most events in both sources: both are loaded, and `event.dataset` tells them apart. Pick one with `WHERE event.dataset == "syslog.journal"` (or `"syslog.file"`) when counting.

## Inputs

The evidence argument can be:

- A **UAC** output, either the `.zip` as UAC wrote it (read in place, not extracted) or the extracted folder. The collection's `[root]/` holds the host's files, and `journal/` holds the journal export.
- Any **collected root filesystem**: a folder holding `etc/` and `var/log/`, such as a mounted image, a KAPE-style copy or a tar extract. The root is found up to three folders down.

Shell history, `/etc/shadow` and other credential stores (browser cookies, saved logins, `key4.db`, form history) are never loaded. Shell history has no reliable order or timestamps per command, so it is better read on its own. Passwords that FTP logs record (a logged `PASS` command, anonymous passwords) are replaced with `<redacted>` before sending.

### The journal needs a JSON export

The binary journal files (`*.journal`, usually zstd-compressed) cannot be read with the Python standard library, so `journal2sofelk.py` loads only the output of `journalctl -o json`:

- **UAC with the custom `journalctl-gh0stS3ntry.yaml` artifact** writes `journal/journalctl_full_journal_logs.json` into the collection. This is found and loaded automatically.
- **Any other collection**: `--journal-json FILE` (repeatable; `.gz`, `.xz` and `.bz2` are fine). Every `journal/*.json` in a UAC collection is also loaded.

When a collection holds binary journal files but no export, the importer loads nothing for the journal, prints an **ACTION NEEDED** message with the exact commands for this collection, and exits with status `3`:

```text
mkdir -p '/cases/web01/journal'
journalctl --directory='/cases/web01/[root]/var/log/journal/<machine-id>' -o json > '/cases/web01/journal/journalctl_full_journal_logs.json'
python3 Linux/journal2sofelk.py '/cases/web01' --hostname web01
```

Run `journalctl` on any Linux machine or in WSL (Windows has no `journalctl`). For a zip, extract it first. A host with no journal at all (for example Alpine with OpenRC) is not an error: the importer says so and exits `0`.

### Text syslog: every distro layout

`syslog2sofelk.py` looks in `var/log/` for the files each distro family writes. The family is stored in `log.file.path`, so the source file is always visible.

| File | Written by |
|---|---|
| `syslog`, `auth.log`, `kern.log`, `daemon.log`, `user.log`, `debug`, `cron.log`, `mail.log`, `ufw.log` | Debian, Ubuntu, Kali, Mint |
| `messages`, `secure`, `cron`, `maillog` | RHEL, CentOS, Rocky, Alma, Fedora, Amazon Linux, SUSE, Alpine (busybox syslogd) |
| `firewalld` | RHEL family |

Rotated copies (`auth.log.1`, `auth.log.2.gz`, `messages-20261025`, `.bz2`, `.xz`) are read too; compression is recognised by content rather than by name. Identical lines are kept as separate documents, one per occurrence, so a stray extra copy of a log file (for example `secure.bak`) passed with `--syslog-file` would load its lines twice. Extra files can be added with `--syslog-file`.

Three line formats are recognised: classic RFC 3164 (`Oct 31 13:30:01 host prog[pid]: msg`), the ISO 8601 timestamps that newer Debian and Ubuntu rsyslog write, and RFC 5424. Continuation lines are joined to the line before them.

### Web server logs

`httpd2sofelk.py` reads `/var/log/apache2/` (Debian family, SUSE), `/var/log/httpd/` (RHEL family, including `ssl_access_log`, `ssl_request_log` and `ssl_error_log`), `/var/log/nginx/` and `/var/log/lighttpd/`, with rotated copies. The format is recognised per line: NCSA common and combined (also with a `vhost:port` prefix), mod_ssl's request log, and Apache, nginx and lighttpd error logs. Access log times carry their own offset; error log times are local time on the host. Logs kept elsewhere are added with `--web-log /path/on/host`.

The documents use SOF-ELK's httpd field names (`source.ip`, `url.path`, `http.response.status_code`, `destination.bytes`, ...) and the same types as the AWS ALB importer, so `FROM httpdlog-*` covers on-premises web servers and ALBs together, and the AWS web hunting queries (AIA-04, APE-03, AEXF-03) run on Linux web servers as well. Like `logstash-*`, `httpdlog-*` is SOF-ELK's own family, so no index template is installed for it.

### Browser history

`browser2sofelk.py` finds Firefox-family `places.sqlite` and Chromium-family `History` databases under every `/home/<user>` and `/root`, including snap and flatpak installs. Each database is copied, with its `-wal` file, to a temporary folder and read there, so the evidence is never opened for writing. Visits and downloads go to `browsinghistory-<hostname>` with the schema BrowsingHistoryView uses on Windows, so the browsing hunting queries (IA-02, C2-03, C2-08, C2-09, EXF-05) cover Linux hosts as well. Its index template is `Windows/index_templates/index-browsinghistory.json`.

### FTP server logs

`vsftpd2sofelk.py` reads `vsftpd.log` (vsftpd's own format: logins, failed logins, transfers, deletes, renames and, with `log_ftp_protocol=YES`, every command and response) and `xferlog` (written by vsftpd, ProFTPD and pure-ftpd), with rotated copies and `--ftp-log` files. They go to `logstash-<hostname>` next to the system logs. vsftpd logs GMT unless `use_localtime=YES`: the importer reads that setting from the evidence's `vsftpd.conf`, and `--ftp-time local|utc` overrides it.

## Host profile and time zone

Every document carries `host.name`, `host.id` (the machine-id) and `host.os.*` (name, version, family, kernel), read from the evidence. The hostname comes from `--hostname`, else UAC's `uac.log`, else `/etc/hostname`. A warning is printed when `--hostname` differs from the evidence.

Classic syslog timestamps have no year and no time zone, so the importer works them out:

- **Time zone:** read from the evidence's own `/etc/localtime` (or `/etc/timezone`), not from the analyst's machine. Override with `--local-tz +08:00` or `--local-tz Asia/Singapore`. The zone used is stored in `event.timezone`, and `@timestamp` is UTC.
- **Year:** inferred per file from the file's modification time, stepping back a year at each December to January rollover. Override with `--year` when the collection did not keep modification times.

The journal needs neither: its `__REALTIME_TIMESTAMP` is UTC in microseconds.

## Quick start

```bash
# Look first: parse everything, show two sample documents per source, send nothing
python3 Linux/linux2sofelk.py /cases/uac-kali-linux-20261031183959.zip --case IR-42 --dry-run

# Load every source into the local SOF-ELK
python3 Linux/linux2sofelk.py /cases/uac-kali-linux-20261031183959.zip --case IR-42

# Or one source at a time
python3 Linux/journal2sofelk.py /cases/web01 --hostname web01
python3 Linux/syslog2sofelk.py  /mnt/rocky9-image --hostname db01 --local-tz America/New_York
python3 Linux/httpd2sofelk.py   /cases/uac-web01.zip --web-log /srv/shop/logs/access.log
python3 Linux/linux2sofelk.py   /cases/uac-ftp01.zip --only vsftpd --ftp-time local
```

Kibana: SOF-ELK's stock `logstash-*` and `httpdlog-*` Data Views and the toolkit's `browsinghistory-*` Data View cover these indexes; `SOF-ELK_CreateDataViews.py` creates it on a plain Elasticsearch and Kibana.

`SOF-ELK_ImportWrapper.py` also finds UAC collections (a folder holding `uac.log`, or a `.zip` with `uac.log` at its top) and runs `linux2sofelk.py` on each one with the wrapper's host name, Elasticsearch and case options. It does not search a UAC collection for Windows exports.

Options shared by every Linux importer: `--hostname`, `--case`, `--local-tz`, `--es`, `--user`, `--password`, `--insecure`, `--batch-size`, `--dry-run`, `--sample-docs`, `--max-retries`, `--retry-backoff`, `--timeout`, `--log-file`. `linux2sofelk.py` adds `--only journal,syslog,httpd,browser,vsftpd`, and accepts each importer's own options (`--journal-json`, `--syslog-file`, `--year`, `--web-log`, `--ftp-log`, `--ftp-time`).

Exit status: `0` when everything loaded, `1` when Elasticsearch rejected documents, `3` when the journal was not loaded because the collection has no JSON export.

## Indexes and mapping

`logstash-*` and `httpdlog-*` are native SOF-ELK families, so no toolkit index template is installed for them (one would take over SOF-ELK's own `logstash-YYYY.MM` indexes). The importer installs the component template `sofelk-toolkit-linux-common` and creates `logstash-<hostname>` and `httpdlog-<hostname>` itself with the mappings in `index_templates/index-logstash.json` and `index_templates/index-httpdlog.json` (`dynamic: false`; `message` is keyword with a `message.text` subfield for full-text search). An existing index that was not made by the toolkit is refused rather than mixed. Deleting with `SOF-ELK_DeleteIndexes.py` works by host and case as for the other families.

`browsinghistory-*` uses the Windows importers' template (component `sofelk-toolkit-common` and index template `sofelk-toolkit-browsinghistory`), which the browser importer installs.

Documents get deterministic IDs: the journal cursor for the journal; a hash of the file family, line and occurrence for text syslog, web and FTP logs; and the database path and row id for browser history. Loading the same collection again overwrites instead of duplicating.

## Message parsing

Messages from the programs that matter most in an investigation are broken into fields, with SOF-ELK's own field names where SOF-ELK has a parser (sshd, PAM, iptables) and ECS names otherwise:

- **sshd:** logins (accepted and failed, with method, user, source IP and port, key fingerprint), invalid users, disconnects and negotiation failures.
- **PAM:** sessions opened and closed, authentication failures (with `pam.rhost` and `pam.ruser`), password changes.
- **sudo, su, pkexec:** who ran what, as whom, from which directory and TTY, and whether it was allowed.
- **Accounts:** `useradd`, `groupadd`, `usermod`, `userdel`, `groupdel`, `gpasswd`, `passwd`, `chpasswd`, `chage` (`event.action` such as `user-created` or `group-membership-added`).
- **systemd-logind sessions, cron commands, firewall logs (iptables, UFW, firewalld), kernel module taint and USB devices.**

Each recognised message gets `event.category`, `event.type`, `event.action`, `event.outcome` and a tag such as `got_ssh` or `got_sudo`.

## Tests

```bash
python3 Linux/tests/test_linux_importers.py -v
python3 Linux/tests/test_linux_web_ftp_browser.py -v
```

The fixtures cover a UAC Ubuntu folder (ISO timestamps, RFC 5424, UFW, a journal export with byte-array and repeated fields), a non-UAC Rocky 9 root (RFC 3164 with a year rollover, rotated and compressed files, firewalld, `America/New_York`), and a UAC folder with binary journal files only. Every test document is checked against the index mapping.

`test_linux_web_ftp_browser.py` uses a UAC Debian folder with Apache, nginx, lighttpd, vsftpd and xferlog lines (including a logged `PASS` command and anonymous logins, to check redaction) and a Rocky 9 root with `httpd/` logs; the Firefox and Chrome databases are built by the test, one with its visits only in the `-wal` file, and read from a folder and from a zip.

Checked against real data: the Kali UAC sample (`uac-kali-linux-20261031183959.zip`, 619,334 journal entries) loads with no rejected documents, including its Firefox history (1,483 visits) and Apache logs. It has no Chromium history database and no FTP server logs, so those parsers are tested with fixtures only. The RHEL-family and Ubuntu paths are tested with synthetic fixtures only, as no real collection from those distros has been available yet.
