# Linux importers

Importers that load a Linux evidence collection straight into SOF-ELK's Elasticsearch, without Logstash or Filebeat. Like the rest of the toolkit they use only the Python standard library (3.9+) and the retrying `_bulk` client in `../Windows/common/sof_elk_es_client.py`, so keep `Linux/` and `Windows/` side by side. They run on Windows as well as Linux.

| Script | Evidence | Index | `event.dataset` | Field reference |
|---|---|---|---|---|
| `journal2sofelk.py` | systemd journal, as a `journalctl -o json` export | `logstash-<hostname>` | `syslog.journal` | [linux-logstash.md](../docs/schemas/linux-logstash.md) |
| `syslog2sofelk.py` | text syslog files under `/var/log` (current and rotated) | `logstash-<hostname>` | `syslog.file` | [linux-logstash.md](../docs/schemas/linux-logstash.md) |
| `auditd2sofelk.py` | `/var/log/audit/audit.log*`, one document per audit event | `auditd-<hostname>` | `auditd.log` | [linux-auditd.md](../docs/schemas/linux-auditd.md) |
| `bodyfile2sofelk.py` | bodyfile (UAC `bodyfile/bodyfile.txt`, or `fls -r -m /`) with UAC executable hashes | `bodyfile-<hostname>` | `bodyfile` | [linux-bodyfile.md](../docs/schemas/linux-bodyfile.md) |
| `wtmp2sofelk.py` | login records: `wtmp`, `btmp`, `wtmpdb` | `wtmp-<hostname>` | `wtmp` | [linux-wtmp.md](../docs/schemas/linux-wtmp.md) |
| `linux2sofelk.py` | runs all of the above on one collection | all | all | |

Both importers write to `logstash-<hostname>`, SOF-ELK's own syslog index family, so SOF-ELK's stock `logstash-*` Data View and its syslog field names work unchanged. A host that runs rsyslog on top of journald has most events in both sources: both are loaded, and `event.dataset` tells them apart. Pick one with `WHERE event.dataset == "syslog.journal"` (or `"syslog.file"`) when counting.

## Inputs

The evidence argument can be:

- A **UAC** output, either the `.zip` as UAC wrote it (read in place, not extracted) or the extracted folder. The collection's `[root]/` holds the host's files, and `journal/` holds the journal export.
- Any **collected root filesystem**: a folder holding `etc/` and `var/log/`, such as a mounted image, a KAPE-style copy or a tar extract. The root is found up to three folders down.

Shell history, `/etc/shadow` and other credential stores are never loaded, nor is anything under UAC's `live_response/` (only `uname -a` is read for `host.os.kernel`). The bodyfile and auditd importers read `/etc/passwd` and `/etc/group` for names only. Shell history has no reliable order or timestamps per command, so it is better read on its own.

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

### auditd

`auditd2sofelk.py` reads `var/log/audit/audit.log` and its rotations (`audit.log.1` ... and logrotate's compressed or dated copies), oldest first; `--audit-log FILE` adds others (inside the evidence or on disk). The records of one audit event (`SYSCALL`, `EXECVE`, `CWD`, `PATH`, `PROCTITLE`, ... sharing one `msg=audit(<time>:<serial>)` id) become one document, Auditbeat-style, so a single row shows who ran which command line, from which directory, on which file. Hex-encoded values are decoded, and names come from the log's ENRICHED part or else the collected `/etc/passwd`. auditd is standard on the RHEL family; Debian, Ubuntu and Kali have it only when the package was installed (the Kali sample has none), so this importer is fixture-tested only.

### Bodyfile

`bodyfile2sofelk.py` loads UAC's `bodyfile/bodyfile.txt` (Sleuth Kit 3.x format), or any bodyfile given with `--bodyfile` (for an image: `fls -r -m / image.raw > image.body`, which also lists deleted entries). UAC's `hash_executables/` MD5 and SHA-1 lists are joined on the path, owner and group names come from the collected `/etc/passwd` and `/etc/group`, and each entry gets flags for setuid/setgid, world-writable, executable, hidden, deleted and regular files under `/dev`. `@timestamp` is the mtime; atime, ctime and crtime are in `file.accessed`, `file.ctime` and `file.created`.

### Login records

`wtmp2sofelk.py` parses `wtmp` and `btmp` (and their rotations) with `struct`, and `wtmpdb` databases (`/var/lib/wtmpdb/wtmp*.db`) with `sqlite3`. Logins are paired with their logouts like `last` does, so a login document carries `event.end`, `event.duration` and `wtmp.logout_type` (`logout`, `shutdown` or `crash`), and a logout document carries the user and source of its login. Every btmp record is a `failed-login`. `utmp` is skipped (it repeats the open sessions in wtmp), as are `lastlog` and `faillog`.

## Host profile and time zone

Every document carries `host.name`, `host.id` (the machine-id) and `host.os.*` (name, version, family, kernel), read from the evidence. The hostname comes from `--hostname`, else UAC's `uac.log`, else `/etc/hostname`. A warning is printed when `--hostname` differs from the evidence.

Classic syslog timestamps have no year and no time zone, so the importer works them out:

- **Time zone:** read from the evidence's own `/etc/localtime` (or `/etc/timezone`), not from the analyst's machine. Override with `--local-tz +08:00` or `--local-tz Asia/Singapore`. The zone used is stored in `event.timezone`, and `@timestamp` is UTC.
- **Year:** inferred per file from the file's modification time, stepping back a year at each December to January rollover. Override with `--year` when the collection did not keep modification times.

The journal needs neither: its `__REALTIME_TIMESTAMP` is UTC in microseconds. Neither do auditd, the bodyfile and wtmp, whose times are epoch-based.

## Quick start

```bash
# Look first: parse everything, show two sample documents per source, send nothing
python3 Linux/linux2sofelk.py /cases/uac-kali-linux-20261031183959.zip --case IR-42 --dry-run

# Load every source into the local SOF-ELK
python3 Linux/linux2sofelk.py /cases/uac-kali-linux-20261031183959.zip --case IR-42

# Or one source at a time
python3 Linux/journal2sofelk.py /cases/web01 --hostname web01
python3 Linux/syslog2sofelk.py  /mnt/rocky9-image --hostname db01 --local-tz America/New_York
python3 Linux/auditd2sofelk.py  /mnt/rocky9-image --hostname db01
python3 Linux/bodyfile2sofelk.py /mnt/rocky9-image --hostname db01 --bodyfile /cases/db01.body
python3 Linux/wtmp2sofelk.py    /cases/uac-kali-linux-20261031183959.zip
```

Kibana: SOF-ELK's stock `logstash-*` Data View covers the journal and syslog indexes. `SOF-ELK_CreateDataViews.py` creates it on a plain Elasticsearch and Kibana, and adds `auditd-*`, `bodyfile-*` and `wtmp-*`.

`SOF-ELK_ImportWrapper.py` also finds UAC collections (a folder holding `uac.log`, or a `.zip` with `uac.log` at its top) and runs `linux2sofelk.py` on each one with the wrapper's host name, Elasticsearch and case options. It does not search a UAC collection for Windows exports.

Options shared by every Linux importer: `--hostname`, `--case`, `--local-tz`, `--es`, `--user`, `--password`, `--insecure`, `--batch-size`, `--dry-run`, `--sample-docs`, `--max-retries`, `--retry-backoff`, `--timeout`, `--log-file`. Source-specific: `--journal-json`, `--syslog-file`, `--year`, `--audit-log`, `--bodyfile`, `--wtmp-file`. `linux2sofelk.py` adds `--only journal,syslog,auditd,bodyfile,wtmp`.

Exit status: `0` when everything loaded, `1` when Elasticsearch rejected documents, `3` when the journal was not loaded because the collection has no JSON export.

## Indexes and mapping

`auditd-*`, `bodyfile-*` and `wtmp-*` are toolkit families (SOF-ELK has no index of those names), so their importers install the index templates `sofelk-toolkit-auditd`, `-bodyfile` and `-wtmp` from `index_templates/`, as the Windows importers do, and `Install-ForensicELK.ps1` loads them too. All three use `dynamic: false`.

`logstash-*` is a native SOF-ELK family, so no toolkit index template is installed for it (one would take over SOF-ELK's own `logstash-YYYY.MM` indexes). The importer installs the component template `sofelk-toolkit-linux-common` and creates `logstash-<hostname>` itself with the mapping in `index_templates/index-logstash.json` (`dynamic: false`; `message` is keyword with a `message.text` subfield for full-text search). An existing index that was not made by the toolkit is refused rather than mixed. Deleting with `SOF-ELK_DeleteIndexes.py` works by host and case as for the other families.

Documents get deterministic IDs: the journal cursor for the journal, and a hash of the file family, line and occurrence for text syslog. Loading the same collection again overwrites instead of duplicating.

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
```

The fixtures cover a UAC Ubuntu folder (ISO timestamps, RFC 5424, UFW, a journal export with byte-array and repeated fields), a non-UAC Rocky 9 root (RFC 3164 with a year rollover, rotated and compressed files, firewalld, `America/New_York`), and a UAC folder with binary journal files only. The Rocky root also holds raw and ENRICHED audit logs (interleaved records, hex-encoded and split arguments, a rotated file), the Ubuntu folder a UAC bodyfile with hash lists, and the tests build wtmp, btmp (with a rotation, a shutdown, a crash and an IPv6 source) and a wtmpdb database on the fly. Every test document is checked against its index mapping.

Checked against real data: the Kali UAC sample (`uac-kali-linux-20261031183959.zip`) loads with no rejected documents: 619,334 journal entries, 605,729 bodyfile entries (22,195 with hashes) and 1,367 wtmp/btmp records (173 logins, 171 paired with a logout). The RHEL-family and Ubuntu paths, auditd and wtmpdb are tested with synthetic fixtures only, as no real collection with them has been available yet.
