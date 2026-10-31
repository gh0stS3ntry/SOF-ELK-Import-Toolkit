# Linux importers

Importers that load a Linux evidence collection straight into SOF-ELK's Elasticsearch, without Logstash or Filebeat. Like the rest of the toolkit they use only the Python standard library (3.9+) and the retrying `_bulk` client in `../Windows/common/sof_elk_es_client.py`, so keep `Linux/` and `Windows/` side by side. They run on Windows as well as Linux.

| Script | Evidence | Index | `event.dataset` |
|---|---|---|---|
| `journal2sofelk.py` | systemd journal, as a `journalctl -o json` export | `logstash-<hostname>` | `syslog.journal` |
| `syslog2sofelk.py` | text syslog files under `/var/log` (current and rotated) | `logstash-<hostname>` | `syslog.file` |
| `packages2sofelk.py` | package history (dpkg, apt, dnf, yum, zypper) and installed packages (dpkg, rpm, apk) | `packages-<hostname>` | `packages.*` |
| `linuxconfig2sofelk.py` | accounts, groups, sudoers, cron, systemd units, init and profile scripts, autostart, SSH keys, hosts, resolver, `ld.so.preload`, repositories | `linuxconfig-<hostname>` | `linux.*` |
| `linux2sofelk.py` | runs all of the above on one collection | all of the above | all |

Field references: [`linux-logstash.md`](../docs/schemas/linux-logstash.md), [`linux-packages.md`](../docs/schemas/linux-packages.md), [`linux-linuxconfig.md`](../docs/schemas/linux-linuxconfig.md).

Both importers write to `logstash-<hostname>`, SOF-ELK's own syslog index family, so SOF-ELK's stock `logstash-*` Data View and its syslog field names work unchanged. A host that runs rsyslog on top of journald has most events in both sources: both are loaded, and `event.dataset` tells them apart. Pick one with `WHERE event.dataset == "syslog.journal"` (or `"syslog.file"`) when counting.

## Inputs

The evidence argument can be:

- A **UAC** output, either the `.zip` as UAC wrote it (read in place, not extracted) or the extracted folder. The collection's `[root]/` holds the host's files, and `journal/` holds the journal export.
- Any **collected root filesystem**: a folder holding `etc/` and `var/log/`, such as a mounted image, a KAPE-style copy or a tar extract. The root is found up to three folders down.

Shell history, `/etc/shadow` and other credential stores are never loaded. Shell history has no reliable order or timestamps per command, so it is better read on its own.

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

## Host profile and time zone

Every document carries `host.name`, `host.id` (the machine-id) and `host.os.*` (name, version, family, kernel), read from the evidence. The hostname comes from `--hostname`, else UAC's `uac.log`, else `/etc/hostname`. A warning is printed when `--hostname` differs from the evidence.

Classic syslog timestamps have no year and no time zone, so the importer works them out:

- **Time zone:** read from the evidence's own `/etc/localtime` (or `/etc/timezone`), not from the analyst's machine. Override with `--local-tz +08:00` or `--local-tz Asia/Singapore`. The zone used is stored in `event.timezone`, and `@timestamp` is UTC.
- **Year:** inferred per file from the file's modification time, stepping back a year at each December to January rollover. Override with `--year` when the collection did not keep modification times.

The journal needs neither: its `__REALTIME_TIMESTAMP` is UTC in microseconds.

## Package history and inventory

`packages2sofelk.py` searches every distro family's locations, whatever the detected distro, and writes one document per package action and one per installed package to `packages-<hostname>`:

| `event.dataset` | Source |
|---|---|
| `packages.dpkg` | `/var/log/dpkg.log*`: `install`, `upgrade`, `remove`, `purge` (status, configure and trigger lines are counted as not loaded) |
| `packages.apt` | `/var/log/apt/history.log*`: each package of each transaction, with `process.command_line` (the apt command) and `user.name` (`Requested-By`) |
| `packages.dnf` | `/var/log/dnf.rpm.log*` (RHEL 8+, Fedora); `Upgraded:` lines fill `packages.previous_version` |
| `packages.dnf_history` | `/var/lib/dnf/history.sqlite`: every transaction with command line, user and repository |
| `packages.yum` | `/var/log/yum.log*` (RHEL/CentOS 7; no year in the file, inferred like syslog, `--year` overrides) |
| `packages.zypper` | `/var/log/zypp/history*` (SUSE): actions, zypper command lines, repositories added and removed |
| `packages.inventory` | `/var/lib/dpkg/status`, `rpmdb.sqlite` (RHEL 9+, Fedora, SUSE), `/lib/apk/db/installed` |

Inventory timestamps: rpm stores each package's install time. dpkg does not, but a UAC bodyfile holds the modification time of `/var/lib/dpkg/info/<package>.list`, which dpkg rewrites at every install or upgrade, so that becomes `package.installed`. Without a bodyfile, `@timestamp` is the database file's mtime. The Berkeley DB rpm database of RHEL 8 and older cannot be read with the standard library; dnf history and the dnf/yum logs cover those hosts.

## Accounts and persistence snapshot

`linuxconfig2sofelk.py` writes one document per account, group, sudoers rule, cron entry, systemd unit or link, script line, autostart entry, SSH key, hosts entry, resolver or loader setting and repository to `linuxconfig-<hostname>`, with `@timestamp` set to the source file's modification time. The full list of locations is in [`linux-linuxconfig.md`](../docs/schemas/linux-linuxconfig.md). Points worth knowing:

- **Shadow:** only metadata enters ELK (hash algorithm, locked or empty, last change, ageing, expiry). The hash is reduced to that in memory and dropped; it is never stored, printed or sent. `/etc/gshadow`, private keys and shell history are never read.
- **Backups:** `/etc/passwd-` and `/etc/group-` hold the files as they were before the last change, so accounts and groups are marked `new_since_backup`, `only_in_backup` or `changed_since_backup` (with `members_added`).
- **Metadata from the bodyfile:** with UAC's `bodyfile/bodyfile.txt`, `@timestamp`, owner, mode and symlink targets are exact, and links UAC did not copy (masked units pointing at `/dev/null`) are still seen. A systemd link's `@timestamp` is when the unit was enabled. Without a bodyfile the folder's own metadata is used (symlinks are resolved inside the evidence, never on the analyst's machine) or, for a zip, the entry date read in the evidence's time zone.
- **Flags:** `linuxconfig.flags` marks things worth a look, such as `uid0`, `empty_password`, `nopasswd`, `download_exec`, `reverse_shell`, `dev_tcp`, `ld_preload`, `runs_from_temp`, `root_authorized_key` and `unsigned_repository`. They are triage pointers, not verdicts.
- **Commented hosts entries** are kept (`linuxconfig.hosts.commented`), as they often name earlier targets.

## Quick start

```bash
# Look first: parse everything, show two sample documents per source, send nothing
python3 Linux/linux2sofelk.py /cases/uac-kali-linux-20261031183959.zip --case IR-42 --dry-run

# Load both sources into the local SOF-ELK
python3 Linux/linux2sofelk.py /cases/uac-kali-linux-20261031183959.zip --case IR-42

# Or one source at a time
python3 Linux/journal2sofelk.py /cases/web01 --hostname web01
python3 Linux/syslog2sofelk.py  /mnt/rocky9-image --hostname db01 --local-tz America/New_York
```

Kibana: SOF-ELK's stock `logstash-*` Data View covers these indexes; `SOF-ELK_CreateDataViews.py` creates it on a plain Elasticsearch and Kibana.

`SOF-ELK_ImportWrapper.py` also finds UAC collections (a folder holding `uac.log`, or a `.zip` with `uac.log` at its top) and runs `linux2sofelk.py` on each one with the wrapper's host name, Elasticsearch and case options. It does not search a UAC collection for Windows exports.

Options shared by every Linux importer: `--hostname`, `--case`, `--local-tz`, `--es`, `--user`, `--password`, `--insecure`, `--batch-size`, `--dry-run`, `--sample-docs`, `--max-retries`, `--retry-backoff`, `--timeout`, `--log-file`. `linux2sofelk.py` adds `--only` (any of `journal,syslog,packages,linuxconfig`).

Exit status: `0` when everything loaded, `1` when Elasticsearch rejected documents, `3` when the journal was not loaded because the collection has no JSON export.

## Indexes and mapping

`packages-*` and `linuxconfig-*` are toolkit families: the importers install the index templates `sofelk-toolkit-packages` and `sofelk-toolkit-linuxconfig` (from `index_templates/`), and `SOF-ELK_CreateDataViews.py` creates their Data Views.

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
python3 Linux/tests/test_linux_packages_config.py -v
```

`test_linux_packages_config.py` uses a UAC Debian folder with a bodyfile (and a zip of it, which must give the same documents), a Rocky 9 root to which the test adds absolute symlinks, an `rpmdb.sqlite` and a dnf `history.sqlite`, a SUSE root and an Alpine root. It also checks that no shadow hash, private key or shell history text reaches any document.

The fixtures cover a UAC Ubuntu folder (ISO timestamps, RFC 5424, UFW, a journal export with byte-array and repeated fields), a non-UAC Rocky 9 root (RFC 3164 with a year rollover, rotated and compressed files, firewalld, `America/New_York`), and a UAC folder with binary journal files only. Every test document is checked against the index mapping.

Checked against real data: the Kali UAC sample (`uac-kali-linux-20261031183959.zip`, 619,334 journal entries) loads with no rejected documents, and so do its 10,654 package documents (dpkg, apt, dpkg inventory with install times from the bodyfile) and 6,158 config documents. The RHEL-family, SUSE, Alpine and Ubuntu paths are tested with synthetic fixtures only, as no real collection from those distros has been available yet.
