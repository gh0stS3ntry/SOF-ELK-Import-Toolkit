# Linux package schema (`packages-*`)

Loaded by `Linux/packages2sofelk.py` (also run by `Linux/linux2sofelk.py`). Mapping: `Linux/index_templates/component-toolkit-linux-common.json` plus `Linux/index_templates/index-packages.json`, installed as the index template `sofelk-toolkit-packages` for `packages-*`. The index uses `dynamic: false`, so a field not listed here is not searchable. The common fields (`host.*`, `case`, `event.dataset`, `log.file.path`, `log.offset`, ...) are listed in [linux-logstash.md](linux-logstash.md#common-fields-every-linux-index).

One document per package action from each package manager's log, and one per installed package from the package database.

## Datasets

| `event.dataset` | Source | Granularity | `@timestamp` |
|---|---|---|---|
| `packages.dpkg` | `/var/log/dpkg.log*` | one `install`, `upgrade`, `remove`, `purge` line (`status`, `configure`, `trigproc` and `startup` lines are counted as not loaded) | the line's local time |
| `packages.apt` | `/var/log/apt/history.log*` | one document per package per transaction, with the apt command line and the user | `Start-Date` (local) |
| `packages.dnf` | `/var/log/dnf.rpm.log*` | one `Installed`, `Upgrade`, `Erase`, `Downgrade`, `Reinstall`, `Obsoleted` line; `Upgraded:` lines become `packages.previous_version` | the line's time (with its UTC offset) |
| `packages.dnf_history` | `/var/lib/dnf/history.sqlite` | one document per package per dnf transaction, with command line, user and repository | transaction begin (epoch) |
| `packages.yum` | `/var/log/yum.log*` (RHEL/CentOS 7) | one line | the line's local time; no year in the file, see below |
| `packages.zypper` | `/var/log/zypp/history*` | `install`, `remove`, `patch`, `command`, `radd`, `rremove` lines | the line's local time |
| `packages.inventory` | `/var/lib/dpkg/status`, `rpmdb.sqlite` (`/var/lib/rpm/` or `/usr/lib/sysimage/rpm/`), `/lib/apk/db/installed` | one installed package (`event.kind` `state`) | the install time where known, else the database file's mtime |

Hosts with both `dnf.rpm.log` and `history.sqlite` (RHEL 8+) have the same actions in both datasets: pick one with `WHERE event.dataset == "packages.dnf_history"` when counting.

## Fields

| Field | Type | Content |
|---|---|---|
| `event.action` | keyword | `install`, `upgrade`, `downgrade`, `reinstall`, `remove`, `purge`, `obsoleted`, `reason-change`, `command`, `patch`, `repository-added`, `repository-removed`; inventory: `installed` or the dpkg state (`config-files`, `half-installed`, ...) |
| `event.category` / `event.type` | keyword | `package` / `installation`, `change`, `deletion`, `info`; repository changes are `configuration` |
| `event.outcome` | keyword | apt (`failure` when the block has `Error:`), dnf history (transaction item state) |
| `event.start` / `event.end` | date | apt `Start-Date` / `End-Date`, dnf `dt_begin` / `dt_end` |
| `event.timezone` | keyword | the zone used for local times |
| `event.original` | keyword (8191) + `.text` | the log line (dpkg, dnf, yum, zypper) |
| `error.message` | keyword + `.text` | apt `Error:` |
| `package.name` / `version` / `architecture` | keyword | rpm versions are `[epoch:]version-release` |
| `package.type` | keyword | `deb`, `rpm`, `apk` |
| `package.manager` | keyword | `dpkg`, `apt`, `dnf`, `yum`, `zypper`, `rpm`, `apk` |
| `package.description` | keyword + `.text` | dpkg `Description`, rpm `SUMMARY`, apk `T:` |
| `package.installed` | date | rpm `INSTALLTIME`; dpkg: mtime of `/var/lib/dpkg/info/<package>.list` from the UAC bodyfile (the last install or upgrade) |
| `package.size` | long | installed size in bytes |
| `package.build_version` | keyword | build time (rpm `BUILDTIME`, apk `t:`) as ISO 8601 |
| `package.reference` | keyword | apk project URL |
| `packages.previous_version` | keyword | version before an upgrade or downgrade |
| `packages.automatic` | boolean | installed as a dependency: apt `automatic`, dnf reason `dependency`/`weak-dependency`, yum `Dep-Installed`, zypper with no requester, apk not in `/etc/apk/world` |
| `packages.reason` | keyword | dnf history reason: `user`, `dependency`, `weak-dependency`, `clean`, `group`, `unknown` |
| `packages.repository` | keyword | dnf history repo id, zypper repository alias |
| `packages.transaction_id` | keyword | dnf transaction id; apt `Start-Date` |
| `packages.status` | keyword | dpkg `Status` line |
| `packages.source_package` / `maintainer` / `vendor` | keyword | from the package database |
| `packages.mtime_source` | keyword | inventory only: where `@timestamp` came from (`bodyfile dpkg info list`, `rpm installtime`, `bodyfile`, `filesystem`, `zip`) |
| `user.name` / `user.id` | keyword | apt `Requested-By`, dnf `user_id` (name from the evidence's `/etc/passwd`), zypper requester |
| `process.command_line` | keyword + `.text` | apt `Commandline`, dnf `cmdline`, zypper `command` (also copied to the actions that follow it within 30 minutes) |
| `url.original` | keyword | zypper `radd` URL |

## Notes

- `yum.log` has no year. It is taken from the file's modification time and counted back over each December to January rollover (`--year` sets the year of the last line instead).
- RHEL 8 and older keep the rpm database in Berkeley DB, which the standard library cannot read: those hosts get `packages.dnf` / `packages.dnf_history` / `packages.yum` but no rpm inventory.
- Not read: `apt/term.log` (terminal output), `dnf.log` and `dnf5.log` (debug text; the history database has the same transactions).
- The RHEL, SUSE and Alpine formats are tested with synthetic fixtures only. The Debian path was also checked against a real Kali UAC collection.

## Example queries

```esql
// Packages installed or upgraded inside the incident window, with who asked for them
FROM packages-* METADATA _index
| WHERE @timestamp >= "2026-10-20T00:00:00Z" AND @timestamp < "2026-10-22T00:00:00Z"
  AND event.dataset IN ("packages.apt", "packages.dnf_history", "packages.zypper", "packages.yum", "packages.dpkg")
| KEEP @timestamp, _index, event.dataset, event.action, package.name, package.version, packages.previous_version,
       user.name, process.command_line
| SORT @timestamp
```

```esql
// Least common installed packages across hosts (stacking)
FROM packages-* METADATA _index
| WHERE event.dataset == "packages.inventory" AND event.action == "installed"
| STATS hosts = COUNT_DISTINCT(host.name), indexes = VALUES(_index), first_installed = MIN(package.installed)
    BY package.name, package.manager
| WHERE hosts == 1
| SORT first_installed DESC
```
