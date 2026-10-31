# Linux accounts and persistence schema (`linuxconfig-*`)

Loaded by `Linux/linuxconfig2sofelk.py` (also run by `Linux/linux2sofelk.py`). Mapping: `Linux/index_templates/component-toolkit-linux-common.json` plus `Linux/index_templates/index-linuxconfig.json`, installed as the index template `sofelk-toolkit-linuxconfig` for `linuxconfig-*`. The index uses `dynamic: false`, so a field not listed here is not searchable. The common fields (`host.*`, `case`, `event.dataset`, `log.file.path`, ...) are listed in [linux-logstash.md](linux-logstash.md#common-fields-every-linux-index).

A snapshot, not events: `event.kind` is `state`, `event.category` is `configuration`, and `@timestamp` is the **modification time of the source file** (for a systemd link, of the link itself, which is when the unit was enabled). Stack documents across hosts (`STATS ... BY`) for least-frequency-of-occurrence hunting.

## Where `@timestamp` and `file.*` come from

`linuxconfig.mtime_source` says which source was used:

| Value | Source |
|---|---|
| `bodyfile` | UAC `bodyfile/bodyfile.txt`: exact epoch times, owner, mode, and symlink targets (also for files UAC did not copy, such as masks pointing at `/dev/null`) |
| `filesystem` | the evidence folder (`lstat`; symlinks are never followed on the analyst's machine, absolute links are resolved inside the evidence root) |
| `zip` | the zip entry date, which zip stores in the collecting host's local time; read with the evidence's time zone. UAC stores symlinks as copies, so links are recognised by folder (`*.wants/`) or by identical content |

## Datasets

| `event.dataset` | `event.action` / `linuxconfig.kind` | Read from |
|---|---|---|
| `linux.account` | `account` | `/etc/passwd`, `/etc/passwd-`, **metadata** from `/etc/shadow` |
| `linux.group` | `group` | `/etc/group`, `/etc/group-` |
| `linux.sudoers` | `rule`, `defaults`, `alias`, `include` | `/etc/sudoers`, `/etc/sudoers.d/*`, included files (names with a dot or ending in `~` are skipped, as sudo does) |
| `linux.cron` | `entry`, `variable`, `script_line` | `/etc/crontab`, `/etc/cron.d/*`, `/etc/anacrontab`, `/var/spool/cron/crontabs/*`, `/var/spool/cron/*`, `/var/spool/cron/tabs/*`, `/etc/crontabs/*`; scripts in `/etc/cron.{hourly,daily,weekly,monthly,yearly}`, `/etc/periodic/*`, at jobs (`/var/spool/cron/atjobs`, `/var/spool/at`, `/var/spool/atjobs`) |
| `linux.systemd_unit` | `unit`, `dropin`, `link` | `/etc/systemd/{system,user}`, `/run/systemd/system`, `/usr/local/lib/systemd/system`, `/usr/lib/systemd/{system,user}`, `/lib/systemd/...` (skipped when `/lib` links to `usr/lib`), `~/.config/systemd/user`, `~/.local/share/systemd/user` |
| `linux.init_script` | `rc.local`, `init.d`, `rc_link`, `local.d`, `profile`, `environment`, `user_profile` | one document per non-comment line: `rc.local`, `/etc/init.d` (or `rc.d/init.d`), `rc?.d` entries with no `init.d` script, `/etc/local.d/*.start|stop`, `/etc/profile`, `/etc/profile.d/*`, `bash.bashrc`, `bashrc`, `/etc/environment`, zsh startup files, and each user's `.bashrc .bash_profile .bash_login .profile .bash_aliases .bash_logout .zshrc .zprofile .zshenv .zlogin .zlogout` |
| `linux.autostart` | `autostart` | `/etc/xdg/autostart/*.desktop`, `~/.config/autostart/*.desktop` |
| `linux.ssh_key` | `authorized_keys`, `known_hosts` | `~/.ssh/authorized_keys`, `authorized_keys2`, `known_hosts` for `/root` and every home, `/etc/ssh/ssh_known_hosts` |
| `linux.hosts` | `entry` | `/etc/hosts`, including commented-out entries |
| `linux.resolver` | `setting` | `/etc/resolv.conf`, `/etc/systemd/resolved.conf`, `resolved.conf.d/*.conf` |
| `linux.ld_preload` | `preload`, `library_path`, `include` | `/etc/ld.so.preload`, `/etc/ld.so.conf`, `/etc/ld.so.conf.d/*.conf` |
| `linux.repository` | `repository` | `/etc/apt/sources.list`, `sources.list.d/*.list` and `*.sources` (deb822), `/etc/yum.repos.d/*.repo`, `/etc/distro.repos.d/*.repo`, `/etc/zypp/repos.d/*.repo`, `/etc/apk/repositories` |

**Never read or stored:** password hashes (the shadow field is reduced to a state and an algorithm in memory and then discarded), `/etc/gshadow`, private keys (`id_*`, `ssh_host_*_key`), shell history, credential stores and UAC `live_response/`.

## Fields shared by the datasets

| Field | Type | Content |
|---|---|---|
| `linuxconfig.kind` | keyword | as `event.action` |
| `linuxconfig.line` (+ `.text`) | keyword (8191) + match_only_text | the source line (continuations joined); not set for accounts and groups |
| `linuxconfig.line_number` | integer | line in the source file, from 1 |
| `linuxconfig.flags` | keyword | markers worth a look, see below |
| `linuxconfig.mtime_source` | keyword | see above |
| `file.path` / `name` / `directory` | keyword | the source file on the evidence host (`/etc/cron.d/php`) |
| `file.mtime` / `file.ctime` | date | |
| `file.uid` / `file.gid` / `file.mode` / `file.size` | keyword / keyword / keyword / long | `mode` is octal, e.g. `0644` |
| `file.type` / `file.target_path` | keyword | `file` or `symlink`, and the link target |
| `user.name` | keyword | the account (accounts), the run-as user (cron), the owner of a per-user file, the principal of a sudoers rule |
| `process.command_line` (+ `.text`) / `process.executable` | keyword | cron command, first `ExecStart`, autostart `Exec`, SSH forced command |

`linuxconfig.flags` values: `uid0` (UID 0 but not root), `duplicate_uid`, `empty_password`, `password_in_passwd`, `password_change_required`, `sudoers_rule` (account or group named in sudoers), `nopasswd`, `all_commands`, `env_preserved` (sudoers keeps `LD_*` or disables `env_reset`), `ld_preload`, `dev_tcp`, `download_exec` (`curl|wget ... | sh`), `base64_decode`, `reverse_shell`, `runs_from_temp` (an `Exec*` under `/tmp`, `/var/tmp`, `/dev/shm`), `root_authorized_key`, `unsigned_repository` (`trusted=yes` or `gpgcheck=0`). Flags are pointers for triage, not verdicts.

## Per-dataset fields

| Field | Type | Content |
|---|---|---|
| `user.id` / `user.group.id` / `user.full_name` | keyword | passwd UID, GID, first GECOS field |
| `linuxconfig.account.gecos` / `home` / `shell` | keyword | |
| `linuxconfig.account.login_shell` / `system_account` | boolean | shell is not nologin/false/sync/...; UID below `UID_MIN` from `/etc/login.defs` (default 1000) |
| `linuxconfig.account.state` | keyword | `present`, `new_since_backup` (in `passwd` but not `passwd-`, the copy before the last change), `only_in_backup` (removed by the last change) |
| `linuxconfig.account.password_state` | keyword | `set`, `locked` (`!` before a hash), `no_password` (`*`), `locked_no_password` (`!`, `!!`, `!*`), `empty` (no password at all) |
| `linuxconfig.account.password_algorithm` | keyword | `yescrypt`, `sha512`, `sha256`, `md5`, `bcrypt`, `scrypt`, `gost-yescrypt`, `des`, ... |
| `linuxconfig.account.password_last_changed` / `account_expires` | date | shadow fields 3 and 8 |
| `linuxconfig.account.password_min_days` / `max_days` / `warn_days` / `inactive_days` | integer | `max_days` 99999 (never) is left empty |
| `group.name` / `group.id` | keyword | groups; also the group of a `%group` sudoers rule |
| `linuxconfig.group.members` / `primary_members` | keyword | listed members / accounts whose primary GID this is |
| `linuxconfig.group.state` / `previous_members` / `members_added` / `members_removed` | keyword | compared with `/etc/group-`: `present`, `new_since_backup`, `changed_since_backup`, `only_in_backup` |
| `linuxconfig.group.privileged` | boolean | root, sudo, wheel, adm, admin, docker, lxd, libvirt, disk, shadow, or named in a sudoers rule |
| `linuxconfig.sudoers.principals` / `principal_type` / `hosts` / `runas` / `tags` / `commands` | keyword | `principal_type`: `user`, `group`, `netgroup`, `alias`, `all` |
| `linuxconfig.sudoers.nopasswd` / `all_commands` | boolean | |
| `linuxconfig.sudoers.defaults` / `defaults_scope` / `alias_type` / `alias_name` / `include` | keyword | |
| `linuxconfig.cron.source` | keyword | `system`, `user`, `anacron`, `periodic`, `at` |
| `linuxconfig.cron.schedule` | keyword | `*/5 * * * *`, `@reboot`, anacron period, or the periodic folder (`daily`, `15min`) |
| `linuxconfig.cron.variable_name` / `variable_value` / `job_id` / `delay_minutes` | keyword / keyword / keyword / integer | |
| `linuxconfig.systemd.unit` / `unit_type` / `scope` / `origin` | keyword | `scope` `system`/`user`; `origin` `admin` (`/etc`, `/usr/local`), `vendor` (`/usr/lib`, `/lib`), `runtime` (`/run`), `user_home` |
| `linuxconfig.systemd.description` / `service_type` / `run_as_user` | keyword | |
| `linuxconfig.systemd.exec_start` / `exec_other` (+ `.text`) | keyword | `ExecStart` values (prefixes `-@:+!` removed) / `ExecStartPre=...`, `ExecStop=...` |
| `linuxconfig.systemd.environment` | keyword | `Environment` and `EnvironmentFile=` values |
| `linuxconfig.systemd.wanted_by` | keyword | `[Install] WantedBy` / `RequiredBy` (what `systemctl enable` would do) |
| `linuxconfig.systemd.enabled` / `enabled_by` | boolean / keyword | a link to the unit exists in `<target>.wants/`, `.requires/` or `.upholds/` |
| `linuxconfig.systemd.masked` | boolean | linked to `/dev/null` |
| `linuxconfig.systemd.link_kind` / `link_target` / `link_inferred` | keyword / keyword / boolean | `wants`, `requires`, `upholds`, `alias`, `mask`; `link_inferred` when the target was matched by content in a zip without a bodyfile |
| `linuxconfig.systemd.timer_schedule` / `listen` / `path_watch` / `triggers_unit` | keyword | timers (`OnCalendar=...`), sockets (`ListenStream=...`), path units, and the unit they start |
| `linuxconfig.init.kind` | keyword | as `event.action` |
| `linuxconfig.autostart.name` / `only_show_in` / `not_show_in` | keyword | |
| `linuxconfig.autostart.hidden` / `enabled` | boolean | `Hidden`, `X-GNOME-Autostart-enabled` |
| `linuxconfig.ssh.key_type` / `fingerprint` / `comment` | keyword | `fingerprint` is `SHA256:...` as `ssh-keygen -l` prints it; the key itself is not stored |
| `linuxconfig.ssh.options` / `forced_command` / `from` | keyword | authorized_keys options |
| `linuxconfig.ssh.hosts` / `hashed` / `marker` | keyword / boolean / keyword | known_hosts (hosts only when not hashed; `@cert-authority`, `@revoked`) |
| `linuxconfig.hosts.ip` / `names` / `commented` | ip / keyword / boolean | commented entries often name earlier targets |
| `linuxconfig.resolver.directive` / `values` / `servers` | keyword / keyword / ip | |
| `linuxconfig.ld.entry` | keyword | library or folder |
| `linuxconfig.repository.manager` / `id` / `name` / `type` / `suites` / `components` / `urls` / `signed_by` / `options` | keyword | |
| `linuxconfig.repository.enabled` / `gpgcheck` / `trusted` | boolean | |
| `url.original` / `url.scheme` / `url.domain` | keyword | the repository URL |

## Example queries

```esql
// Enabled services and timers that are not vendor units, newest first
FROM linuxconfig-* METADATA _index
| WHERE event.dataset == "linux.systemd_unit" AND event.action IN ("unit", "dropin")
  AND linuxconfig.systemd.origin != "vendor"
| KEEP @timestamp, _index, linuxconfig.systemd.unit, linuxconfig.systemd.origin, linuxconfig.systemd.enabled,
       linuxconfig.systemd.exec_start, linuxconfig.systemd.run_as_user, file.path, linuxconfig.flags
| SORT @timestamp DESC
```

```esql
// Accounts that can log in, have UID 0 or an empty password, or were changed by the last edit
FROM linuxconfig-* METADATA _index
| WHERE event.dataset == "linux.account"
| EVAL flags = COALESCE(MV_CONCAT(linuxconfig.flags, ","), "")
| WHERE linuxconfig.account.login_shell == true OR flags LIKE "*uid0*" OR flags LIKE "*empty_password*"
  OR linuxconfig.account.state != "present"
| KEEP _index, user.name, user.id, linuxconfig.account.shell, linuxconfig.account.state,
       linuxconfig.account.password_state, linuxconfig.account.password_last_changed, linuxconfig.flags
| SORT user.id
```

```esql
// Cron commands seen on only one host (stacking)
FROM linuxconfig-* METADATA _index
| WHERE event.dataset == "linux.cron" AND event.action IN ("entry", "script_line")
| EVAL what = COALESCE(process.command_line, linuxconfig.line)
| STATS hosts = COUNT_DISTINCT(host.name), indexes = VALUES(_index) BY what
| WHERE hosts == 1
```
