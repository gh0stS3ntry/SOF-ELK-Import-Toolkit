# LPE-10 Desktop autostart entries and per-user systemd units

| | |
|---|---|
| Tactic | TA0003 Persistence |
| ATT&CK | T1547.013 XDG Autostart Entries, T1543.002 Systemd Service |
| Indexes | `linuxconfig-*`, `bodyfile-*`, `logstash-*`, `auditd-*` |
| Needs | linuxconfig-* or bodyfile-* |
| Applies to | workstations and hosts with a desktop |

**What it finds.** Programs started when a user logs in to a desktop: XDG autostart entries in `/etc/xdg/autostart` and each user's `~/.config/autostart` (with their `Exec` line, hidden and enabled settings), systemd units kept in a user's home (`~/.config/systemd/user`), the files in those folders from the bodyfile and audit records, and `systemctl --user enable` or autostart-file commands.

**Reading the output.** System-wide entries in `/etc/xdg/autostart` come from packages and score only when their command is odd or the file changed recently. Entries and units inside a home folder score 2 by themselves: most users have none, and malware that runs without root (Linux stealers, crypto miners, backdoors spread through fake software) uses them because they need no privileges. Check `exec` for programs in hidden or home folders and for interpreters running scripts. Set `since` first.

**If it errors or looks empty.** `Unknown column [linuxconfig.autostart.name]`: no `linuxconfig-*` index exists; replace the `linuxconfig.*` fields with `null`. `Unknown column [file.type]`: no `bodyfile-*`; remove it.

**Next.** [LPE-01](../LPE-01-systemd-units-defined-started-and-changed/) for system units, [LPE-03](../LPE-03-shell-startup-files-and-init-scripts/) for shell startup files.
