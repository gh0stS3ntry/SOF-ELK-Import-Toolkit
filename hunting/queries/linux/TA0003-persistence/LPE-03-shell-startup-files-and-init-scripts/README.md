# LPE-03 Shell startup files, profile scripts, rc.local and init scripts with suspicious lines or recent changes

| | |
|---|---|
| Tactic | TA0003 Persistence |
| ATT&CK | T1546.004 Unix Shell Configuration Modification, T1037.004 RC Scripts |
| Indexes | `linuxconfig-*`, `bodyfile-*`, `logstash-*`, `auditd-*` |
| Needs | linuxconfig-* (file content); bodyfile-*, logstash-*, auditd-* add file times and edit commands |
| Applies to | every Linux host |

**What it finds.** Files that run code whenever a user logs in or opens a shell, or when the system boots: `/etc/profile` and `profile.d`, `bash.bashrc`, `/etc/environment`, zsh startup files, each user's `.bashrc`, `.profile`, `.bash_aliases` and the like, `rc.local`, `/etc/local.d` and init scripts. Each file is scored on its lines (downloads, network tools, `/dev/tcp`, `/tmp` paths, `LD_PRELOAD`, `PROMPT_COMMAND`, history settings, aliases that wrap `sudo` or `ssh`, `trap`), its modification and inode-change times from the bodyfile, audited writes, and edit commands seen in sudo or audit logs.

**Reading the output.** Score 5 and above first; `suspicious_lines` shows why. An alias or function that wraps `sudo` or `ssh` in a user's `.bashrc` is a classic credential grab; a `PROMPT_COMMAND` or `trap` that runs a program is persistence; `HISTFILE`/`HISTSIZE` settings in a startup file are anti-forensics ([LDE-01](../../TA0112-defense-impairment/LDE-01-log-and-history-tampering/)). A recently changed `.bashrc` with nothing suspicious is usually the user. `rc.local` and `/etc/local.d` exist only when someone made them on most modern distros. Set `since` first.

**If it errors or looks empty.** `Unknown column [linuxconfig.line]`: no `linuxconfig-*` index exists; this query needs it for the file content. `Unknown column [file.type]`: no `bodyfile-*`; remove it.

**Next.** [LPE-06](../LPE-06-ld-preload-and-dynamic-linker-hijacking/) for `LD_PRELOAD`, [LPE-10](../LPE-10-desktop-autostart-and-user-level-units/) for desktop autostart entries.
