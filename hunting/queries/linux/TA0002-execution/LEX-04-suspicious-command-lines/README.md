# LEX-04 Download-and-run, encoded and interpreter one-liner command lines (logs, audit, cron, units, shell startup files)

| | |
|---|---|
| Tactic | TA0002 Execution |
| ATT&CK | T1059.004 Unix Shell, T1059.006 Python, T1027 Obfuscated Files or Information, T1105 Ingress Tool Transfer |
| Indexes | `logstash-*`, `auditd-*`, `linuxconfig-*`, `packages-*` |
| Needs | command lines in logstash-*, auditd-*, linuxconfig-*, or packages-* |
| Applies to | every Linux host |

**What it finds.** Command lines that download and run something (`curl ... | sh`, `wget -O /tmp/x && chmod +x`), decode encoded content (`base64 -d`, `xxd -r`, long base64 strings), run interpreter one-liners (`python -c`, `perl -e`, `bash -c "...curl..."`) or run programs from `/tmp`, `/dev/shm` and `/var/tmp`, wherever they were recorded: sudo, pkexec and cron messages and the command line of every process that logged (journal `_CMDLINE`), audit `execve` records, cron entries, systemd `ExecStart`, autostart entries, shell startup files and init scripts, and apt/dnf command lines.

**Reading the output.** Score 3 and up first. For log and audit rows, `first_seen` is when it ran; for `linux.*` rows it is the modification time of the file holding the line (`files`), which is the latest time it could have been planted. A download-and-run in a cron entry or a shell startup file is persistence as well ([LPE-02](../../TA0003-persistence/LPE-02-cron-and-at-jobs-configured-and-run/), [LPE-03](../../TA0003-persistence/LPE-03-shell-startup-files-and-init-scripts/)). Installers (`curl https://... | sh` for rustup, nvm, oh-my-zsh) are the usual false positives on workstations; the URL and the user decide.

**If it errors or looks empty.** `Unknown column [linuxconfig.line]`: no `linuxconfig-*` index exists; replace `linuxconfig.line` and `linuxconfig.flags` with `null`. The query uses no auditd-only field.

**Next.** [LC2-01](../../TA0011-command-and-control/LC2-01-reverse-shells-tunnels-and-proxies/) for reverse shells and tunnels, [LIA-03](../../TA0001-initial-access/LIA-03-suspicious-urls-visited-and-fetched/) for the URLs.
