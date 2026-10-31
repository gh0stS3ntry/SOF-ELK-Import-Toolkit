# LIM-01 Destructive commands: wiping disks and folders, dropping databases, killing services and containers

| | |
|---|---|
| Tactic | TA0040 Impact |
| ATT&CK | T1485 Data Destruction, T1561 Disk Wipe, T1489 Service Stop, T1531 Account Access Removal |
| Indexes | `logstash-*`, `auditd-*`, `linuxconfig-*` |
| Needs | commands in logstash-*, auditd-*, or linuxconfig-* (cron, units, startup files) |
| Applies to | every Linux host |

**What it finds.** Commands that destroy data or stop the host from doing its job: recursive deletes of `/`, `/etc`, `/home`, `/var`, backup and data folders; `shred`, `wipe`, `dd` from `/dev/zero` or `/dev/urandom` onto a disk, `mkfs`, `wipefs`, partition-table wipes; `truncate -s 0`, `crontab -r`, `find -delete`; database, web, container and backup services stopped or masked; `docker rm -f`, volume prunes, `kubectl delete`, `virsh destroy`, ESXi VM kills; `DROP DATABASE`/`TABLE`; `userdel -r`, locking root, mass `kill -9`. Read from sudo, pkexec, cron and audit command lines, and from cron entries, units and startup files (a planted logic bomb).

**Reading the output.** Newest first. Wiping and database drops on a production host are rarely routine; check who (`user.name`, `user.effective.name`) and from which session. A destructive line in a cron entry, unit or startup file (`linux.*` rows) is a time bomb: its schedule is in [LPE-02](../../TA0003-persistence/LPE-02-cron-and-at-jobs-configured-and-run/) and [LPE-01](../../TA0003-persistence/LPE-01-systemd-units-defined-started-and-changed/). Developers and CI hosts run `docker system prune` and `rm -rf` on build folders often; the target folder decides.

**If it errors or looks empty.** No rows on a host without auditd can simply mean the commands ran without sudo. `Unknown column [linuxconfig.line]`: no `linuxconfig-*` index exists; replace `linuxconfig.line` with `null` and remove it from `KEEP`.

**Next.** [LIM-02](../LIM-02-ransomware-notes-and-encryption/) for encryption, [LDE-01](../../TA0112-defense-impairment/LDE-01-log-and-history-tampering/) for log wiping that often follows.
