# LDE-03 Timestomping and clock changes: file times that contradict each other, touch commands, and system clock changes

| | |
|---|---|
| Tactic | TA0112 Defense Impairment |
| ATT&CK | T1070.006 Timestomp, T1070 Indicator Removal |
| Indexes | `bodyfile-*`, `logstash-*`, `auditd-*` |
| Needs | bodyfile-* (file times); logstash-*, auditd-* for commands and clock changes |
| Applies to | every Linux host |

**What it finds.** Backdated files and clock tampering. In the places where attackers drop or change files (temporary and web folders, cron, systemd, init, profile and PAM folders, `/usr/local`, SSH and sudoers files, user startup files), files whose inode-change time is earlier than their modification time (not possible without changing the clock or editing the filesystem directly), files modified a day or more before they were created on this filesystem (`touch -d` sets mtime but cannot set the birth time), and times in the future. Also `touch -d/-t/-r`, `debugfs set_inode_field` and clock-setting commands (`date -s`, `timedatectl set-time`, `hwclock`, NTP turned off), journal messages about clock jumps, and audited clock syscalls.

**Reading the output.** `ctime < mtime` (4) is the strongest sign: only a clock change or raw filesystem editing makes it. `mtime` well before `crtime` is normal for files unpacked from archives or copied with `cp -p`/`rsync -a`, which is why only the watched folders are read; in those folders a backdated cron file, unit or web script is a lead, all the more if it is executable. Set the file against the commands and clock changes at the same time. ext3 and some XFS volumes keep no birth time, so only the `ctime` test works there.

**If it errors or looks empty.** `Unknown column [file.created]`: no `bodyfile-*` index exists; this query needs it for the file rows.

**Next.** [LDE-04](../LDE-04-hidden-masquerading-and-deleted-binaries/) for hidden and masquerading files, [LTRI-02](../../00-triage/LTRI-02-boots-shutdowns-and-log-gaps/) for clock and boot context.
