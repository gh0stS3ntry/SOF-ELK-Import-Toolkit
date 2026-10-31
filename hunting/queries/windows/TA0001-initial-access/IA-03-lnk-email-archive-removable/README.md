# IA-03 Files opened from email attachments, archives, mounted images, removable or network drives

| | |
|---|---|
| Tactic | TA0001 Initial Access |
| ATT&CK | T1566.001 Spearphishing Attachment, T1204.002 Malicious File, T1091 Removable Media, T1553.005 Mark-of-the-Web Bypass (ISO/IMG) |
| Indexes | `lnkfiles-*` |
| Needs | LECmd output (Recent and Office\Recent `.lnk` files) |
| Roles | end-user workstation, jump host |

**What it finds.** Shortcuts Windows created when a user opened a file whose target is in the Outlook attachment cache, inside an archive's temporary extraction folder (WinRAR `Rar$EX`, 7-Zip `7zO`, Windows `Temp1_x.zip`, WinZip), on a CD-ROM drive (how a mounted ISO/IMG appears), on removable media, on a network share, or a risky file type in Downloads.

**Reading the output.** `file.created` of the `.lnk` is roughly the first time the target was opened, `file.mtime` the last time. `profile` is the user whose Recent folder held the shortcut. An `.iso`/`.img` opened from Downloads followed by an executable on a CD-ROM drive minutes later is the classic MOTW-bypass chain. `file.tracker.machine_id` is the NetBIOS name of the machine where the target lived.

**Limits.** LECmd command-line arguments are not kept by either SOF-ELK or the toolkit (see the native field reference, 3.5). Jump lists record the same opens per application: pivot with [CO-05](../../TA0009-collection/CO-05-jumplist-files-opened/).
