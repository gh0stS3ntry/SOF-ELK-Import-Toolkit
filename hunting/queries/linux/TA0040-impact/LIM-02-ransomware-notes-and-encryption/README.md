# LIM-02 Ransomware: ransom notes, bursts of files with a new extension, and encryption commands

| | |
|---|---|
| Tactic | TA0040 Impact |
| ATT&CK | T1486 Data Encrypted for Impact, T1490 Inhibit System Recovery |
| Indexes | `bodyfile-*`, `logstash-*`, `auditd-*`, `linuxconfig-*` |
| Needs | bodyfile-*; logstash-*, auditd-*, linuxconfig-* for commands |
| Applies to | every Linux host; ESXi-style and file servers first |

**What it finds.** Signs of encryption for ransom: ransom-note names (`README`, `HOW_TO_DECRYPT`, `RECOVER`, `!!!`, ...) appearing in three or more folders within an hour; files with a known ransomware or encrypted-file extension (`.locked`, `.encrypted`, `.lockbit`, `.babyk`, `.akira`, `.esxiargs`, ...) appearing 20 or more times within an hour; and encryption commands (`openssl enc`, `gpg -c`, password-protected `7z`/`zip`, loops and `find -exec` running them, ESXi VM listing before encryption, `chattr -i` to unlock files) from sudo, pkexec, cron and audit records or planted in cron entries, units and startup files.

**Reading the output.** A burst of 100 or more files with one new extension (score 5) is encryption in progress or done; its first `hour` is the start of the impact. Ransom notes in many folders confirm it and name the group. Then work backwards: which account ran the encryptor ([LEX-01](../../TA0002-execution/LEX-01-commands-run-with-sudo-su-pkexec/), [LEX-02](../../TA0002-execution/LEX-02-programs-in-temp-hidden-and-user-writable-locations/)), how it got in, and what was taken first ([LCO-01](../../TA0009-collection/LCO-01-archives-dumps-and-staging/), [LEXF-01](../../TA0010-exfiltration/LEXF-01-exfiltration-tools-and-commands/); most groups steal before they encrypt). Files keep their birth time when only renamed, so on ext4 the burst shows by `ctime` (inode change on rename) where the birth time does not change; the query uses birth time first, so check `last_time` and the bodyfile's `file.ctime` as well.

**If it errors or looks empty.** `Unknown column [file.extension]`: no `bodyfile-*` index exists; this query needs it for the file rows.

**Next.** [LIM-01](../LIM-01-destructive-commands/) for wiping, [LCO-02](../../TA0009-collection/LCO-02-file-creation-bursts/) for file bursts in general.
