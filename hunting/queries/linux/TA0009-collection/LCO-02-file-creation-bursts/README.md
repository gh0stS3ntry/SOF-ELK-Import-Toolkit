# LCO-02 Bursts of files created in one folder within ten minutes (mass copy, unpacking, collection)

| | |
|---|---|
| Tactic | TA0009 Collection |
| ATT&CK | T1074.001 Local Data Staging, T1119 Automated Collection |
| Indexes | `bodyfile-*`, `auditd-*` |
| Needs | bodyfile-* with birth or inode-change times |
| Applies to | file servers and hosts holding sensitive data |

**What it finds.** Folders outside the package-managed tree in which 50 or more files were created within ten minutes, by the files' birth time (or inode-change time where the filesystem keeps no birth time) in the bodyfile, plus audited file writes. A copy keeps neither the original birth time nor the inode, so a mass copy shows as a burst in the destination folder.

**Reading the output.** Bursts of documents, configuration files or keys in a temporary, web or hidden folder are staging; a burst of documents in a home folder right before an archive appears in [LCO-01](../LCO-01-archives-dumps-and-staging/) is collection. Unpacking a downloaded tool, cloning a repository or installing an application also makes bursts: `extensions` and `sample` tell them apart. `ctime` also changes on `chmod` and `chown`, so on ext3 (no birth time) a recursive `chown` shows as a burst too.

**If it errors or looks empty.** `Unknown column [file.created]`: no `bodyfile-*` index exists; this query needs it. The audit log adds only paths its rules watch.

**Next.** [LCO-01](../LCO-01-archives-dumps-and-staging/) for archives, [LIM-02](../../TA0040-impact/LIM-02-ransomware-notes-and-encryption/) for encryption bursts.
