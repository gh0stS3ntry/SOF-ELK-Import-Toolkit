# EX-11 ShimCache executables by rarity (long tail by path)

| | |
|---|---|
| Tactic | TA0002 Execution |
| ATT&CK | T1204.002 Malicious File, T1036 Masquerading |
| Indexes | `shimcache-*` |
| Needs | AppCompatCacheParser output for the SYSTEM hive |
| Roles | all |

**What it finds.** Least frequency of occurrence over every `.exe` in the AppCompatCache, one row per normalised path: host count, the `Executed` flags, the most recent cache position, whether the path is user-writable, and the range of `$SI` last-modified times.

**Reading the output.** `file.mtime` is the file's last-modified time recorded in the cache, **not** an execution time. `shimcache.executed` is only meaningful on Windows 7/2008 R2 and earlier; on Windows 10+ an entry means the file was present and looked at by the shim engine. `newest_position` close to 0 means the entry was added recently (before the last shutdown).

**Next.** [EX-15](../EX-15-execution-evidence-pivot/) shows the same file in Amcache and SRUM.
