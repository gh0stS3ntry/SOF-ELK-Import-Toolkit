# EX-10 Amcache executables by rarity (long tail by SHA-1)

| | |
|---|---|
| Tactic | TA0002 Execution |
| ATT&CK | T1204.002 Malicious File, T1036 Masquerading |
| Indexes | `amcache-*` |
| Needs | AmcacheParser `UnassociatedFileEntries` / `AssociatedFileEntries` |
| Roles | all |

**What it finds.** Least frequency of occurrence over every `.exe` Amcache recorded, grouped by SHA-1: how many hosts and entries have it, every path it was seen at, product name, PE link date, whether any copy sat in a user-writable folder, and the first and last Amcache key write.

**Reading the output.** Rare hashes, `in_userpath = 1`, `os_component = 0` and empty `products` together are the shortlist. Several `fullpaths` for one hash means the same tool was copied around or renamed. `amcache.file_key_last_write` is often close to first execution but is not proof of it; confirm with [EX-11](../EX-11-shimcache-long-tail/), [EX-13](../EX-13-prefetch-rare-executables/) and [EX-16](../EX-16-userassist-bam/).

**Tuning.** The SHA-1 exclusions are Microsoft binaries that were unique per update on RD01. Add your own known-good hashes there, or remove the block. Remove the `.exe` line to include DLLs and drivers.

**Next.** Put the suspicious hashes or names into [EX-15](../EX-15-execution-evidence-pivot/) to see every execution artifact for them.
