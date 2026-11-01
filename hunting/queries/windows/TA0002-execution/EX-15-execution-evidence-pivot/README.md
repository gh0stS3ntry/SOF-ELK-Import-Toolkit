# EX-15 Execution evidence for named files across Amcache, ShimCache and SRUM (pivot)

| | |
|---|---|
| Tactic | TA0002 Execution |
| ATT&CK | T1204.002 Malicious File |
| Indexes | `amcache-*`, `shimcache-*`, `srum-*` |
| Needs | any of the three; remove the families you did not load from `FROM` |
| Roles | all (pivot, not first cut) |

**What it finds.** Every Amcache, ShimCache and SRUM record of the files you name, side by side, with what each timestamp means.

**How to use it.** Edit the `WHERE` block: put file names in the `RLIKE` (`[.]` for a literal dot) and SHA-1 values in the `IN` list. The example names are the RD01 implant (`wabmailpv.exe`, `epdevmgr.dll`).

**Reading the output.** Amcache gives SHA-1, size, PE metadata and the file key write time; ShimCache proves the file was present and gives its `$SI` modified time; SRUM shows the hours the program was active, the user and the bytes it wrote. For Prefetch and the `$MFT`, search the same names with [EX-13](../EX-13-prefetch-rare-executables/) and `FROM filesystem-*`.

**If it errors.** `Unknown column` on `process.executable` or `srum.*` means no `srum-*` index exists; remove `srum-*` and those fields. The same applies to the other two families.
