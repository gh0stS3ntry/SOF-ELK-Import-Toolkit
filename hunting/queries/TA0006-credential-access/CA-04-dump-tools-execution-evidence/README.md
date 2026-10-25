# CA-04 Credential dumping and memory dump tools in Amcache, ShimCache and SRUM

| | |
|---|---|
| Tactic | TA0006 Credential Access |
| ATT&CK | T1003 OS Credential Dumping |
| Indexes | `amcache-*`, `shimcache-*`, `srum-*` |
| Needs | any of the three; remove the families you did not load from `FROM` |
| Roles | all |

**What it finds.** Credential-dumping tools, dump utilities, process-inspection tools and NTDS/shadow-copy LOLBins in any of the three execution artifacts, one row per normalised path with the artifacts that saw it, users (SRUM), MB written (SRUM), SHA-1 (Amcache), and first and last time.

**Reading the output.** `ntdsutil.exe`, `vssadmin.exe` and `esentutl.exe` from System32 score 2 and are normal on domain controllers; on a workstation they need a reason. A tool seen only in ShimCache was present on disk; Amcache or SRUM make execution likely. `first_seen`/`last_seen` mix the three timestamp meanings described in [EX-15](../../TA0002-execution/EX-15-execution-evidence-pivot/).

**If it errors.** Remove the family that is not loaded and the fields that only it has (`srum.*`, `process.executable` for SRUM; `amcache.*` for Amcache).
