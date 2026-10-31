# EX-04 Rare binaries by hash (Sysmon 1)

| | |
|---|---|
| Tactic | TA0002 Execution |
| ATT&CK | T1204.002 Malicious File, T1036 Masquerading |
| Indexes | `evtxlogs-*` |
| Needs | Sysmon event 1 with `Hashes` (any of SHA256, SHA1, MD5) |
| Roles | all |

**What it finds.** Long-tail analysis by file hash: one row per distinct binary that Sysmon saw executing, with how many hosts ran it, under which paths, users and PE company names.

**Reading the output.** Binaries run on one host, a few times, with no company, from a user-writable path, are the first candidates. A hash seen under several unrelated paths may be a tool copied around. Check the hashes against threat intelligence and pivot to Amcache with [EX-15](../EX-15-execution-evidence-pivot/) (`file.hash.sha1`) to see the same file on hosts without Sysmon.

**If it errors.** `Unknown column` on `Company`: older Sysmon schemas do not log it; remove the `company` lines.
