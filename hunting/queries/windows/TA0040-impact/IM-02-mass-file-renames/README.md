# IM-02 Mass renames to a new extension (encryption bursts)

| | |
|---|---|
| Tactic | TA0040 Impact |
| ATT&CK | T1486 Data Encrypted for Impact |
| Indexes | `filesystem-*` |
| Needs | MFTECmd `$J` output (`$J` covers days to weeks on a busy volume; collect it early) |
| Roles | all; file servers first |

**What it finds.** Five-minute windows where 50 or more files were renamed to (or created with) the same extension, or the extension appeared in 20 or more folders, leaving out temp, cache and update churn. Known locker extensions, long letter-and-digit extensions (per-victim IDs), volume and spread score higher.

**Reading the output.** `first_seen` of the top row per host is when encryption started there; across hosts it shows the order in which the encryptor ran (and often the host it was pushed from). Search the MFT for the ransom note next to the encrypted files ([IM-03](../IM-03-ransom-notes/)) and for the encryptor's execution around `first_seen` ([EX-15](../../TA0002-execution/EX-15-execution-evidence-pivot/)). Ransomware that encrypts in place without renaming will not show here.
