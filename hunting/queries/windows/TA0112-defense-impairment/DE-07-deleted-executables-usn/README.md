# DE-07 Executables and scripts deleted (USN `$J`)

| | |
|---|---|
| Tactic | TA0112 Defense Impairment |
| ATT&CK | T1070.004 File Deletion |
| Indexes | `filesystem-*` |
| Needs | MFTECmd `$J` output |
| Roles | all |

**What it finds.** Every `$J` record with a delete reason for a binary, installer, shortcut or script, with the file's MFT entry and parent entry so it can be tied back to the `$MFT` (the entry may already be reused). `f_userpath` marks user-writable and staging folders when the path is known; `name_hosts` and `deletes_of_name` show whether the same file name was deleted on several hosts or many times (normal for updaters).

**Reading the output.** The earlier engagement's query, with the path flag and the per-name counts added and `file.update_timestamp` dropped (its type differs between indexes). `$J` rows often carry only the file name; resolve the folder through `file.parent.inode` in the `$MFT`. A tool deleted minutes after its last execution ([EX-15](../../TA0002-execution/EX-15-execution-evidence-pivot/)) is classic clean-up.
