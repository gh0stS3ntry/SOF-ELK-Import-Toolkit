# CA-02 Credential dump files and dump tools on disk ($MFT)

| | |
|---|---|
| Tactic | TA0006 Credential Access |
| ATT&CK | T1003.001 LSASS Memory, T1003.002 Security Account Manager, T1003.003 NTDS |
| Indexes | `filesystem-*` |
| Needs | MFTECmd `$MFT` output |
| Roles | all; domain controllers for `ntds.dit` copies |

**What it finds.** Files named like credential-theft tools, LSASS dumps, copies of the SAM/SYSTEM/SECURITY hives outside `System32\config`, `ntds.dit` outside `Windows\NTDS`, dump utilities outside their install folders, and `.dmp` files outside the crash-report folders (larger ones score higher). Staging folders and deleted records add a point.

**Reading the output.** `event_time` is the `$FN` creation time. Deleted records (`kape.mft.inuse = false`) may still be recoverable from the collection or a volume shadow copy. A dump is usually archived and sent out next: look for archives in the same folder ([CO-01](../../TA0009-collection/CO-01-archives-and-staged-files/)).
