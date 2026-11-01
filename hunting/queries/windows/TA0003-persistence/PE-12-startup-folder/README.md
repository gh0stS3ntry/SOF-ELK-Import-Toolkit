# PE-12 Files in Startup folders ($MFT and $J), scored

| | |
|---|---|
| Tactic | TA0003 Persistence |
| ATT&CK | T1547.001 Registry Run Keys / Startup Folder |
| Indexes | `filesystem-*` |
| Needs | MFTECmd `$MFT` and/or `$J` output |
| Roles | end-user workstation, RDP/jump host; all hosts for the all-users folder |

**What it finds.** Files present in, or written to and deleted from, the per-user and all-users Startup folders, scored for executables and scripts, double extensions, shortcuts, hidden/system attributes, `$SI` earlier than `$FN` (possible timestomping), no extension, deletion, and Startup paths in unusual places.

**Reading the output.** `$J` rows (`record_type = USN $J`) show files that were created and removed before collection; `reasons` lists the USN reasons. For a `.lnk`, read its target in `lnkfiles-*` by name, or open the file from the collection.
