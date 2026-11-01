# PE-11 Scheduled task XML files on disk ($MFT), outside the \Microsoft\ tree

| | |
|---|---|
| Tactic | TA0003 Persistence |
| ATT&CK | T1053.005 Scheduled Task |
| Indexes | `filesystem-*` |
| Needs | MFTECmd `$MFT` output |
| Roles | all |

**What it finds.** Every task definition file under `C:\Windows\System32\Tasks` (and the legacy `C:\Windows\Tasks` `.job` folder) that is not under `\Microsoft\`, with `$SI` and `$FN` creation times, last modification, size and whether the MFT record is deleted.

**Reading the output.** `file.filename.created` is hard to fake, so use it as the task creation time when `si_fn_gap_sec` is large (possible timestomping, [DE-01](../../TA0112-defense-impairment/DE-01-timestomping/)). Vendor tasks (Google, Adobe, OneDrive per-user tasks) appear here too; compare names across hosts. The task XML itself is in the KAPE collection under the same path.
