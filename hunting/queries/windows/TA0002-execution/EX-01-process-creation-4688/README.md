# EX-01 Suspicious process creation (Security 4688)

| | |
|---|---|
| Tactic | TA0002 Execution |
| ATT&CK | T1059 Command and Scripting Interpreter, T1218 System Binary Proxy Execution, T1204.002 Malicious File, T1047 WMI |
| Indexes | `evtxlogs-*` |
| Needs | Security 4688 ("Audit Process Creation"). Command lines need "Include command line in process creation events"; without it the query still scores image and parent names |
| Roles | all |

**What it finds.** Process creations scored on: attack tools and destructive commands, shells or LOLBins spawned by web/database servers, Office, WMI or browsers, encoded/hidden PowerShell and download cradles, images in user-writable folders, URLs or UNC-to-IP paths, script arguments, LOLBins and discovery commands. Only rows scoring 3 or more are returned.

**Reading the output.** `reasons` explains the score. `cmd` comes from EvtxECmd's `ExecutableInfo`: the command line when command-line auditing is on, otherwise just the image path. `TokenElevationType` `%%1937` means a full admin token. Use `NewProcessId` / `ProcessId` (hex) to chain children to parents on the same host.

**Tuning.** Lower `WHERE score >= 3` to 2 to see every LOLBin with any second signal. Add known management tools (SCCM, backup agents) as `AND NOT parent_name IN (...)` before the `WHERE score` line.

**Variants.** [EX-02](../EX-02-process-creation-sysmon/) is the same hunt on Sysmon 1, with hashes and parent command lines. [EX-03](../EX-03-rare-parent-child-4688/) ranks parent and child pairs by rarity.
