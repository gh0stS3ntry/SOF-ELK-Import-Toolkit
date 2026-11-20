# LM-07 Lateral movement tools in execution artifacts (source and destination side)

| | |
|---|---|
| Tactic | TA0008 Lateral Movement |
| ATT&CK | T1021.001 RDP, T1021.002 SMB/Admin Shares, T1021.006 WinRM, T1047 WMI, T1053.005 Scheduled Task, T1569.002 Service Execution |
| Indexes | `prefetch-*`, `amcache-*`, `shimcache-*`, `registry-*` |
| Needs | any of them; `registry-*` needs RECmd `UserAssist` and/or `BamDam` plugin output. Remove the families you did not load from `FROM` |
| Roles | all (baseline) |
| Source | SANS DFIR "Hunt Evil" poster (FOR508), "Hunt Evil: Lateral Movement" panel |

**What it finds.** One row per host and binary for the executables the poster lists as evidence of each lateral-movement technique, with what every execution artifact says about it side by side:

| Technique | Source host (attacker's side) | Destination host |
|---|---|---|
| RDP | `mstsc.exe` | `rdpclip.exe`, `tstheme.exe` |
| Mapped shares | `net.exe`, `net1.exe` | (files copied: [LM-04](../LM-04-executables-dropped-in-admin-share-paths/), [LM-08](../LM-08-remote-execution-filesystem-traces/)) |
| PsExec | `psexec.exe`, `psexec64.exe`, `paexec.exe`, RemCom, CSExec | `psexesvc.exe` (and PAExec / RemCom / CSExec services) |
| Scheduled tasks | `at.exe`, `schtasks.exe` | (task events: [PE-07](../../TA0003-persistence/PE-07-task-scheduler-per-task/), [PE-08](../../TA0003-persistence/PE-08-scheduled-task-created-4698/)) |
| Services | `sc.exe` | (service installs: [PE-05](../../TA0003-persistence/PE-05-service-install-events/)) |
| WMI | `wmic.exe` | `scrcons.exe`, `mofcomp.exe` |
| PowerShell remoting / WinRM | `powershell.exe`, `pwsh.exe`, `winrs.exe` | `wsmprovhost.exe`, `winrshost.exe` |

Columns per artifact: Prefetch first run (the `.pf` creation time, about 10 seconds before the first run), last run and run count; Amcache first seen (key last write) and SHA-1; ShimCache file modification time; BAM last run; UserAssist last run and run count; and the accounts that BAM and UserAssist name.

**Reading the output.** Sorted by host, then score. PsExec on either side scores 4; `wsmprovhost.exe`, `scrcons.exe`, `mofcomp.exe`, `winrs.exe` and `at.exe` score 3; `rdpclip.exe`, `tstheme.exe` and `mstsc.exe` score 2; the rest 1. A copy outside `System32` / `SysWOW64` (`outside_system_dir`) adds 2 and one in a user folder adds 2 more. A destination-side binary is the stronger lead: `rdpclip.exe` in Prefetch means someone logged on with RDP, `wsmprovhost.exe` means an inbound PowerShell remoting session, `psexesvc.exe` means PsExec ran against this host. Then line up the source and destination rows of two hosts by time and confirm with the event logs in [LM-01](../LM-01-lateral-movement-methods/) and the sessions in [LM-03](../LM-03-logon-sessions-with-duration/). `net.exe`, `sc.exe`, `schtasks.exe` and `powershell.exe` run on every host; their rows matter only when the times fall in the incident window or the run count jumps. Prefetch records the executable name only, so `exe_dirs` comes from the other artifacts; servers often have Prefetch turned off (see `EnablePrefetcher` in [DE-04](../../TA0112-defense-impairment/DE-04-security-tool-tampering-registry/)).

**What each time means.** ShimCache time is the file's last modification time, not an execution time. Amcache first seen is when the entry was written, usually the first run. BAM keeps about a week. Details are in [EX-15](../../TA0002-execution/EX-15-execution-evidence-pivot/) and [EX-16](../../TA0002-execution/EX-16-userassist-bam/).

**If it errors.** Remove the family that is not loaded from `FROM` and the fields that only it has (`kape.prefetch.*` and `file.stdinfo.ctime` for Prefetch, `amcache.*` for Amcache, `registry.*` for the registry).
