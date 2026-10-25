# EX-14 .NET CLR loaded by unusual processes (CLR usage logs)

| | |
|---|---|
| Tactic | TA0002 Execution |
| ATT&CK | T1620 Reflective Code Loading, T1055 Process Injection, T1218 System Binary Proxy Execution |
| Indexes | `clrusagelogs-*` |
| Needs | `ConvertUsageLogsTo-CSV.ps1` output (KAPE `PowerShell_ConvertUsageLogsTo-CSV`) |
| Roles | all |

**What it finds.** Every process that loaded the .NET runtime, per user (`%LOCALAPPDATA%\Microsoft\CLR_v4.0\UsageLogs\<process>.log`), scored higher when the process should never host .NET (`rundll32`, `dllhost`, `svchost`, `werfault`, `notepad`...), is a .NET-capable LOLBin (`msbuild`, `installutil`, `regasm`, `mshta`), is an Office application, or appears on one host only.

**Reading the output.** C2 frameworks that run .NET assemblies in memory (`execute-assembly`) inject them into a sacrificial process, which then leaves a usage log the first time it loads the CLR. `clr_usage.first_execution_timestamp` is that first time for the user. All rows are returned, so the long tail of ordinary .NET programs is below the scored ones.
