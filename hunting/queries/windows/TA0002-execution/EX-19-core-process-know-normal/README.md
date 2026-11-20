# EX-19 Core Windows processes that break the "Know Normal" rules (Security 4688, Sysmon 1)

| | |
|---|---|
| Tactic | TA0002 Execution |
| ATT&CK | T1036.005 Match Legitimate Name or Location, T1055 Process Injection, T1543.003 Windows Service, T1574 Hijack Execution Flow |
| Indexes | `evtxlogs-*` |
| Needs | Security 4688 (with `ParentProcessName`, Windows 10 / Server 2016 and later) and/or Sysmon 1; System 12 from `Microsoft-Windows-Kernel-General` for boot times |
| Roles | all (baseline) |
| Source | SANS DFIR "Hunt Evil" poster (FOR508), "Find Evil – Know Normal" panel |

**What it finds.** Process-creation events for the core Windows processes on the poster (`smss.exe`, `csrss.exe`, `wininit.exe`, `winlogon.exe`, `services.exe`, `lsass.exe`, `lsaiso.exe`, `svchost.exe`, `taskhostw.exe`, `RuntimeBroker.exe`, `explorer.exe`, plus `userinit.exe`) that break what is normal for them, and any child process of `lsass.exe`:

| Rule | Normal | Score |
|---|---|---|
| Path | `%SystemRoot%\System32`; `explorer.exe` in `%SystemRoot%`; `svchost.exe`, `taskhostw.exe`, `RuntimeBroker.exe` may also run from `SysWOW64` | 4 |
| Parent | `smss.exe` from System (master) or `smss.exe` (session child); `csrss.exe`, `wininit.exe`, `winlogon.exe` from `smss.exe`; `services.exe`, `lsass.exe`, `lsaiso.exe` from `wininit.exe`; `svchost.exe` from `services.exe`; `taskhostw.exe`, `RuntimeBroker.exe` from `svchost.exe`; `explorer.exe` from `userinit.exe` (also `explorer.exe`, `svchost.exe` /factory relaunch, `winlogon.exe`); `userinit.exe` from `winlogon.exe` | 3 |
| Children of lsass.exe | rare; `efsui.exe` (Encrypting File System) is the known exception and is left out | 4 |
| Account | Local System for `smss`, `csrss`, `wininit`, `winlogon`, `services`, `lsass`, `lsaiso`; `explorer.exe` never as SYSTEM, Local Service or Network Service | 3 |
| svchost.exe arguments | always `-k <service host group>` | 3 |
| Start time | `wininit`, `services`, `lsass`, `lsaiso` and the master `smss` start within seconds of boot | 3 when more than 5 minutes after the last System 12 |
| Instances | one `wininit`, `services`, `lsass`, master `smss`, and zero or one `lsaiso` per boot | 3 when two or more in the same boot |

Rows with a total of 3 or more are returned, highest first. `reasons` lists the rules broken, `expected_path` and `expected_parent` say what the poster expects.

**Reading the output.** The singletons (`wininit`, `services`, `lsass`, `lsaiso`, master `smss`) start before the Security log and Sysmon are running, so a normal boot usually leaves no 4688 or Sysmon 1 for them at all. A creation event for one of them minutes or days after `last_boot` means something started a second copy: process hollowing launchers, a renamed tool, or a copy run from another folder. A `csrss.exe` or `winlogon.exe` whose parent is not `smss.exe` is a strong lead, as is anything started by `lsass.exe` (credential-dumping tools that spawn from LSASS, malicious security packages). `svchost.exe` without `-k` is judged only on hosts that record command lines (`host_cmdlines > 0`); with only 4688 and no command-line auditing the rule stays silent. `explorer.exe` under SYSTEM usually means a shell started from a service or a scheduled task.

Security 4688 and Sysmon 1 for the same process give two rows (`source`). Chain Sysmon rows with `ProcessGuid` / `ParentProcessGuid` in [EX-02](../EX-02-process-creation-sysmon/); files on disk with the same names in the wrong folder are in [DE-09](../../TA0112-defense-impairment/DE-09-masquerading-system-binaries/).

**What it cannot see.** Instance counts and start times of processes that were already running when logging started need a memory image or a live process listing; the toolkit does not ingest those yet. Without System 12 events (`last_boot` empty) the start-time and instance rules cannot run; such singletons get 1 point and the reason "no boot event".

**If it errors.** `Unknown column` on `winlog.payload.event_data.Image` / `ParentImage` / `User` means no loaded host has Sysmon 1, and on `NewProcessName` / `ParentProcessName` / `TargetUserSid` / `TargetUserName` / `TargetDomainName` that no host has 4688 with those fields: replace the field with `null` in its `COALESCE`. `SOF-ELK_RunChecklists.py` does this by itself. [TRI-02](../../00-triage/TRI-02-event-log-coverage/) shows which event types each host has.
