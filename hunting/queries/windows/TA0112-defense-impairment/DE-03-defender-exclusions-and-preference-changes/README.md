# DE-03 Defender exclusions and protection settings changed

| | |
|---|---|
| Tactic | TA0112 Defense Impairment |
| ATT&CK | T1562.001 Disable or Modify Tools |
| Indexes | `evtxlogs-*` |
| Needs | Defender Operational 5007 (and 5001/5010/5012/5013); `Set-MpPreference` commands from 4688, Sysmon 1 or 4104 |
| Roles | all |

**What it finds.** A timeline of every Defender exclusion added or removed, protection features turned off, cloud protection and sample submission disabled, Tamper Protection changes, default-action changes and ASR/Network Protection changes from 5007 `New Value`/`Old Value`, plus the commands that do the same (`Add-MpPreference -ExclusionPath`, `Set-MpPreference -Disable...`, `MpCmdRun -RemoveDefinitions`, `reg add ...\Windows Defender`, stopping `WinDefend`). `f_excl_suspicious` marks exclusions of user-writable folders, whole drives and executable types.

**Reading the output.** [TRI-03](../../00-triage/TRI-03-defender-events/) shows these next to detections; this query is the full settings history. Exclusions pushed by Group Policy or Intune also appear as 5007, so ask the client for their baseline. An exclusion added minutes before a tool appears on disk is a strong lead.
