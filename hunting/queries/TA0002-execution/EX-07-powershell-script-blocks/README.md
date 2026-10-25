# EX-07 Suspicious PowerShell script blocks (4104)

| | |
|---|---|
| Tactic | TA0002 Execution |
| ATT&CK | T1059.001 PowerShell, T1027 Obfuscated Files, T1562.001 Disable or Modify Tools, T1105 Ingress Tool Transfer |
| Indexes | `evtxlogs-*` |
| Needs | PowerShell Operational 4104. Windows logs suspicious script blocks as warnings by default; full logging needs the Script Block Logging policy |
| Roles | all |

**What it finds.** Script blocks scored on AMSI and ETW bypasses, offensive PowerShell frameworks, reflective loading and Win32 API use, Defender exclusions or disabling, event log clearing, shadow copy manipulation, download-and-execute, encoding/compression/XOR, dynamic execution and tick or string-concatenation obfuscation.

**Reading the output.** Large scripts are split across several 4104 events with the same `ScriptBlockId` (`MessageNumber` of `MessageTotal`); a hit in one part means you should read all of them. `Path` is the script file, empty for interactive or encoded commands. `user.id` is the SID that ran it.

**Next.** Re-run with `| WHERE winlog.payload.event_data.ScriptBlockId == "<id>"` and `| SORT winlog.payload.event_data.MessageNumber ASC` to rebuild a whole script.
