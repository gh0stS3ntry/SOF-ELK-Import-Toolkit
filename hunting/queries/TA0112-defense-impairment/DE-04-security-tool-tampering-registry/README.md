# DE-04 Defender, firewall, logging and security-tool settings in the registry

| | |
|---|---|
| Tactic | TA0112 Defense Impairment |
| ATT&CK | T1562.001 Disable or Modify Tools, T1562.002 Disable Windows Event Logging, T1562.004 Disable or Modify System Firewall, T1112 Modify Registry |
| Indexes | `registry-*` |
| Needs | RECmd batch output (`event.dataset: registry.batch`) that dumps the relevant keys |
| Roles | all |

**What it finds.** The state the attacker left behind, which survives even when the change events were cleared: Defender exclusions (paths, extensions, processes), Defender features or Tamper Protection off, cloud protection off, security and logging services (`WinDefend`, `Sense`, `mpssvc`, `EventLog`, Sysmon) disabled, firewall profiles off, event log channels and ETW autologgers disabled, PowerShell logging off, AMSI providers and AMSI disabled, UAC and remote token filtering, RDP enabled, and event log size/retention.

**Reading the output.** `registry.last_write` is the key's last write, not necessarily when this value changed. A value under `Policies\Microsoft\Windows Defender` comes from Group Policy or a local policy edit; compare with a clean host of the same role. Only keys your batch file dumps can appear; the stock DFIRBatch covers Defender exclusions and the main policy values but not every key listed here.
