# DE-05 Windows Firewall rules and settings changed (events)

| | |
|---|---|
| Tactic | TA0112 Defense Impairment |
| ATT&CK | T1562.004 Disable or Modify System Firewall |
| Indexes | `evtxlogs-*` |
| Needs | Security 4946/4947/4948/4950 (subcategory "MPSSVC Rule-Level Policy Change", off by default) and/or `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall` 2003-2099; firewall commands from 4688, Sysmon 1 or 4104 |
| Roles | all |

**What it finds.** Firewall rules added, modified and deleted, profile and setting changes, Group Policy firewall changes, and `netsh advfirewall`, `netsh interface portproxy` and `*-NetFirewallRule` / `Set-NetFirewallProfile` commands. `f_any_rule` marks rules or commands that mention RDP/SMB/WinRM/SSH ports, remote-access tools, user-writable paths or turning a profile off.

**Reading the output.** Software installs add many rules; sort by `_index` and look for rules added outside install times, or added on many hosts at once (pushed by the attacker). The Firewall channel names the application and port in the event text, which the importer keeps in the event's `event_data` fields. The rules that remain in the registry are in [DE-06](../DE-06-firewall-rules-registry/).

**If it errors.** `Unknown column` on `RuleName` means no 4946-4948 events were loaded; replace it with `null`.
