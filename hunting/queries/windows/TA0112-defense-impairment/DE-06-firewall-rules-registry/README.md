# DE-06 Inbound allow rules and odd programs in the firewall rule list (registry)

| | |
|---|---|
| Tactic | TA0112 Defense Impairment |
| ATT&CK | T1562.004 Disable or Modify System Firewall, T1219 Remote Access Software |
| Indexes | `registry-*` |
| Needs | RECmd `FirewallRules` plugin output from the SYSTEM hive |
| Roles | all; servers first |

**What it finds.** Active allow rules that point at a program in a user-writable folder, a LOLBin, a remote-access or tunnel tool, inbound rules for admin ports (RDP, SMB, RPC, WinRM, SSH, VNC, SQL, 4444) or any port with no program, and rules that exist on one host only. Rows score 2 or more.

**Reading the output.** These are the rules in place when the hive was collected, whether or not the change events survived ([DE-05](../DE-05-firewall-rule-changes-events/)). `registry.last_write` is the last write of the whole `FirewallRules` key, so it dates the newest change on that host, not this rule.

**If it errors.** The plugin's column names (`Action`, `Active`, `Dir`, `App`, `LPort`, `RPort`, `Name`, `Desc`, `Protocol`) map to `registry.plugin.<snake_case>`; if your RECmd version names them differently, adjust the field names to what Discover shows for `event.dataset: registry.firewallrules`.
