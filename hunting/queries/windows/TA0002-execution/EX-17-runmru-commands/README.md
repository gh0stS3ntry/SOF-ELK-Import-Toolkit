# EX-17 Commands typed in the Run dialog (RunMRU)

| | |
|---|---|
| Tactic | TA0002 Execution |
| ATT&CK | T1059 Command and Scripting Interpreter, T1204.004 Malicious Copy and Paste |
| Indexes | `registry-*` |
| Needs | RECmd `RunMRU` plugin output (`NTUSER.DAT`) |
| Roles | end-user workstation, RDP/jump host, any server where admins log on interactively |

**What it finds.** Everything a user typed into Win+R, scored for encoded or download commands, shells with a URL or UNC path, and admin consoles. "Paste this into Run to fix your PC" lures (ClickFix / fake CAPTCHA) show up here as long `powershell`/`mshta` one-liners.

**Reading the output.** `registry.plugin.opened_on` is only known for the most recent entry (the key's last write); the others have only their `mru_position` order (0 = most recent). `user.name` is the hive owner.
