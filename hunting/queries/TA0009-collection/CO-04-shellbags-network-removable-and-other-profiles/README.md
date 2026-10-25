# CO-04 Folders browsed on network shares, removable drives, other profiles and sensitive paths

| | |
|---|---|
| Tactic | TA0009 Collection |
| ATT&CK | T1039 Data from Network Shared Drive, T1025 Data from Removable Media, T1005 Data from Local System, T1083 File and Directory Discovery |
| Indexes | `shellbag-*` |
| Needs | SBECmd output for NTUSER.DAT and UsrClass.dat |
| Roles | end-user workstation, RDP/jump host, file server (for admins browsing locally) |

**What it finds.** Folders a user opened in Explorer that were on a UNC path, a removable or portable device, inside another user's profile, under sensitive-sounding names (finance, HR, legal, backup, passwords, VPN, SQL...), or in credential stores. ShellBags survive deletion of the folders themselves, so they show what an intruder using a GUI session (RDP) browsed.

**Reading the output.** `last_interacted` is the last time the folder was opened (not always set; `shellbag.last_write` is the registry key time as fallback). `user.name` is the profile whose hive held the bag, which for an RDP intruder is the account they used. Edit the keyword list in the `sensitive-sounding folder` branch to the client's naming.
