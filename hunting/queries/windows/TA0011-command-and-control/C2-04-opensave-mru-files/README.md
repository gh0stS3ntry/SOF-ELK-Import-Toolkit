# C2-04 Files chosen in Open/Save dialogs (OpenSaveMRU / OpenSavePidlMRU)

| | |
|---|---|
| Tactic | TA0011 Command and Control |
| ATT&CK | T1105 Ingress Tool Transfer, T1204.002 Malicious File |
| Indexes | `registry-*` |
| Needs | RECmd `OpenSavePidlMRU` plugin CSV (`event.dataset: registry.opensavepidlmru`) and/or a batch CSV that dumps `ComDlg32\OpenSaveMRU` / `OpenSavePidlMRU` |
| Roles | end-user workstation, RDP/jump host |

**What it finds.** Files a user picked in a standard Open or Save As dialog, by extension, including files saved from a browser ("Save as") and files uploaded through a browser's file picker (a common exfiltration trace). Flags downloads folders, executables/archives/images and network paths.

**Reading the output.** `opened` is exact only for the most recent entry per extension (MRU position 0, the key's last write); older entries have only their `mru_position`. `user.name` is the hive owner. The earlier engagement's query, ported to the template field names; its `ValueData2 NOT LIKE "Opened*"` filter also dropped every row without a `ValueData2`, which the `COALESCE` here avoids.
