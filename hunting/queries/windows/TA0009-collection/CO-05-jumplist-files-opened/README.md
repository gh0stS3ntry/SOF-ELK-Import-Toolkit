# CO-05 Files and folders opened, per application (jump lists)

| | |
|---|---|
| Tactic | TA0009 Collection |
| ATT&CK | T1005 Data from Local System, T1039 Data from Network Shared Drive, T1025 Data from Removable Media |
| Indexes | `jumplist-*` |
| Needs | JLECmd output (AutomaticDestinations and CustomDestinations) |
| Roles | end-user workstation, RDP/jump host |

**What it finds.** Every file or folder a user opened through an application with a jump list (Office, Explorer, Notepad, 7-Zip, WinSCP, Remote Desktop...), scored for network paths, removable drives, a different source machine in the tracker block, archives, sensitive-sounding names and admin/transfer tools as the opening application.

**Reading the output.** `opened` is the jump list entry's last modification, close to the last time the file was opened. `jumplist.volume_serial_number` and `volume_label` tie a removable-drive file to a USB device ([EXF-01](../../TA0010-exfiltration/EXF-01-usb-devices-registry/)). `Remote Desktop` entries list hosts this user connected to (`jumplist.arguments` holds `/v:host`).
