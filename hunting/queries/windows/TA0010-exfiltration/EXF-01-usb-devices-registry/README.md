# EXF-01 USB and removable storage devices in the SYSTEM hive, scored

| | |
|---|---|
| Tactic | TA0010 Exfiltration |
| ATT&CK | T1052.001 Exfiltration over USB, T1091 Replication Through Removable Media, T1200 Hardware Additions |
| Indexes | `registry-*` |
| Needs | RECmd batch output with `Enum\USBSTOR` / `Enum\USB` / `Enum\SCSI`, or the RECmd `USB`, `USBSTOR` and `SCSI` plugins (RD01 has `SCSI` only) |
| Roles | end-user workstation; servers where console access is in scope |

**What it finds.** Every USB device, USB mass-storage device and SCSI/UASP disk, one row per serial, vendor, product and VID, with first and last time seen, device names, on how many loaded hosts it appears, and flags for BadUSB / development boards (Rubber Ducky, Teensy, Digispark, Arduino, Flipper...), serials Windows generated because the device had none, encrypted-drive brands and generic vendor strings. Newest first.

**Reading the output.** `first_seen` uses the plugin's `FirstInstalled` when present, else the key write. `last_seen` is `LastConnected` (plugin) or the key write. Put the serial into [CO-05](../../TA0009-collection/CO-05-jumplist-files-opened/) and the `lnkfiles-*` index (`volume.serial_number` is the volume serial, a different number: match by drive letter and time instead) to see the files opened from it. Ported from the earlier engagement's query, with plugin fields and the SCSI key added and the "seen in the last 30 days" flag removed (it depended on the analysis date).

**If it errors.** `Unknown column` on a `registry.plugin.*` field means no USB/SCSI plugin output was loaded; replace that field with `null`.
