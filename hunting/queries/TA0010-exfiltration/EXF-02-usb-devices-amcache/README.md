# EXF-02 Plug and Play devices recorded in Amcache

| | |
|---|---|
| Tactic | TA0010 Exfiltration |
| ATT&CK | T1052.001 Exfiltration over USB, T1200 Hardware Additions |
| Indexes | `amcache-*` |
| Needs | AmcacheParser `DevicePnps` output (`event.dataset: amcache.device_pnps`) |
| Roles | end-user workstation |

**What it finds.** USB storage, phones and cameras (MTP/WPD), USB keyboards and HID devices, and volumes from Amcache's `InventoryDevicePnp`, one row per device instance with its descriptions, manufacturer, first and last key write, and a BadUSB flag. This survives when the SYSTEM hive's USB keys were cleaned up.

**Reading the output.** `amcache.key_last_write` is when Windows inventoried the device, usually its first connection. Compare with [EXF-01](../EXF-01-usb-devices-registry/). A new USB keyboard (HID) shortly before suspicious commands can be a keystroke-injection device.
