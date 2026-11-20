# LM-02 netsh portproxy rules, RDP enablement and remote-admin settings

| | |
|---|---|
| Tactic | TA0008 Lateral Movement |
| ATT&CK | T1090.001 Internal Proxy, T1021.001 Remote Desktop Protocol, T1112 Modify Registry, T1548.002 Bypass UAC |
| Indexes | `registry-*` |
| Needs | RECmd batch CSV that dumps `Services\PortProxy`, `Control\Terminal Server` (and `WinStations\RDP-Tcp`), `Policies\System` and the user `Terminal Server Client` and `Explorer\MountPoints2` keys |
| Roles | all; jump hosts and internet-facing servers especially |

**What it finds.** `netsh interface portproxy` rules (listen address/port to connect address/port; a rule forwarding to 3389 or 445 on another internal host is a pivot), RDP turned on, NLA turned off, RDP on a non-default port, multiple sessions per user allowed, `LocalAccountTokenFilterPolicy = 1` (lets local admin accounts use admin shares and PsExec remotely), the per-user list of servers this host connected to with RDP, and the network shares each user mapped (`MountPoints2` keys named `##server#share`, shown as `mapped_share`). A mapped admin share (`C$`, `ADMIN$`) scores 3 more: the SANS Hunt Evil poster lists it as the source-side trace of `net use z: \\host\c$`.

**Reading the output.** `registry.last_write` dates the change. For outbound RDP history, the RECmd `TerminalServerClient` plugin (`event.dataset: registry.terminalserverclient`) adds `registry.plugin.host_name`, `username` and `mru_position`.
