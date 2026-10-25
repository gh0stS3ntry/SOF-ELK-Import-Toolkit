# EXF-05 Visits to file-sharing, paste and personal cloud storage sites

| | |
|---|---|
| Tactic | TA0010 Exfiltration |
| ATT&CK | T1567.002 Exfiltration to Cloud Storage, T1567 Exfiltration Over Web Service |
| Indexes | `browsinghistory-*` |
| Needs | NirSoft BrowsingHistoryView output |
| Roles | end-user workstation, RDP/jump host, any server where someone browsed |

**What it finds.** Per host, user and site: visits to MEGA, WeTransfer, anonymous file drops (transfer.sh, file.io, gofile, catbox...), paste sites, personal cloud storage (Dropbox, Google Drive, OneDrive personal, Box, MediaFire...) and tunnel endpoints, with upload-looking URLs counted, the time range, page titles and sample URLs.

**Reading the output.** Any browsing on a server is unusual; browsing to MEGA from a server during the incident window is a strong lead. Personal cloud use on workstations is common, so judge by user and time. The full list of URLs is in [C2-08](../../TA0011-command-and-control/C2-08-unique-urls/).
