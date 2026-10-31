# Checklist: End-user workstation

Laptops, desktops and VDI, and RDP/jump hosts that people use interactively. Run the [baseline](00-baseline-all-windows-hosts.md) first. Workstations usually lack 4688 and Sysmon but have the richest user-activity artifacts (browser history, jump lists, shellbags, UserAssist, MRUs), so most rows here work without event logs. A workstation is usually where the incident starts (phishing, a drive-by download, a stolen VPN or RDP session), so the aim is to find patient zero and the first attacker action.

## 1. Host profile

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 1.1 | Primary user(s) of the device and their normal working hours | | 1.2.3, 1.3.5 | Ask the client. Activity from another profile or outside these hours stands out. |
| 1.2 | Whether the device is a laptop that leaves the network (VPN, home Wi-Fi) | | 1.2.2 | Decides whether public-IP logons and cloud-sync traffic are normal. |
| 1.3 | Profiles on the device | [TRI-01](../queries/windows/00-triage/TRI-01-data-coverage/) | 2.3.5 | User names in `user.name` across registry, jump list and browser indexes; profiles created during the incident. |

## 2. How did it start?

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 2.1 | Files downloaded from the internet | [C2-02](../queries/windows/TA0011-command-and-control/C2-02-motw-zone-identifier/), [C2-03](../queries/windows/TA0011-command-and-control/C2-03-browser-downloads/), [C2-04](../queries/windows/TA0011-command-and-control/C2-04-opensave-mru-files/) | 2.1.7 | Executables, scripts, ISO/IMG/VHD and archives downloaded shortly before the first detection or suspicious execution. |
| 2.2 | Suspicious URLs and unique URLs | [IA-02](../queries/windows/TA0001-initial-access/IA-02-suspicious-urls/), [C2-08](../queries/windows/TA0011-command-and-control/C2-08-unique-urls/) | 2.1.7 | Phishing landing pages, file-sharing links, IP-literal URLs, newly registered or look-alike domains. |
| 2.3 | Attachments, archives, mounted images and removable media opened | [IA-03](../queries/windows/TA0001-initial-access/IA-03-lnk-email-archive-removable/) | 2.1.5 | Files opened from Outlook's temporary folder, from inside an archive, from a mounted ISO or a USB drive. |
| 2.4 | Programs the user started | [EX-16](../queries/windows/TA0002-execution/EX-16-userassist-bam/), [EX-17](../queries/windows/TA0002-execution/EX-17-runmru-commands/), [EX-13](../queries/windows/TA0002-execution/EX-13-prefetch-rare-executables/) | 2.1.1 | UserAssist/BAM entries and Run-dialog commands (`powershell -enc`, `mshta http...`, the "fake CAPTCHA" paste) around the download time. |
| 2.5 | Macro and script execution | [EX-08](../queries/windows/TA0002-execution/EX-08-scripting-interpreters/), [EX-07](../queries/windows/TA0002-execution/EX-07-powershell-script-blocks/) | 2.4.12 | `wscript`/`mshta`/PowerShell launched from Office or a browser. |
| 2.6 | Logons from outside (VPN, RDP exposed) | [IA-01](../queries/windows/TA0001-initial-access/IA-01-logons-from-public-ip/), [CA-06](../queries/windows/TA0006-credential-access/CA-06-brute-force-then-success/) | 2.4.4 | RDP from public addresses; a VPN address pool logging on with an account that is not the device's user. |

## 3. What did the user (or attacker) touch?

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 3.1 | Documents opened | [CO-06](../queries/windows/TA0009-collection/CO-06-office-mru-and-recent-docs/), [CO-05](../queries/windows/TA0009-collection/CO-05-jumplist-files-opened/) | 2.1.5 | Sensitive documents opened during the incident window, files opened from shares or USB. |
| 3.2 | Folders browsed | [CO-04](../queries/windows/TA0009-collection/CO-04-shellbags-network-removable-and-other-profiles/) | 2.1.5 | Network shares, other users' profiles, removable drives, `\Windows\Temp` and tool folders. |
| 3.3 | USB and removable devices | [EXF-01](../queries/windows/TA0010-exfiltration/EXF-01-usb-devices-registry/), [EXF-02](../queries/windows/TA0010-exfiltration/EXF-02-usb-devices-amcache/) | 2.3.10 | Mass-storage devices first connected during the incident window, especially for insider cases. |
| 3.4 | Cloud and file-sharing sites, upload tools | [EXF-05](../queries/windows/TA0010-exfiltration/EXF-05-file-sharing-site-visits/), [EXF-04](../queries/windows/TA0010-exfiltration/EXF-04-exfil-and-cloud-sync-tools/), [EXF-03](../queries/windows/TA0010-exfiltration/EXF-03-srum-network-usage/) | 2.1.7 | Personal cloud storage, paste sites, large upload volumes per app in SRUM. |
| 3.5 | Recycle Bin | [DE-08](../queries/windows/TA0112-defense-impairment/DE-08-recycle-bin-deletions/) | 2.1.6 | Tools, archives and documents deleted by the user after the activity. |
| 3.6 | Browsing for named accounts (pivot) | [C2-09](../queries/windows/TA0011-command-and-control/C2-09-browsing-pivot-named-accounts/) | 2.1.7 | All pages visited by an account the attacker used, in time order. |

## 4. Persistence specific to user sessions

| # | Check | Queries | IR ref | What to look for |
|---|---|---|---|---|
| 4.1 | Per-user Run keys and Startup folder | [PE-01](../queries/windows/TA0003-persistence/PE-01-asep-registry-scoring/), [PE-12](../queries/windows/TA0003-persistence/PE-12-startup-folder/) | 2.1.2 | HKCU Run entries and Startup shortcuts pointing at `AppData`, `Temp` or `Downloads`. |
| 4.2 | Remote-access tools | [C2-05](../queries/windows/TA0011-command-and-control/C2-05-remote-access-and-tunnel-tools/) | 2.1.3 | AnyDesk/ScreenConnect/TeamViewer installed by the user after a "support" call. |

## Not covered by these queries

- Email: the message and the sender (mail gateway or Microsoft 365 message trace).
- Browser cache, cookies, session-restore and search-term files beyond what BrowsingHistoryView exports (IR 2.1.7).
- The contents of downloaded files: hash them from the image and check threat intel.
