# C2-07 Network connections by process (Sysmon 3), scored

| | |
|---|---|
| Tactic | TA0011 Command and Control |
| ATT&CK | T1071 Application Layer Protocol, T1571 Non-Standard Port, T1219 Remote Access Software |
| Indexes | `evtxlogs-*` |
| Needs | Sysmon event 3 (network connection; often limited by the Sysmon config) |
| Roles | all with Sysmon |

**What it finds.** Per host and process image: outbound connections, how many went to public addresses, distinct destinations, destination host names (Sysmon resolves them when it can), ports, users and the time range. LOLBins talking to the internet, images in user-writable folders, tunnel/paste/chat destinations, images on one host only and non-service processes using lateral-movement ports (445, 135, 5985/5986, 3389, 22) score higher.

**Reading the output.** `rundll32.exe` or `dllhost.exe` with a handful of public destinations is a common Cobalt Strike/Sliver beacon host; `powershell.exe` to 445 on many internal hosts is lateral movement or scanning.

**If it errors.** `Unknown column` on a Sysmon field means no Sysmon 3 events were loaded.
