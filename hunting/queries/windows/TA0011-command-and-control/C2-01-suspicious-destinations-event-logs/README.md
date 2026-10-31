# C2-01 Suspicious destinations and beacon-style code in event logs

| | |
|---|---|
| Tactic | TA0011 Command and Control |
| ATT&CK | T1071.001 Web Protocols, T1102 Web Service, T1105 Ingress Tool Transfer, T1197 BITS Jobs, T1568.002 DGA, T1572 Protocol Tunneling |
| Indexes | `evtxlogs-*` |
| Needs | Defender Operational, PowerShell Operational 4103/4104 or Windows PowerShell 400/800; `Microsoft-Windows-Bits-Client/Operational` 3/59/60/61 and `Microsoft-Windows-DNS-Client/Operational` 3006/3008 when collected (DNS-Client is off by default) |
| Roles | all |

**What it finds.** Chat-API and webhook callbacks (Telegram, Discord, Slack, OAST), tunnels and dynamic DNS, IP-literal URLs, C2-framework URL paths, raw socket clients and endless sleep-and-request loops in scripts, BITS jobs to non-vendor URLs, Defender web-file and Network Protection events, DGA-like and very long DNS names, encoded download cradles, and paste/file-hosting/cloud-API hosts. `indicator` is the DNS name, BITS URL or the first URL found in the text.

**Reading the output.** The earlier engagement's query with three fixes: `winlog.user.identifier` (was misspelled `identifer`, which the importer fixed in PR #9), PowerShell 4104 `ScriptBlockText` added to the text, and the Google Update filter no longer drops rows that have no URL. A BITS job (59/60) to a raw IP or a tunnel host is a common persistence-and-download trick; the job name is in the same event.

**If it errors.** `Unknown column` on `QueryName` (DNS-Client), `url` (BITS) or `winlog.payload.event_data.string` means that source was not loaded; replace the field with `null` or `""`.
