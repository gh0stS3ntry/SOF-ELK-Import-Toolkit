# C2-03 Files downloaded through the browser

| | |
|---|---|
| Tactic | TA0011 Command and Control |
| ATT&CK | T1105 Ingress Tool Transfer, T1204.002 Malicious File, T1189 Drive-by Compromise |
| Indexes | `browsinghistory-*` |
| Needs | NirSoft BrowsingHistoryView output |
| Roles | end-user workstation; any server where someone browsed |

**What it finds.** History entries that point at a downloadable file type, have a download visit type, are local `file:` paths in a Downloads folder, or are the browser's own downloads page. `f_exec` marks executables, scripts and disk images.

**Reading the output.** In time order. A download URL here plus a Zone.Identifier with the same `HostUrl` ([C2-02](../C2-02-motw-zone-identifier/)) gives the file name on disk; then check execution in [EX-15](../../TA0002-execution/EX-15-execution-evidence-pivot/). The earlier engagement's query, ported to the `browsinghistory.*` field names.
