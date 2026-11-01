# C2-02 Files downloaded from the internet: Zone.Identifier streams (Mark of the Web)

| | |
|---|---|
| Tactic | TA0011 Command and Control |
| ATT&CK | T1105 Ingress Tool Transfer, T1566.002 Spearphishing Link, T1204 User Execution |
| Indexes | `filesystem-*` |
| Needs | MFTECmd `$MFT` output; the stream contents (`file.fork_contents`) are only kept for resident `Zone.Identifier` streams, which is almost all of them |
| Roles | all |

**What it finds.** Every file with a `Zone.Identifier` alternate data stream for zone 3 (Internet) or 4 (Restricted), with the download URL (`HostUrl`) and the referring page (`ReferrerUrl`) when the browser or mail client recorded them, the file's `$SI`/`$FN` creation times and size.

**Reading the output.** `file.filename.created` of the stream is the download time. `host_url` is the strongest pivot for an initial-access download; look it up in [C2-03](../C2-03-browser-downloads/) and [IA-02](../../TA0001-initial-access/IA-02-suspicious-urls/). Files extracted from a downloaded archive with 7-Zip or older tools lose MOTW, so the archive may be the only file here. The earlier engagement's query, extended to zone 4.
