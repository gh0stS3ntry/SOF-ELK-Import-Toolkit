# C2-08 Unique URLs visited

| | |
|---|---|
| Tactic | TA0011 Command and Control |
| ATT&CK | T1071.001 Web Protocols, T1102 Web Service |
| Indexes | `browsinghistory-*` |
| Needs | NirSoft BrowsingHistoryView output |
| Roles | all where browsing history was collected |

**What it finds.** One row per URL across all loaded hosts: how many hosts and users visited it, first and last visit, visit and typed counts, browsers, domain and page titles. Newest first.

**Reading the output.** Use it as a lookup after another query gives a time or domain: add `| WHERE url.domain == "<domain>"` or a `first_visit` range. `typed_count_sum > 0` means someone typed the URL (or picked it from the address bar), which an attacker on an RDP session often does for tool downloads. The earlier engagement's query on the template field names; scored URL indicators are in [IA-02](../../TA0001-initial-access/IA-02-suspicious-urls/).
