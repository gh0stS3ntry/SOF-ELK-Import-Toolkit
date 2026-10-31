# C2-09 Browsing history of named accounts (pivot)

| | |
|---|---|
| Tactic | TA0011 Command and Control |
| ATT&CK | T1071.001 Web Protocols, T1105 Ingress Tool Transfer |
| Indexes | `browsinghistory-*` |
| Needs | NirSoft BrowsingHistoryView output |
| Roles | all (pivot, not first cut) |

**What it finds.** Every page visited by the accounts you name, in time order, matched on `user.name` and on the profile path in the history file (BrowsingHistoryView sometimes attributes history to the account that ran it).

**How to use it.** Replace `kaspersky` and `guest` (the accounts abused in the earlier engagement) everywhere they appear in the query (four places). `visit_time_local` is the time as exported, before conversion to UTC, which helps when comparing with a user's statement.
