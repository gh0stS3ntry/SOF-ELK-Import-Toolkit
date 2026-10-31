# CO-06 Recently opened documents (OfficeMRU and RecentDocs)

| | |
|---|---|
| Tactic | TA0009 Collection |
| ATT&CK | T1005 Data from Local System, T1039 Data from Network Shared Drive, T1213 Data from Information Repositories |
| Indexes | `registry-*` |
| Needs | RECmd `OfficeMRU` and/or `RecentDocs` plugin CSVs (NTUSER.DAT) |
| Roles | end-user workstation, RDP/jump host |

**What it finds.** Documents opened in Office (with last opened and closed times) and files listed in Explorer's RecentDocs per user, flagged for network or SharePoint paths, archives and sensitive-sounding names.

**Reading the output.** `opened` is exact for Office MRU; for RecentDocs it is known only for the most recent entry of each extension (`extension_last_opened`) and otherwise empty, so use `mru_position` for order. A compromised account opening finance or HR documents it never touched before is collection.

**If it errors.** `Unknown column` on a `registry.plugin.*` field means that plugin was not loaded for any host; replace the field with `null`.
