# IA-02 Suspicious URLs in browsing history

| | |
|---|---|
| Tactic | TA0001 Initial Access |
| ATT&CK | T1566.002 Spearphishing Link, T1189 Drive-by Compromise, T1204.001 Malicious Link |
| Indexes | `browsinghistory-*` |
| Needs | NirSoft BrowsingHistoryView loaded with `--tz` |
| Roles | end-user workstation, jump host; servers where admins browse |

**What it finds.** Each visit is scored against 16 indicators: webhook/bot exfil endpoints, abusable URI schemes, offensive-tool keywords, IP-literal hosts, credentials in the URL, tunnels and dynamic DNS, paste and file-share hosting, executable or disk-image downloads, punycode, shorteners, high-abuse TLDs, odd ports, very long or encoded URLs, phishing-style paths and remote-access-tool sites.

**Reading the output.** Sort is by `score`; `reasons` explains it. A shortener or phishing path followed minutes later by an executable download or a remote-tool site is a typical delivery chain. `browsinghistory.visit_time` is UTC (converted with `--tz`); the text as exported is in `browsinghistory.visit_time_local`.

**Tuning.** Add the client's own domains to the `f_phish_kw` exclusion. Raise `WHERE score > 0` to `>= 2` on very large histories.

**Next.** [C2-03](../../TA0011-command-and-control/C2-03-browser-downloads/) for downloads and [C2-02](../../TA0011-command-and-control/C2-02-motw-zone-identifier/) for the matching Zone.Identifier streams.
