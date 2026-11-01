# LEXF-02 File-sharing, paste, cloud-storage and request-capture sites in browser history and command lines

| | |
|---|---|
| Tactic | TA0010 Exfiltration |
| ATT&CK | T1567.002 Exfiltration to Cloud Storage, T1567.003 Exfiltration to Text Storage Sites, T1102 Web Service |
| Indexes | `browsinghistory-*`, `logstash-*`, `auditd-*`, `linuxconfig-*` |
| Needs | browsinghistory-*, or command lines in logstash-*, auditd-*, linuxconfig-* |
| Applies to | workstations and jump hosts; servers for command-line use |

**What it finds.** Visits, downloads and command lines involving file-sharing and cloud-storage services (MEGA, Dropbox, Google Drive, OneDrive, WeTransfer, Gofile, file.io, `transfer.sh`, catbox, pixeldrain, ...), paste sites (Pastebin, paste.ee, rentry, termbin), request-capture services (`webhook.site`, RequestBin, Pipedream) and tunnelling services (ngrok, Cloudflare quick tunnels), per domain: browser visits and downloads, upload and share pages, and command lines from sudo, cron, audit records, cron entries, units and startup files.

**Reading the output.** Command-line use (+3) is rarely innocent on a server: `curl` to `transfer.sh`, `webhook.site` or a paste site is exfiltration or a callback. In a browser, upload and share pages (`upload_pages`) around the incident window matter more than plain visits; take `first_seen` to [LCO-01](../../TA0009-collection/LCO-01-archives-dumps-and-staging/) for the files staged before. Personal cloud storage on workstations is common, so the user and timing decide.

**If it errors or looks empty.** `Unknown column [url.domain]` cannot happen while `linuxconfig-*` exists (repository URLs map it); without it and without browser history, replace `url.original` and `url.domain` with `null`.

**Next.** [LEXF-01](../LEXF-01-exfiltration-tools-and-commands/) for upload commands, [LIA-03](../../TA0001-initial-access/LIA-03-suspicious-urls-visited-and-fetched/) for other suspicious URLs.
