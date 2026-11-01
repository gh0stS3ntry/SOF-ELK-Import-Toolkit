# LIA-03 Suspicious URLs visited in browsers or fetched by commands, cron jobs and repositories

| | |
|---|---|
| Tactic | TA0001 Initial Access |
| ATT&CK | T1566.002 Spearphishing Link, T1189 Drive-by Compromise, T1105 Ingress Tool Transfer |
| Indexes | `browsinghistory-*`, `logstash-*`, `auditd-*`, `linuxconfig-*` |
| Needs | browsinghistory-*, or command lines in logstash-*, auditd-*, linuxconfig-* |
| Applies to | workstations and jump hosts; servers for command-line fetches |

**What it finds.** URLs a user visited (Firefox and Chromium-family history and downloads) and URLs on command lines (sudo, cron and audit command lines, cron and systemd definitions, shell startup files, package repository definitions), scored for traits of delivery and staging: an IP address instead of a host name, a non-standard port, punycode, URL shorteners, paste and file-drop sites, tunnelling and dynamic-DNS services, and links straight to scripts, binaries or archives.

**Reading the output.** `u` is the first URL found in the text; `examples` shows where it came from. Score 3 or more on a browser row is a lead to follow with the download list ([LC2-03](../../TA0011-command-and-control/LC2-03-tool-and-payload-downloads/)) and the files in the user's `Downloads` folder; on a command line it is a payload fetch: look at what ran next in [LEX-01](../../TA0002-execution/LEX-01-commands-run-with-sudo-su-pkexec/) and [LEX-04](../../TA0002-execution/LEX-04-suspicious-command-lines/). Raw GitHub and paste links are common on admin and pentest machines; their target (a script name, a known tool) decides. Lab, VPN and internal addresses score on `f_ip_host` too.

**If it errors or looks empty.** `Unknown column [url.original]` cannot happen while `linuxconfig-*` exists (it maps the field for repository URLs); without it and without browser history, replace `url.original` with `null`. Firefox history keeps visits for months; Chromium deletes visits after 90 days.

**Next.** [LEXF-02](../../TA0010-exfiltration/LEXF-02-file-sharing-and-paste-sites/) for file-sharing sites, [LC2-03](../../TA0011-command-and-control/LC2-03-tool-and-payload-downloads/) for downloads.
