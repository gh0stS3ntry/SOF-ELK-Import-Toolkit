# LEXF-03 Clients that pulled the most data from the host's web and FTP servers

| | |
|---|---|
| Tactic | TA0010 Exfiltration |
| ATT&CK | T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol, T1041 Exfiltration Over C2 Channel |
| Indexes | `httpdlog-*`, `logstash-*` |
| Needs | httpdlog-* (web) or FTP logs in logstash-* |
| Applies to | Linux web and FTP servers |

**What it finds.** For each client of the host's Apache, nginx or lighttpd server and of its FTP server (vsftpd, ProFTPD and pure-ftpd transfer logs): how many requests it made, how much data it received from the host and sent to it, the largest single response, and how many of its requests fetched archives, dumps, databases or documents.

**Reading the output.** A client that downloaded an archive or dump (`archive_hits`, `sample_archives`), above all one staged in the web root ([LCO-01](../../TA0009-collection/LCO-01-archives-dumps-and-staging/)), is the clearest sign of data taken through the server. Large totals from search engines, monitoring or backup servers are normal; a public address that also appears in [LIA-02](../../TA0001-initial-access/LIA-02-web-exploitation-on-linux-web-servers/) or [LPE-07](../../TA0003-persistence/LPE-07-web-shells-files-and-requests/) is not. Web response sizes are as logged (`%b`), so compressed responses count their compressed size.

**If it errors or looks empty.** `Unknown column [destination.bytes]`: no web logs were loaded (`httpdlog-*`); remove `httpdlog-*` and replace `destination.bytes` and `url.path` with `null` to keep only FTP. No FTP rows: no FTP transfer logs were collected.

**Next.** [LPE-07](../../TA0003-persistence/LPE-07-web-shells-files-and-requests/) for web shells used to pull data, [LIA-02](../../TA0001-initial-access/LIA-02-web-exploitation-on-linux-web-servers/) for the same clients' exploitation attempts.
