# LPE-07 Web shells: script files in web roots and the requests that reached them, joined by file name

| | |
|---|---|
| Tactic | TA0003 Persistence |
| ATT&CK | T1505.003 Web Shell |
| Indexes | `bodyfile-*`, `httpdlog-*`, `auditd-*` |
| Needs | bodyfile-* and httpdlog-* |
| Applies to | Linux web servers |

**What it finds.** Server-side script files (`.php`, `.phtml`, `.jsp`, `.cgi`, `.pl`, `.py`, `.sh`, ...) in web roots (`/var/www`, `/srv`, `/usr/share/nginx`, `public_html`, Tomcat `webapps`, `cgi-bin`) from the bodyfile and audited writes, joined by file name with the access-log requests for scripts of the same name. A script that is new, small, oddly named, reached by very few clients, or receiving POSTs scores higher; so does a script that answered 200 but is no longer on disk.

**Reading the output.** A web shell is usually a small script, created recently (`file_created`, or `file_ctime` where the filesystem has no birth time), owned by the web server account (`www-data`, `apache`, `nginx`), requested by one or two addresses, mostly with POST. Check `queries` for commands passed in the URL. Then take `client_ips` and `first_request` into [LIA-02](../../TA0001-initial-access/LIA-02-web-exploitation-on-linux-web-servers/) for how it got there and [LEX-02](../../TA0002-execution/LEX-02-programs-in-temp-hidden-and-user-writable-locations/) for what the web server account ran. The join is by file name only, so two `index.php` files in different applications share a row; `files` and `paths` show them. Set `since` first.

**If it errors or looks empty.** `Unknown column [url.extension]` or `[http.request.method]`: no web logs were loaded (`httpdlog-*`); remove `httpdlog-*` and replace the `url.*` and `http.*` fields with `null` to look at the files only. `Unknown column [file.created]`: no `bodyfile-*` index exists.

**Next.** [LIA-02](../../TA0001-initial-access/LIA-02-web-exploitation-on-linux-web-servers/) for the exploitation, [LEXF-03](../../TA0010-exfiltration/LEXF-03-large-transfers-served-by-web-and-ftp/) for data pulled through the web server.
