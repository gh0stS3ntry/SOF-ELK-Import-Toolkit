# WPE-01 Malicious uploads: executable, double-extension and active-content files requested from upload folders, and whether the requesting client used an upload endpoint first

| | |
|---|---|
| Tactic | TA0003 Persistence |
| ATT&CK | T1505.003 Web Shell, T1608.002 Upload Tool |
| OWASP WSTG | WSTG-BUSL-08 Upload of Unexpected File Types, WSTG-BUSL-09 Upload of Malicious Files, WSTG-INJT-11.1 File Inclusion |
| Indexes | `httpdlog-*` |
| Needs | web access logs in `httpdlog-*`: ALB/ELB (`alb2sofelk.py`), CloudFront (`cloudfrontaccess2sofelk.py`), Apache/nginx/lighttpd (`httpd2sofelk.py`) |
| Applies to | web applications that accept uploads (CMSs, ticketing, HR and document portals) |

**What it finds.** Requests for files in upload-type folders (`/uploads/`, `/files/`, `/attachments/`, `/avatars/`, `/media/`, `wp-content/uploads`, ...) whose name is a server-side script (`.php`, `.phtml`, `.phar`, `.jsp`, `.aspx`, `.ashx`, `.cer`, `.cgi`, ...), a double extension or filter-bypass suffix (`shell.php.jpg`, `shell.asp;.jpg`, `%00`, `::$DATA`), or active content (`.svg`, `.html`, `.xml` in user-upload folders such as `/uploads/` and `/attachments/`, and `.htaccess` or `.user.ini` anywhere in those folders). For each file: whether any client that requested it had POSTed or PUT to an upload route, and when. Scored: script +3, double extension +3, active content +1, any 2xx +2, requested by an uploading client +2, POSTed to +1, at most two clients +1.

**Reading the output.** The pattern to find is one client uploading through the application and then requesting the uploaded `.php` or `.jsp` from the upload folder, mostly by POST: a web shell. `earliest_upload_by_these_clients` dates the upload. A `.htaccess` or `.user.ini` request after an upload is the step that makes a harmless extension executable. An `.svg` or `.html` served from an upload folder is stored XSS rather than code execution. Unlike [APE-03](../../../aws/TA0003-persistence/APE-03-web-shell-requests/), this check does not need the file to be rarely used, and it ties the file to the uploader.

**If it errors or looks empty.** `httpdlog-*` also matches SOF-ELK's own `httpdlog-YYYY.MM` indexes when web logs went through its Logstash pipeline; their strings are `text`, the toolkit's `keyword`. If ES|QL reports a type conflict, name the toolkit indexes instead (`FROM httpdlog-web01, httpdlog-123456789012`). No rows: no web logs were loaded, or nothing crossed the thresholds marked `// EDIT:`.

**Next.** [PE-17](../../../windows/TA0003-persistence/PE-17-web-shell-files/) or [LPE-07](../../../linux/TA0003-persistence/LPE-07-web-shells-files-and-requests/) for the file on disk, [WIA-02](../../TA0001-initial-access/WIA-02-http-method-abuse-and-verb-tampering/) for uploads made with PUT.
