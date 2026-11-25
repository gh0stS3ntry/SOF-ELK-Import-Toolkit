# Web access logs (NCSA Common / Combined)

`ncsa2sofelk.py` loads web server access logs written in **NCSA Common Log Format (CLF)** or
**NCSA Combined Log Format** into SOF-ELK, one index per web server: `httpdlog-<hostname>`.
It sits next to the other `httpdlog-*` importers, so the
[web access log checklist](../hunting/checklists/web-access-logs.md) (W* queries) and any
`FROM httpdlog-* METADATA _index` hunt cover these logs too.

| Importer | Reads | Index |
|---|---|---|
| `Web/ncsa2sofelk.py` | NCSA Common/Combined files or folders, from any server | `httpdlog-<hostname>` |
| `Linux/httpd2sofelk.py` | Apache/nginx/lighttpd access **and error** logs inside a UAC collection or collected root filesystem | `httpdlog-<hostname>` |
| `Windows/csv_importers/iisgeolocate2sofelk.py` | IIS W3C `u_ex*.log` and iisGeolocate CSVs | `httpdlog-<hostname>` |
| `AWS/alb2sofelk.py`, `AWS/cloudfrontaccess2sofelk.py` | ALB/ELB and CloudFront access logs | `httpdlog-<source>` |

Use `ncsa2sofelk.py` for access logs that are not in a Linux collection: Apache or nginx on
Windows (`C:\Apache24\logs`, XAMPP, WampServer), Tomcat `localhost_access_log.<date>.txt`
(AccessLogValve `common`/`combined` patterns), IIS logs in IIS's NCSA format (`nc<yymmdd>.log`),
varnishncsa/HAProxy/Squid logs in CLF, or logs handed over by a hosting provider.

## Formats

| `httpd.log_format` | Line |
|---|---|
| `common` | `host ident authuser [dd/Mon/yyyy:HH:MM:SS +zzzz] "request" status bytes` |
| `combined` | common + `"referrer" "user-agent"` |
| `vhost_common` | `vhost:port ` + common (Apache `vhost_common`) |
| `vhost_combined` | `vhost:port ` + combined (Apache `vhost_combined`, Debian `other_vhosts_access.log`) |
| `partial` | not one of the above, but has an access log date: loaded as SOF-ELK does, tagged `partial_httpd_log`, raw line in `message` |

Fields after the standard ones (Tomcat `%D`, `%T`, X-Forwarded-For, ...) are kept in
`httpd.extra`. Times carry their own UTC offset and are stored in UTC, so there is no time zone
option (`--local-tz` is accepted for the wrapper and ignored). Lines that fit nothing are counted
and reported, not loaded.

## Fields

The parser is `Linux/httpd2sofelk.py`'s, so the names are SOF-ELK's (6100-httpd.conf,
8004-postprocess-httpd.conf) and the types match every other `httpdlog-*` importer.

| NCSA field | Elasticsearch field |
|---|---|
| `%h` remote host | `source.ip` (or `source.address` for a host name) |
| `%l` identd | `client.user.name` (`url.domain` for lighttpd, whose default format puts the host there) |
| `%u` authuser | `server.user.name` |
| `%t` time | `@timestamp` (UTC) |
| `"%r"` request line | `http.request.method`, `url.original`, `url.path`, `url.query`, `url.extension`, `http.version`, tag `page` / `not_page`; an unparseable request goes to `sof-elk.rawrequest` |
| `%>s` status | `http.response.status_code`, `event.outcome` (`failure` from 400) |
| `%b` bytes | `destination.bytes` (`-` is 0) |
| `"%{Referer}i"` | `http.request.referrer` |
| `"%{User-agent}i"` | `user_agent.original` |
| `vhost:port` | `url.domain`, `destination.port` |

Every document also has `host.name`, `event.kind` `event`, `event.category` `web`, `event.type`
`access`, `event.dataset` `<server>.access`, `labels.type` `httpdlog`, `log.file.path` (path
under the folder given), `log.offset` (line number), and `case` / `host.os.type` when given.

`<server>` is guessed per file from its path: `tomcat` (`localhost_access_log*`, `tomcat`,
`catalina`), `iis` (`nc<yymmdd>.log`, `W3SVC*`, `inetpub`), `nginx`, `lighttpd`, `apache`
(`apache`, `httpd`, `xampp`, `wamp`, `access_log`), otherwise `web`. Force it with `--server`.
IIS-only input sets `host.os.type` `windows`; otherwise set it with `--host-os` if the checklist
runner should know the server's OS.

## Usage

```bash
python3 Web/ncsa2sofelk.py /cases/IR-42/web01/logs --hostname WEB01 --dry-run
python3 Web/ncsa2sofelk.py /cases/IR-42/web01/logs --hostname WEB01 --case IR-42
python3 Web/ncsa2sofelk.py /cases/IR-42/app01/tomcat/logs --hostname APP01 --server tomcat --host-os linux
```

Folders are searched recursively; `.gz`, `.bz2` and `.xz` files are read without unpacking.
Files that do not look like NCSA access logs (at least half of their first 20 lines must be
common/combined lines) are skipped and listed. Options: `--hostname` (required), `--case`,
`--server`, `--host-os`, `--es`, `--user`, `--password`, `--insecure`, `--batch-size`,
`--dry-run`, `--sample-docs`, and the shared retry/logging options (`--max-retries`,
`--retry-backoff`, `--timeout`, `--log-file`).

`SOF-ELK_ImportWrapper.py` finds these logs on its own (every file no other importer claimed is
checked with this importer's `detect()`) and runs this importer on them. Logs inside a UAC
collection stay with `Linux/linux2sofelk.py`.

## Index and IDs

No index template is installed for `httpdlog-*` (SOF-ELK's own family): the index is created
from `Linux/index_templates/index-httpdlog.json`, and an `httpdlog-<hostname>` index made by
another toolkit web importer is extended rather than replaced. Any other existing index is
refused.

The `_id` comes from the host, the dataset, the file name without its rotation suffix
(`access.log.2.gz` -> `access.log`), the line and its occurrence number, so re-running, giving
the folder differently, or loading a log again after rotation renamed it overwrites instead of
duplicating. Identical lines in one log stay separate documents.

Tests: `python3 tests/test_ncsa.py -v`.
