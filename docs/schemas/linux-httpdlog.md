# Linux web server log schema (`httpdlog-*`)

Loaded by `Linux/httpd2sofelk.py` into `httpdlog-<hostname>`. Mapping: `Linux/index_templates/component-toolkit-linux-common.json` plus `Linux/index_templates/index-httpdlog.json`, applied when the importer creates the index. No index template is installed, because `httpdlog-*` is SOF-ELK's own family (its Logstash pipeline writes `httpdlog-YYYY.MM`). The index uses `dynamic: false`, so a field not listed here is not searchable.

Field names follow SOF-ELK's httpd parsing (`6100-httpd.conf`, `8004-postprocess-httpd.conf`) and the types match `AWS/index_templates/index-httpdlog.json`, so one `FROM httpdlog-*` query covers ALB/ELB logs from `alb2sofelk.py` and Apache/nginx logs from Linux hosts. Use `event.dataset` or `_index` to tell them apart.

The common fields (`@timestamp`, `case`, `host.name`, `host.id`, `host.os.*`, `log.file.path`, `log.offset`, `event.*`) are described in [linux-logstash.md](linux-logstash.md#common-fields-every-linux-index).

## Files read

| Distro | Folder | Files |
|---|---|---|
| Debian, Ubuntu, Kali, SUSE | `/var/log/apache2/` | `access.log`, `error.log`, `other_vhosts_access.log`, `ssl_access.log`, any other `*access*`, `*request*` or `*error*` file |
| RHEL family | `/var/log/httpd/` | `access_log`, `error_log`, `ssl_access_log`, `ssl_request_log`, `ssl_error_log` |
| any | `/var/log/nginx/`, `/var/log/lighttpd/` | `access.log`, `error.log` |

Rotated copies (`.1`, `.2.gz`, `-20261025`, `.xz`, `.bz2`) are included, one subfolder deep as well. `--web-log /path/on/host` adds a log kept elsewhere (custom vhost paths); its server is taken from the path, else `web`.

## Line formats and time zones

| Format | Example | `event.dataset` | Time |
|---|---|---|---|
| NCSA common / combined (Apache, nginx `combined`) | `1.2.3.4 - bob [30/Oct/2026:22:16:40 +0800] "GET /a.php?x=1 HTTP/1.1" 200 37 "-" "curl/8.4"` | `<server>.access` | offset in the line |
| vhost_combined (`other_vhosts_access.log`) | `shop.example.com:443 1.2.3.4 - - [...] "GET / HTTP/2.0" 200 1500 ...` | `<server>.access` | offset in the line |
| mod_ssl `ssl_request_log` | `[30/Oct/2026:12:00:00 -0400] 10.0.0.9 TLSv1.3 TLS_AES_256_GCM_SHA384 "GET /login HTTP/1.1" 3120` | `apache.access` | offset in the line |
| Apache 2.4 / 2.2 error log | `[Fri Oct 30 22:16:40.123456 2026] [php:error] [pid 4242:tid 4242] [client 1.2.3.4:51234] AH00035: ...` | `apache.error` | host local time |
| nginx error log | `2026/10/30 23:00:00 [error] 812#812: *15 open() ... failed, client: 1.2.3.4, server: x, request: "GET / HTTP/1.1", host: "x"` | `nginx.error` | host local time |
| lighttpd error log | `2026-10-30 23:10:00: (server.c.1513) server started` | `lighttpd.error` | host local time |
| anything else with an `[dd/Mon/yyyy:HH:MM:SS +zzzz]` date | | `<server>.access`, tag `partial_httpd_log`, raw line in `message` | offset in the line |

`<server>` is `apache` (folders `apache2/`, `httpd/`), `nginx`, `lighttpd`, or `web` for `--web-log` files elsewhere. Local times use the evidence's own `/etc/localtime` (or `--local-tz`); the zone is stored in `event.timezone`. Lines matching none of these are counted under "Not loaded".

## Fields

| Field | Type | Content |
|---|---|---|
| `source.ip` / `source.address` / `source.port` | ip / keyword / integer | client (`source.address` when it is a host name) |
| `client.user.name` | keyword | identd name (`%l`), as SOF-ELK maps it. lighttpd writes the requested host there instead, which goes to `url.domain` |
| `server.user.name` | keyword | authenticated user (`%u`), as SOF-ELK maps it |
| `http.request.method`, `http.version` | keyword | from the request line |
| `url.original` | keyword (+ `.text`) | the request target exactly as logged (`/a.php?x=1`, or the full URL for proxy requests) |
| `url.path`, `url.query` | keyword (+ `.text`) | split from the target. `CONNECT` gets `url.path` "(Tunnel setup request)", as in SOF-ELK |
| `url.scheme`, `url.domain`, `destination.port` | keyword / keyword / integer | from an absolute URL, the vhost prefix, nginx's `host:` or a `CONNECT` target |
| `url.extension` | keyword | extension of the last path segment, lower case |
| `http.response.status_code` | short | |
| `destination.bytes` | long | response size (`-` becomes 0, as in SOF-ELK) |
| `http.request.referrer`, `user_agent.original` | keyword | `-` is left out |
| `tags` | keyword | `page` or `not_page` (static resources: css, js, images, fonts; SOF-ELK's list), `partial_httpd_log` |
| `sof-elk.rawrequest` | keyword | a request line that is not `METHOD target HTTP/x` (TLS handshakes on port 80, scanners) |
| `tls.protocol`, `tls.cipher` | keyword | `ssl_request_log` |
| `httpd.extra` | keyword | anything logged after the user agent (custom `LogFormat` fields) |
| `event.outcome` | keyword | `failure` for status 400 and above, else `success` (access logs) |
| `log.level` | keyword | error logs |
| `apache.error.module` | keyword | Apache module (`core`, `php`, `ssl`, ...); lighttpd source location |
| `process.pid`, `process.thread.id` | long | error logs |
| `error.code` | keyword | Apache `AHnnnnn` |
| `error.message` | keyword (+ `.text`) | error text, with nginx's `, client: ..., request: ...` context and Apache's `, referer: ...` split off into fields |
| `httpd.connection_id`, `httpd.server_name`, `httpd.upstream` | long / keyword / keyword | nginx error context |
| `message` | keyword (+ `.text`) | raw line, only for `partial_httpd_log` documents |
| `labels.type` | keyword | `httpdlog` |

`_id` is a hash of the host, the log path without its rotation suffix, the line, and its occurrence number, so `access.log` loaded today and the same lines as `access.log.1` in a later collection overwrite instead of duplicating, while two identical requests in one file stay two documents.

## Example ES|QL

```esql
FROM httpdlog-* METADATA _index
| WHERE event.dataset LIKE "*.access" AND url.extension IN ("php", "jsp", "aspx", "cgi") AND http.request.method == "POST"
| STATS requests = COUNT(*), clients = COUNT_DISTINCT(source.ip), first = MIN(@timestamp), last = MAX(@timestamp) BY _index, url.path
| WHERE clients <= 2
| SORT requests DESC
```

```esql
FROM httpdlog-* METADATA _index
| WHERE event.dataset IN ("apache.error", "nginx.error") AND log.level IN ("error", "crit", "alert", "emerg")
| KEEP @timestamp, _index, event.dataset, log.level, apache.error.module, error.code, source.ip, url.path, error.message
| SORT @timestamp
```
