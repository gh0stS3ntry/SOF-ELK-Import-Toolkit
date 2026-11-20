# IIS access log schema (`httpdlog-*`, `event.dataset` `iis.access`)

Loaded by `Windows/csv_importers/iisgeolocate2sofelk.py` into `httpdlog-<hostname>`. Mapping: `Windows/index_templates/component-toolkit-common.json` plus `Windows/index_templates/index-httpdlog.json`, applied when the importer creates the index. No index template is installed, because `httpdlog-*` is SOF-ELK's own family (its Logstash pipeline writes `httpdlog-YYYY.MM`). The index uses `dynamic: false`, except under `iis.unmapped`.

Field names follow SOF-ELK's IIS parsing (`6100-httpd.conf`, `8004-postprocess-httpd.conf`). Fields shared with `AWS/index_templates/index-httpdlog.json` and `Linux/index_templates/index-httpdlog.json` have the same types (a test checks this), so one `FROM httpdlog-*` query covers IIS, ALB/ELB, CloudFront, Apache, nginx and lighttpd logs, and an `httpdlog-<hostname>` index made by one of those importers can take IIS documents too. Use `event.dataset` or `_index` to tell them apart.

## Inputs

| Input | Recognised by | `iis.source_format` |
|---|---|---|
| [iisGeolocate](https://github.com/EricZimmerman/iisGeolocate) CSV, `<run>_<log name>_Chunk<N>.csv` | header with `date`, `time`, `cs-method`, `cs-uri-stem` | `iisgeolocate` |
| IIS W3C extended log, `u_ex*.log` (also `.gz`) | `#Fields:` line with the same columns | `w3c` |
| iisGeolocate `!UniqueIPs.csv`, `*_ConsoleLog.txt` | file name | not loaded |
| iisGeolocate `BadDataRows_REVIEW_ME.txt` | file name | not loaded; its rows are counted and reported |

A W3C file with `x-edge-*` columns is a CloudFront log and is left to `AWS/cloudfrontaccess2sofelk.py`. A raw log can change its `#Fields` line part way through (after an IIS logging change); each line uses the last one seen.

## Fields

| Field | Type | Source |
|---|---|---|
| `@timestamp` | date | `date` + `time` (W3C extended logs are written in UTC) |
| `host.name` | keyword | `--hostname`, normalised |
| `host.hostname` | keyword | `s-computername` |
| `host.os.type` | keyword | `windows` |
| `service.name` | keyword | `s-sitename` (`W3SVC1`, ...) |
| `source.ip` | ip | `c-ip` |
| `source.bytes` | long | `cs-bytes` (request size) |
| `source.geo.city_name`, `source.geo.country_name` | keyword | iisGeolocate `GeoCity`, `GeoCountry`; `NA` (private or unknown address) is left out and `_` becomes a space |
| `destination.ip`, `destination.port` | ip / integer | `s-ip`, `s-port` |
| `destination.bytes` | long | `sc-bytes` (response size) |
| `client.user.name` | keyword | `cs-username` |
| `http.request.method` | keyword | `cs-method`, upper case |
| `http.version` | keyword | `cs-version` without `HTTP/` (`1.1`) |
| `http.request.referrer`, `http.request.cookie` | keyword | `cs(Referer)`, `cs(Cookie)` |
| `http.response.status_code`, `http.response.substatus_code` | short | `sc-status`, `sc-substatus` |
| `process.exit_code`, `iis.win32_status` | long | `sc-win32-status` (SOF-ELK uses `process.exit_code`) |
| `url.path`, `url.query` | keyword (+ `.text`) | `cs-uri-stem`, `cs-uri-query` |
| `url.original` | keyword (+ `.text`) | `path?query` |
| `url.extension` | keyword | extension of the last path segment, lower case |
| `url.domain` | keyword | `cs-host` |
| `user_agent.original` | keyword | `cs(User-Agent)`, with IIS's `+` turned back into spaces |
| `xff.ip` | ip | each address in an `X-Forwarded-For`, `True-Client-IP`, `X-Real-IP` or similar custom field |
| `iis.time_taken.ms` / `event.duration` | long | `time-taken` in milliseconds / in nanoseconds |
| `iis.unmapped.<column>` | object | any other column (custom logging fields), name in snake case |
| `iis.malformed` | keyword | `column=value` for a value that did not fit its field type |
| `iis.source_format` | keyword | `iisgeolocate` or `w3c` |
| `event.dataset`, `event.kind`, `event.category` | keyword | `iis.access`, `event`, `web` |
| `log.file.path` | keyword | the input file, relative to the folder given on the command line |
| `case` | keyword | `--case` |

`-` values are left out.

## Document IDs

The `_id` is a hash of the host, the log's name (the iisGeolocate run prefix and `_Chunk<N>` removed, so `20261120085119_u_ex261102_Chunk1.csv` and `u_ex261102.log` share `u_ex261102`), every request column except the geolocation, and a counter for identical lines. Re-running the importer, loading a second iisGeolocate run, or loading the raw log and its iisGeolocate CSV therefore overwrites rather than duplicates; the CSV loaded last adds the geolocation.
