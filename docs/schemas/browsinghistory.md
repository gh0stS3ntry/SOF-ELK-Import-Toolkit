# Browsing history schema (`browsinghistory-*`)

`nirsoft_bhv2sofelk.py` writes every NirSoft BrowsingHistoryView column to a fixed field with a fixed type, defined in:

| Template | File | Applies to |
|---|---|---|
| Component `sofelk-toolkit-common` | `Windows/index_templates/component-toolkit-common.json` | shared by every toolkit custom-artifact index |
| Index template `sofelk-toolkit-browsinghistory` (priority 200) | `Windows/index_templates/index-browsinghistory.json` | `browsinghistory-*` |

The naming rules, the common fields (`@timestamp`, `host.name`, `case`, `event.dataset`, `kape.*`), and the handling of unknown columns (`browsinghistory.unmapped.*`) and bad values (`browsinghistory.malformed`) are the same as for [Amcache](amcache.md).

`event.dataset` is always `browsinghistory`. `@timestamp` is `Visit Time`, converted to UTC. BrowsingHistoryView writes visit times in the regional format and clock of the machine that **ran** it, so the importer needs `--tz` (that machine's UTC offset, or `UTC` if its GMT option was on) and detects day/month order, or takes it from `--date-order`. The text as exported is kept in `browsinghistory.visit_time_local`.

`url.domain` and `url.scheme` are derived from the URL; `user.name` is the last part of `User Profile`, lower-cased. Exports without a header line are read with BrowsingHistoryView's default column order.

## Column to field

| BrowsingHistoryView column | Field | Type | Notes |
|---|---|---|---|
| `URL` | `url.original` | keyword |  |
| `Title` | `browsinghistory.title` | keyword |  |
| `Visit Time` | `browsinghistory.visit_time` | date | converted to UTC with `--tz`; also `@timestamp` |
| `Visit Time` | `browsinghistory.visit_time_local` | keyword | as exported (machine-local text) |
| `Visit Count` | `browsinghistory.visit_count` | long |  |
| `Visited From` | `browsinghistory.visited_from` | keyword |  |
| `Visit Type` | `browsinghistory.visit_type` | keyword |  |
| `Visit Duration` | `browsinghistory.visit_duration` | keyword |  |
| `Web Browser` | `browsinghistory.web_browser` | keyword |  |
| `User Profile` | `browsinghistory.user_profile` | keyword |  |
| `Browser Profile` | `browsinghistory.browser_profile` | keyword |  |
| `URL Length` | `browsinghistory.url_length` | long |  |
| `Typed Count` | `browsinghistory.typed_count` | long |  |
| `History File` | `browsinghistory.history_file` | keyword |  |
| `Record ID` | `browsinghistory.record_id` | long |  |
| (derived) | `url.domain`, `url.scheme` | keyword | from `URL` |
| (derived) | `user.name` | keyword | from `User Profile` |

## Upgrading from the inferred-type importer

The importer refuses to append to a `browsinghistory-<hostname>` index built by the earlier version, which stored each CSV column under its own name with an inferred type. Delete the index and reload the host. Old field → new field: `URL` → `url.original`, `Title` → `browsinghistory.title`, `Visit_Time_local` → `browsinghistory.visit_time_local`, `ingest.source_file` → `kape.source_file`, `ingest.timestamp_source` → `kape.timestamp_source`; every other column is `browsinghistory.<snake_case>`.
