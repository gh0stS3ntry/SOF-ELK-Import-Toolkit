# Browsing history schema (`browsinghistory-*`)

Two importers write this schema: `nirsoft_bhv2sofelk.py` (NirSoft BrowsingHistoryView exports from Windows hosts) and `Linux/browser2sofelk.py` (Firefox and Chromium-family databases read straight from a Linux collection, see [below](#linux-firefox-and-chromium-family-linuxbrowser2sofelkpy)). The hunting queries on `browsinghistory-*` work for both.

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

## Linux: Firefox and Chromium family (`Linux/browser2sofelk.py`)

`browser2sofelk.py` reads the browsers' SQLite databases for every user under `/home/*` and `/root`, including snap and flatpak installs:

| Browser | Database |
|---|---|
| Firefox, Firefox ESR, LibreWolf, Waterfox | `.mozilla/firefox/<profile>/places.sqlite` (also `snap/firefox/common/.mozilla/...`, `.var/app/org.mozilla.firefox/.mozilla/...`, `.librewolf/...`) |
| Chrome, Chromium, Brave, Edge, Vivaldi, Opera | `.config/<browser>/<profile>/History` (also `snap/chromium/common/chromium/...`, `.var/app/*/config/...`) |

Each database is copied to a temporary folder together with its `-wal` file (so visits not yet checkpointed are included) and read there. Cookies, saved logins, `key4.db`, form history and session files are never opened.

It writes the same fields as BrowsingHistoryView, plus the host profile (`host.id`, `host.os.*`), so Windows and Linux hosts can be queried together. Times are epoch-based (Firefox PRTime, Chromium WebKit time), so no time zone is needed.

| Field | Firefox (`moz_places` + `moz_historyvisits`) | Chromium (`urls` + `visits`) |
|---|---|---|
| `@timestamp`, `browsinghistory.visit_time` | `visit_date` | `visit_time` |
| `url.original` (+ `url.domain`, `url.scheme`), `browsinghistory.url_length` | `url` | `url` |
| `browsinghistory.title`, `visit_count`, `typed_count` | `title`, `visit_count`, `typed` (0/1) | `title`, `visit_count`, `typed_count` |
| `browsinghistory.visit_type` | `visit_type` as text: Link, Typed, Bookmark, Embed, Permanent Redirect, Temporary Redirect, Download, Framed Link, Reload | core transition as text: Link, Typed, Auto Bookmark, Auto Subframe, Manual Subframe, Generated, Start Page, Form Submit, Reload, Keyword, Keyword Generated |
| `browsinghistory.transition` (long) | `visit_type` number | full `transition` value |
| `browsinghistory.transition_qualifiers` | | qualifier flags, e.g. `FROM_ADDRESS_BAR`, `CHAIN_START`, `SERVER_REDIRECT` |
| `browsinghistory.visit_source` | `source`: organic, sponsored, bookmarked, searched, tagged | |
| `browsinghistory.visit_duration` | | `visit_duration` as `HH:MM:SS.mmm` |
| `browsinghistory.from_visit` (long), `browsinghistory.visited_from` | `from_visit` and the URL of that visit | `from_visit` and the URL of that visit |
| `browsinghistory.hidden` (boolean) | `hidden` | `hidden` |
| `browsinghistory.record_id` | visit `id` | visit `id` |
| `browsinghistory.web_browser` | Firefox, LibreWolf, Waterfox | Chrome, Chromium, Brave, Edge, Vivaldi, Opera |
| `browsinghistory.user_profile`, `user.name` | `/home/<user>` and `<user>` (`/root` and `root`) | same |
| `browsinghistory.browser_profile` | profile folder, e.g. `4oxjzvod.default-esr` | `Default`, `Profile 1`, ... |
| `browsinghistory.history_file` | path on the evidence host | same |
| `kape.source_file`, `kape.timestamp_source`, `kape.timestamp_meaning` | path inside the collection, the column used for `@timestamp`, what it means | same |

`event.dataset` is `browsinghistory` for visits, as for BrowsingHistoryView.

**Downloads** are separate documents with `event.dataset` `browsinghistory.download` and `browsinghistory.visit_type` `Download` (so hunting query C2-03 lists them). `@timestamp` and `browsinghistory.visit_time` are the download start.

| Field | Firefox (`moz_annos` `downloads/*`) | Chromium (`downloads`, `downloads_url_chains`) |
|---|---|---|
| `url.original` | the downloaded URL | the last URL of the redirect chain |
| `file.path`, `file.name`, `file.extension` | `destinationFileURI` | `target_path` (else `current_path`) |
| `file.size` | | `total_bytes` |
| `browsinghistory.download.state` | `metaData.state`: complete, failed, cancelled, ... | `state`: complete, cancelled, interrupted, in progress |
| `browsinghistory.download.end_time` (date) | `metaData.endTime` | `end_time` |
| `browsinghistory.download.total_bytes` / `received_bytes` (long) | `metaData.fileSize` | `total_bytes` / `received_bytes` |
| `browsinghistory.download.deleted` (boolean) | `metaData.deleted` | |
| `browsinghistory.download.danger_type`, `interrupt_reason`, `opened` (boolean), `mime_type`, `guid`, `referrer`, `tab_url` | | same-named columns (danger type as text) |
| `browsinghistory.visited_from` | | `referrer`, else `tab_url` |

Example: every download, both platforms.

```esql
FROM browsinghistory-* METADATA _index
| WHERE event.dataset == "browsinghistory.download" OR browsinghistory.visit_type == "Download"
| KEEP @timestamp, _index, user.name, browsinghistory.web_browser, url.original, url.domain, file.path, browsinghistory.download.state, browsinghistory.download.danger_type
| SORT @timestamp
```

## Upgrading from the inferred-type importer

The importer refuses to append to a `browsinghistory-<hostname>` index built by the earlier version, which stored each CSV column under its own name with an inferred type. Delete the index and reload the host. Old field → new field: `URL` → `url.original`, `Title` → `browsinghistory.title`, `Visit_Time_local` → `browsinghistory.visit_time_local`, `ingest.source_file` → `kape.source_file`, `ingest.timestamp_source` → `kape.timestamp_source`; every other column is `browsinghistory.<snake_case>`.
