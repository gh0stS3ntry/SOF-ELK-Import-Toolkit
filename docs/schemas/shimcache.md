# ShimCache schema (`shimcache-*`)

`shimcache2sofelk.py` writes every AppCompatCacheParser column to a fixed field with a fixed type, defined in:

| Template | File | Applies to |
|---|---|---|
| Component `sofelk-toolkit-common` | `Windows/index_templates/component-toolkit-common.json` | shared by every toolkit custom-artifact index |
| Index template `sofelk-toolkit-shimcache` (priority 200) | `Windows/index_templates/index-shimcache.json` | `shimcache-*` |

The naming rules, the common fields (`@timestamp`, `host.name`, `case`, `event.dataset`, `kape.*`), and the handling of unknown columns (`shimcache.unmapped.*`) and bad values (`shimcache.malformed`) are the same as for [Amcache](amcache.md).

`event.dataset` is always `shimcache`. `@timestamp` is `LastModifiedTimeUTC`: the file's $SI last-modified time recorded in the cache. **It is not an execution time.**

## Column to field

| AppCompatCacheParser column | Field | Type | Notes |
|---|---|---|---|
| `ControlSet` | `shimcache.control_set` | long | |
| `CacheEntryPosition` | `shimcache.cache_entry_position` | long | 0 = most recently added |
| `Path` | `file.path` | keyword | lower-cased, `/` → `\` |
| `Path` | `shimcache.path` | keyword | as recorded (original case) |
| `LastModifiedTimeUTC` | `file.mtime` | date | also `@timestamp` |
| `Executed` | `shimcache.executed` | keyword | `Yes` / `No` / `NA` |
| `Duplicate` | `shimcache.duplicate` | boolean | |
| `SourceFile` | `shimcache.source_hive` | keyword | SYSTEM hive path on the analysis machine |
| (derived) | `file.name`, `file.extension` | keyword | from `file.path` |

## Upgrading from the inferred-type importer

The importer refuses to append to a `shimcache-<hostname>` index built by the earlier version. Delete it and reload the host. Old field → new field: `Path` → `file.path` (or `shimcache.path` for the original case), `LastModifiedTimeUTC` → `file.mtime`, `Executed` → `shimcache.executed`, `CacheEntryPosition` → `shimcache.cache_entry_position`, `ControlSet` → `shimcache.control_set`, `Duplicate` → `shimcache.duplicate`, `SourceFile` → `shimcache.source_hive`.
