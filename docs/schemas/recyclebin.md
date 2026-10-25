# Recycle Bin schema (`recyclebin-*`)

`rbcmd2sofelk.py` writes every RBCmd column to a fixed field with a fixed type, defined in:

| Template | File | Applies to |
|---|---|---|
| Component `sofelk-toolkit-common` | `Windows/index_templates/component-toolkit-common.json` | shared by every toolkit custom-artifact index |
| Index template `sofelk-toolkit-recyclebin` (priority 200) | `Windows/index_templates/index-recyclebin.json` | `recyclebin-*` |

The naming rules, the common fields (`@timestamp`, `host.name`, `case`, `event.dataset`, `kape.*`), and the handling of unknown columns (`recyclebin.unmapped.*`) and bad values (`recyclebin.malformed`) are the same as for [Amcache](amcache.md).

`event.dataset` is always `recyclebin`. `@timestamp` is `DeletedOn`: when the file was moved to the Recycle Bin. `user.id` is the SID of the `$Recycle.Bin\<SID>` folder that held the `$I` file (not set for INFO2 records, which have no SID folder).

## Column to field

| RBCmd column | Field | Type | Notes |
|---|---|---|---|
| `SourceName` | `recyclebin.source_name` | keyword | `$I` / INFO2 file on the analysis machine; `user.id` is taken from it |
| `FileType` | `recyclebin.file_type` | keyword |  |
| `FileName` | `file.path` | keyword | lower-cased, `/` → `\` |
| `FileName` | `recyclebin.original_path` | keyword | as recorded (original case) |
| `FileSize` | `file.size` | long |  |
| `DeletedOn` | `recyclebin.deleted_on` | date | also `@timestamp` |
| (derived) | `user.id` | keyword | SID from `SourceName` |

## Upgrading from the inferred-type importer

The importer refuses to append to a `recyclebin-<hostname>` index built by the earlier version, which stored each CSV column under its own name with an inferred type. Delete the index and reload the host. Old field → new field: `FileName` → `file.path` (or `recyclebin.original_path`), `DeletedOn` → `recyclebin.deleted_on`, `FileSize` → `file.size`, `SourceName` → `recyclebin.source_name`, `FileType` → `recyclebin.file_type`.
