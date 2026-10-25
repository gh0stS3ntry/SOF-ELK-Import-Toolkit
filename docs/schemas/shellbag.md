# ShellBags schema (`shellbag-*`)

`sbecmd2sofelk.py` writes every SBECmd column to a fixed field with a fixed type, defined in:

| Template | File | Applies to |
|---|---|---|
| Component `sofelk-toolkit-common` | `Windows/index_templates/component-toolkit-common.json` | shared by every toolkit custom-artifact index |
| Index template `sofelk-toolkit-shellbag` (priority 200) | `Windows/index_templates/index-shellbag.json` | `shellbag-*` |

The naming rules, the common fields (`@timestamp`, `host.name`, `case`, `event.dataset`, `kape.*`), and the handling of unknown columns (`shellbag.unmapped.*`) and bad values (`shellbag.malformed`) are the same as for [Amcache](amcache.md).

`event.dataset` is always `shellbag`. SBECmd names its CSVs `<user>_NTUSER.csv` and `<user>_UsrClass.csv`; the importer takes `user.name` (lower-cased) and `shellbag.hive` (`NTUSER` or `UsrClass`) from that file name.

`@timestamp` is `LastInteracted` when the bag has one, otherwise the bag key's `LastWriteTime`. A key's last write time can be caused by a later change to a sibling folder, so treat it as "no later than", not as the time this folder was opened.

The folder's own MAC times, when the shell item carries them, go to ECS `file.created`, `file.mtime` and `file.accessed`. These come from the shell item's DOS timestamps (2-second resolution), not from the file system. `file.accessed` is added by this template; the others come from the common component.

## Column to field

| SBECmd column | Field | Type | Notes |
|---|---|---|---|
| `BagPath` | `shellbag.bag_path` | keyword |  |
| `Slot` | `shellbag.slot` | long |  |
| `NodeSlot` | `shellbag.node_slot` | long |  |
| `MRUPosition` | `shellbag.mru_position` | long |  |
| `AbsolutePath` | `shellbag.absolute_path` | keyword |  |
| `ShellType` | `shellbag.shell_type` | keyword |  |
| `Value` | `shellbag.value` | keyword |  |
| `ChildBags` | `shellbag.child_bags` | long |  |
| `CreatedOn` | `file.created` | date |  |
| `ModifiedOn` | `file.mtime` | date |  |
| `AccessedOn` | `file.accessed` | date |  |
| `LastWriteTime` | `shellbag.last_write` | date | `@timestamp` fallback |
| `MFTEntry` | `shellbag.mft_entry` | long |  |
| `MFTSequenceNumber` | `shellbag.mft_sequence_number` | long |  |
| `ExtensionBlockCount` | `shellbag.extension_block_count` | long |  |
| `FirstInteracted` | `shellbag.first_interacted` | date |  |
| `LastInteracted` | `shellbag.last_interacted` | date | `@timestamp` when present |
| `HasExplored` | `shellbag.has_explored` | boolean |  |
| `Miscellaneous` | `shellbag.miscellaneous` | keyword |  |
| (file name) | `user.name` | keyword | `<user>_NTUSER.csv` / `<user>_UsrClass.csv` |
| (file name) | `shellbag.hive` | keyword | `NTUSER` or `UsrClass` |

## Upgrading from the inferred-type importer

The importer refuses to append to a `shellbag-<hostname>` index built by the earlier version, which used the raw SBECmd column names with types inferred per run. Delete it and reload the host. Renames: `AbsolutePath` → `shellbag.absolute_path`, `LastInteracted` → `shellbag.last_interacted`, `FirstInteracted` → `shellbag.first_interacted`, `LastWriteTime` → `shellbag.last_write`, `CreatedOn`/`ModifiedOn`/`AccessedOn` → `file.created`/`file.mtime`/`file.accessed`, `MFTEntry` → `shellbag.mft_entry`. Every other column is `shellbag.<snake_case>` as listed above. The earlier version also did not set `user.name` for SBECmd's file names; this one does.
