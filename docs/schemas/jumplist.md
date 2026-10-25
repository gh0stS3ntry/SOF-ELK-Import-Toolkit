# Jump List schema (`jumplist-*`)

`jlecmd2sofelk.py` writes every JLECmd column to a fixed field with a fixed type, defined in:

| Template | File | Applies to |
|---|---|---|
| Component `sofelk-toolkit-common` | `Windows/index_templates/component-toolkit-common.json` | shared by every toolkit custom-artifact index |
| Index template `sofelk-toolkit-jumplist` (priority 200) | `Windows/index_templates/index-jumplist.json` | `jumplist-*` |

The naming rules, the common fields (`@timestamp`, `host.name`, `case`, `event.dataset`, `kape.*`), and the handling of unknown columns (`jumplist.unmapped.*`) and bad values (`jumplist.malformed`) are the same as for [Amcache](amcache.md).

`event.dataset` is `jumplist.automatic` (AutomaticDestinations) or `jumplist.custom` (CustomDestinations). `user.name` is the profile in the jump list file's path (`...\Users\<name>\AppData\...`), lower-cased.

`@timestamp` is the DestList entry's `LastModified` for automatic jump lists (when the item was last opened through that app), falling back to the jump list file's `SourceModified`. Custom jump lists have no per-entry time, so they use `SourceModified`. `kape.timestamp_meaning` says which one a document got.

The embedded LNK target is described with ECS `file.*`: `file.path` from `LocalPath`, and `file.created`, `file.mtime`, `file.accessed` and `file.size` from the target's times and size. `file.accessed` is added by this template; the others come from the common component. Rows whose target has no local path (known folders, network shares, `CommonPath` only) have no `file.path`.

## Column to field

| JLECmd column | Field | Type | Notes |
|---|---|---|---|
| `SourceFile` | `jumplist.source.path` | keyword |  |
| `SourceCreated` | `jumplist.source.created` | date |  |
| `SourceModified` | `jumplist.source.modified` | date | `@timestamp` for `jumplist.custom`, and fallback for automatic |
| `SourceAccessed` | `jumplist.source.accessed` | date |  |
| `AppId` | `jumplist.app_id` | keyword |  |
| `AppIdDescription` | `jumplist.app_id_description` | keyword |  |
| `DestListVersion` | `jumplist.dest_list_version` | long |  |
| `LastUsedEntryNumber` | `jumplist.last_used_entry_number` | keyword | hex, as written by JLECmd |
| `MRU` | `jumplist.mru` | long |  |
| `EntryNumber` | `jumplist.entry_number` | keyword | hex, as written by JLECmd |
| `CreationTime` | `jumplist.entry_created` | date |  |
| `LastModified` | `jumplist.entry_last_modified` | date | `@timestamp` for `jumplist.automatic` |
| `Hostname` | `jumplist.hostname` | keyword |  |
| `MacAddress` | `jumplist.mac_address` | keyword |  |
| `Path` | `jumplist.path` | keyword |  |
| `InteractionCount` | `jumplist.interaction_count` | long |  |
| `PinStatus` | `jumplist.pinned` | boolean |  |
| `FileBirthDroid` | `jumplist.tracker.file_birth_droid` | keyword |  |
| `FileDroid` | `jumplist.tracker.file_droid` | keyword |  |
| `VolumeBirthDroid` | `jumplist.tracker.volume_birth_droid` | keyword |  |
| `VolumeDroid` | `jumplist.tracker.volume_droid` | keyword |  |
| `EntryName` | `jumplist.entry_name` | keyword | CustomDestinations category, e.g. `Recently closed` |
| `TargetCreated` | `file.created` | date |  |
| `TargetModified` | `file.mtime` | date |  |
| `TargetAccessed` | `file.accessed` | date |  |
| `FileSize` | `file.size` | long |  |
| `RelativePath` | `jumplist.relative_path` | keyword |  |
| `WorkingDirectory` | `jumplist.working_directory` | keyword |  |
| `FileAttributes` | `jumplist.file_attributes` | keyword |  |
| `HeaderFlags` | `jumplist.header_flags` | keyword |  |
| `DriveType` | `jumplist.drive_type` | keyword |  |
| `VolumeSerialNumber` | `jumplist.volume_serial_number` | keyword |  |
| `VolumeLabel` | `jumplist.volume_label` | keyword |  |
| `LocalPath` | `file.path` | keyword | lower-cased, `/` → `\` |
| `LocalPath` | `jumplist.local_path` | keyword | as recorded (original case) |
| `CommonPath` | `jumplist.common_path` | keyword |  |
| `TargetIDAbsolutePath` | `jumplist.target_id_absolute_path` | keyword |  |
| `TargetMFTEntryNumber` | `jumplist.target_mft_entry_number` | keyword | hex, e.g. `0x1B871` |
| `TargetMFTSequenceNumber` | `jumplist.target_mft_sequence_number` | keyword | hex |
| `MachineID` | `jumplist.tracker.machine_id` | keyword |  |
| `MachineMACAddress` | `jumplist.tracker.machine_mac_address` | keyword |  |
| `TrackerCreatedOn` | `jumplist.tracker.created` | date |  |
| `ExtraBlocksPresent` | `jumplist.extra_blocks_present` | keyword |  |
| `Arguments` | `jumplist.arguments` | keyword |  |
| `Notes` | `jumplist.notes` | keyword |  |
| (derived) | `file.name`, `file.extension` | keyword | from `file.path` |
| (derived) | `user.name` | keyword | from `SourceFile` |

## Upgrading from the inferred-type importer

The importer refuses to append to a `jumplist-<hostname>` index built by the earlier version, which used the raw JLECmd column names with types inferred per run. Delete it and reload the host. Main renames: `SourceFile` → `jumplist.source.path`, `AppId` → `jumplist.app_id`, `AppIdDescription` → `jumplist.app_id_description`, `LastModified` → `jumplist.entry_last_modified`, `LocalPath` → `file.path` (lower-cased) / `jumplist.local_path`, `TargetCreated`/`TargetModified`/`TargetAccessed` → `file.created`/`file.mtime`/`file.accessed`, `FileSize` → `file.size`, `Arguments` → `jumplist.arguments`. Every other column is `jumplist.<snake_case>` as listed above.
