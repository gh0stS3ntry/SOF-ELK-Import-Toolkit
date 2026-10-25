# Windows Timeline schema (`activitiescache-*`)

`wxtcmd2sofelk.py` writes every WxTCmd column to a fixed field with a fixed type, defined in:

| Template | File | Applies to |
|---|---|---|
| Component `sofelk-toolkit-common` | `Windows/index_templates/component-toolkit-common.json` | shared by every toolkit custom-artifact index |
| Index template `sofelk-toolkit-activitiescache` (priority 200) | `Windows/index_templates/index-activitiescache.json` | `activitiescache-*` |

The naming rules, the common fields (`@timestamp`, `host.name`, `case`, `event.dataset`, `kape.*`), and the handling of unknown columns (`activitiescache.unmapped.*`) and bad values (`activitiescache.malformed`) are the same as for [Amcache](amcache.md).

WxTCmd writes one set of CSVs per user: `<user>_Activity.csv`, `<user>_Activity_PackageIDs.csv` and, when present, `<user>_ActivityOperations.csv`. `user.name` is the user from the file name.

| CSV | `event.dataset` | `@timestamp` |
|---|---|---|
| `*_Activity.csv` | `activitiescache.activity` | `StartTime`, falling back to `LastModifiedTime` |
| `*_ActivityOperations.csv` | `activitiescache.operations` | `StartTime`, falling back to `LastModifiedTime` |
| `*_Activity_PackageIDs.csv` | `activitiescache.package_ids` | ingest time (the only date is an expiry, which is not activity) |

## Activity and ActivityOperations columns

| WxTCmd column | Field | Type | Notes |
|---|---|---|---|
| `Id` | `activitiescache.id` | keyword |  |
| `ActivityTypeOrg` | `activitiescache.activity_type_org` | long |  |
| `ActivityType` | `activitiescache.activity_type` | keyword | number or name, as written |
| `Executable` | `activitiescache.executable` | keyword |  |
| `DisplayText` | `activitiescache.display_text` | keyword |  |
| `ContentInfo` | `activitiescache.content_info` | keyword |  |
| `Payload` | `activitiescache.payload` | keyword |  |
| `ClipboardPayload` | `activitiescache.clipboard_payload` | keyword |  |
| `StartTime` | `activitiescache.start_time` | date | `@timestamp` (fallback `LastModifiedTime`) |
| `EndTime` | `activitiescache.end_time` | date |  |
| `Duration` | `activitiescache.duration` | keyword | `hh:mm:ss` as written |
| `LastModifiedTime` | `activitiescache.last_modified_time` | date |  |
| `LastModifiedOnClient` | `activitiescache.last_modified_on_client` | date |  |
| `OriginalLastModifiedOnClient` | `activitiescache.original_last_modified_on_client` | date |  |
| `ExpirationTime` | `activitiescache.expiration_time` | date |  |
| `CreatedInCloud` | `activitiescache.created_in_cloud` | date |  |
| `IsLocalOnly` | `activitiescache.is_local_only` | boolean |  |
| `ETag` | `activitiescache.etag` | long |  |
| `PackageIdHash` | `activitiescache.package_id_hash` | keyword |  |
| `PlatformDeviceId` | `activitiescache.platform_device_id` | keyword |  |
| `DevicePlatform` | `activitiescache.device_platform` | keyword |  |
| `TimeZone` | `activitiescache.time_zone` | keyword |  |
| `OperationType` | `activitiescache.operation_type` | keyword |  |

## PackageIDs columns

| WxTCmd column | Field | Type | Notes |
|---|---|---|---|
| `Id` | `activitiescache.id` | keyword | links to the Activity row's `activitiescache.id` |
| `Platform` | `activitiescache.platform` | keyword |  |
| `Name` | `activitiescache.package_name` | keyword |  |
| `AdditionalInformation` | `activitiescache.additional_information` | keyword |  |
| `Expires` | `activitiescache.expiration_time` | date | not used for `@timestamp` |

## Upgrading from the inferred-type importer

The importer refuses to append to a `activitiescache-<hostname>` index built by the earlier version, which stored each CSV column under its own name with an inferred type. Delete the index and reload the host. Old column names map to `activitiescache.<snake_case>` (for example `StartTime` → `activitiescache.start_time`, `Executable` → `activitiescache.executable`); PackageIDs `Name` is now `activitiescache.package_name`.
