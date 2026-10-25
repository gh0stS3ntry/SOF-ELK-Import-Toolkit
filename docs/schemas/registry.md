# Registry schema (`registry-*`)

`recmd2sofelk.py` loads RECmd output into `registry-<hostname>` with a schema defined in:

| Template | File | Applies to |
|---|---|---|
| Component `sofelk-toolkit-common` | `Windows/index_templates/component-toolkit-common.json` | shared by every toolkit custom-artifact index |
| Index template `sofelk-toolkit-registry` (priority 200) | `Windows/index_templates/index-registry.json` | `registry-*` |

The common fields (`@timestamp`, `host.name`, `case`, `event.dataset`, `kape.*`) and the handling of bad values (`registry.malformed`) are the same as for [Amcache](amcache.md).

RECmd produces two kinds of CSV, and they are mapped differently:

- **The batch CSV** (`*_RECmd_Batch_*_Output.csv`) always has the same columns. Each one has a fixed field.
- **Plugin-detail CSVs** (`*_UserAssist__Users_bob_NTUSER.DAT.csv`, `*_Services__...SYSTEM.csv`, ...) each have their own columns, about 35 plugins in a KAPE run. They share `registry.key` with the batch CSV. Every other column goes to `registry.plugin.<snake_case_column>` as keyword, except the known timestamp columns listed below, which are dates.

## Fields on every document

| Field | Type | Content |
|---|---|---|
| `event.dataset` | keyword | `registry.batch`, or the plugin name lower-cased: `registry.userassist`, `registry.bamdam`, `registry.services`, ... |
| `registry.key` | keyword | Batch `KeyPath`, or plugin `BatchKeyPath` |
| `user.name` | keyword | Profile owner when the hive is a user's `NTUSER.DAT` / `UsrClass.dat` (from `HivePath`, or from the plugin file name) |
| `kape.source_hive` | keyword | Plugin files only: hive part of the file name, e.g. `Users_tdungan_NTUSER.DAT` |

## Batch CSV (`event.dataset: registry.batch`)

| RECmd column | Field | Type |
|---|---|---|
| `HivePath` | `registry.hive_path` | keyword |
| `HiveType` | `registry.hive_type` | keyword |
| `Description` | `registry.description` | keyword |
| `Category` | `registry.category` | keyword |
| `KeyPath` | `registry.key` | keyword |
| `ValueName` | `registry.value` | keyword |
| `ValueType` | `registry.data.type` | keyword |
| `ValueData` | `registry.data.strings` | keyword |
| `ValueData2` | `registry.value_data2` | keyword |
| `ValueData3` | `registry.value_data3` | keyword |
| `Comment` | `registry.comment` | keyword |
| `Recursive` | `registry.recursive` | boolean |
| `Deleted` | `registry.deleted` | boolean |
| `LastWriteTimestamp` | `registry.last_write` | date (also `@timestamp`) |
| `PluginDetailFile` | `registry.plugin_detail_file` | keyword |

## Plugin-detail CSVs (`event.dataset: registry.<plugin>`)

| RECmd column | Field | Type |
|---|---|---|
| `BatchKeyPath` | `registry.key` | keyword |
| `BatchValueName` | `registry.batch_value_name` | keyword |
| `ValueName` (MRU plugins, TimeZoneInfo) | `registry.value` | keyword |
| `ValueData` (TimeZoneInfo) | `registry.data.strings` | keyword |
| `LastWriteTimestamp` (ETW) | `registry.last_write` | date |
| Timestamp columns below | `registry.plugin.<snake_case>` | date |
| Any other column | `registry.plugin.<snake_case>` | keyword, e.g. `ProgramName` → `registry.plugin.program_name`, `RunCounter` → `registry.plugin.run_counter`, `ImagePath` → `registry.plugin.image_path` |

Typed timestamp columns (UTC): `Timestamp`, `ExecutionTime`, `LastExecuted`, `ExecutedOn`, `OpenedOn`, `LastOpened`, `ModifiedTime`, `LastDetectionTime`, `LastStart`, `CreatedOn`, `LastLoginTime`, `LastLogonTime`, `LastConnected`, `LastModified`, `ParametersKeyLastWrite`, `NameKeyLastWrite`, `ExtensionLastOpened`, `LastClosed`, `FirstInstalled`, `Installed`, `InitialTimestamp`, `LastStop`, `LastLogoffTime`, `LastPasswordChange`, `LastIncorrectPassword`. The ETW plugin's en-US format (`8/31/2022 7:34:40 PM +00:00`) is converted too.

`@timestamp` for a plugin row is the first of `registry.last_write` and then the columns above, in that order, that has a value. `kape.timestamp_source` names the column it came from. Rows with none of them, such as UserAssist entries without `LastExecuted`, use the load time.

Counts and positions (`RunCounter`, `MruPosition`, ...) are keywords. In ES|QL, use `TO_INTEGER(registry.plugin.run_counter)` to do arithmetic on them. Columns ending in `LOCAL` (KnownNetworks) are host local time with no offset, so they stay keywords.

## Upgrading from the inferred-type importer

The importer refuses to append to a `registry-<hostname>` index built by the earlier version. Delete it and reload the host. Old field → new field:

| Old field | New field |
|---|---|
| `KeyPath`, `BatchKeyPath` | `registry.key` |
| `ValueName` | `registry.value` |
| `ValueData` | `registry.data.strings` |
| `ValueData2`, `ValueData3` | `registry.value_data2`, `registry.value_data3` |
| `HivePath` | `registry.hive_path` |
| `LastWriteTimestamp` | `registry.last_write` |
| `ImagePath`, `ServiceDLL`, `ProgramName`, ... (plugin columns) | `registry.plugin.image_path`, `registry.plugin.service_dll`, `registry.plugin.program_name`, ... |
| `Username` / `UserName` (plugin columns) | `registry.plugin.username` / `registry.plugin.user_name`; `user.name` for the hive owner |
