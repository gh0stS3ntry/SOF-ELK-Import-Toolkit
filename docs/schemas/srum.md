# SRUM schema (`srum-*`)

`srumecmd2sofelk.py` writes every SrumECmd column to a fixed field with a fixed type, defined in:

| Template | File | Applies to |
|---|---|---|
| Component `sofelk-toolkit-common` | `Windows/index_templates/component-toolkit-common.json` | shared by every toolkit custom-artifact index |
| Index template `sofelk-toolkit-srum` (priority 200) | `Windows/index_templates/index-srum.json` | `srum-*` |

The naming rules, the common fields (`@timestamp`, `host.name`, `case`, `event.dataset`, `kape.*`), and the handling of unknown columns (`srum.unmapped.*`) and bad values (`srum.malformed`) are the same as for [Amcache](amcache.md).

SrumECmd writes one CSV per SRUM table (`<time>_SrumECmd_<Table>_Output.csv`). `event.dataset` names the table:

| Table | `event.dataset` |
|---|---|
| AppResourceUseInfo | `srum.app_resource_use_info` |
| AppTimelineProvider | `srum.app_timeline_provider` |
| EnergyUsage | `srum.energy_usage` |
| NetworkConnections | `srum.network_connections` |
| NetworkUsages | `srum.network_usages` |
| PushNotifications | `srum.push_notifications` |
| vfuprov | `srum.vfuprov` |

A table this list doesn't know gets `srum.<snake_case>`. Renamed CSVs are matched by their columns.

`@timestamp` is the record's `Timestamp`: when Windows wrote the usage record (SRUM flushes roughly hourly). **It is not when the activity started**; for network connections, `srum.connect_start_time` is the connection start.

All tables share the identity columns `Id` through `AppId`. When `ExeInfo` is a file path (`\Device\HarddiskVolume2\...\x.exe`), it is also written lower-cased to ECS `process.executable`, and the file name to `process.name`. Service and package names stay only in `srum.exe_info`. `UserId` and `AppId` are row numbers in SRUM's SruDbIdMapTable, not account or application IDs; the resolved values are `user.id` / `user.name` and `srum.exe_info`.

## Column to field

| SrumECmd column | Field | Type | Notes |
|---|---|---|---|
| `Id` | `srum.id` | long |  |
| `Timestamp` | `srum.timestamp` | date | also `@timestamp` |
| `ExeInfo` | `srum.exe_info` | keyword | path, service or package name, as written |
| `ExeInfoDescription` | `srum.exe_info_description` | keyword |  |
| `ExeTimestamp` | `srum.exe_timestamp` | date |  |
| `SidType` | `srum.sid_type` | keyword |  |
| `Sid` | `user.id` | keyword |  |
| `UserName` | `user.name` | keyword |  |
| `UserId` | `srum.user_id` | long | SruDbIdMapTable index, not a Windows account ID |
| `AppId` | `srum.app_id` | long | SruDbIdMapTable index |
| `BackgroundBytesRead` | `srum.background_bytes_read` | long |  |
| `BackgroundBytesWritten` | `srum.background_bytes_written` | long |  |
| `BackgroundContextSwitches` | `srum.background_context_switches` | long |  |
| `BackgroundCycleTime` | `srum.background_cycle_time` | long |  |
| `BackgroundNumberOfFlushes` | `srum.background_number_of_flushes` | long |  |
| `BackgroundNumReadOperations` | `srum.background_num_read_operations` | long |  |
| `BackgroundNumWriteOperations` | `srum.background_num_write_operations` | long |  |
| `FaceTime` | `srum.face_time` | long |  |
| `ForegroundBytesRead` | `srum.foreground_bytes_read` | long |  |
| `ForegroundBytesWritten` | `srum.foreground_bytes_written` | long |  |
| `ForegroundContextSwitches` | `srum.foreground_context_switches` | long |  |
| `ForegroundCycleTime` | `srum.foreground_cycle_time` | long |  |
| `ForegroundNumberOfFlushes` | `srum.foreground_number_of_flushes` | long |  |
| `ForegroundNumReadOperations` | `srum.foreground_num_read_operations` | long |  |
| `ForegroundNumWriteOperations` | `srum.foreground_num_write_operations` | long |  |
| `BytesReceived` | `srum.bytes_received` | long |  |
| `BytesSent` | `srum.bytes_sent` | long |  |
| `ConnectedTime` | `srum.connected_time` | long | seconds |
| `ConnectStartTime` | `srum.connect_start_time` | date |  |
| `InterfaceLuid` | `srum.interface_luid` | long |  |
| `InterfaceType` | `srum.interface_type` | keyword |  |
| `L2ProfileFlags` | `srum.l2_profile_flags` | long |  |
| `L2ProfileId` | `srum.l2_profile_id` | long |  |
| `ProfileName` | `srum.profile_name` | keyword |  |
| `NetworkType` | `srum.network_type` | keyword |  |
| `NotificationType` | `srum.notification_type` | keyword |  |
| `PayloadSize` | `srum.payload_size` | long |  |
| `StartTime` | `srum.start_time` | date |  |
| `EndTime` | `srum.end_time` | date |  |
| `DurationMs` | `srum.duration_ms` | long |  |
| `Duration` | `srum.duration` | long |  |
| `Flags` | `srum.flags` | long |  |
| `IsLt` | `srum.is_lt` | boolean |  |
| `ConfigurationHash` | `srum.configuration_hash` | keyword |  |
| `EventTimestamp` | `srum.event_timestamp` | date |  |
| `StateTransition` | `srum.state_transition` | long |  |
| `ChargeLevel` | `srum.charge_level` | long |  |
| `CycleCount` | `srum.cycle_count` | long |  |
| `DesignedCapacity` | `srum.designed_capacity` | long |  |
| `FullChargedCapacity` | `srum.full_charged_capacity` | long |  |
| `ActiveAcTime` | `srum.active_ac_time` | long |  |
| `ActiveDcTime` | `srum.active_dc_time` | long |  |
| `ActiveDischargeTime` | `srum.active_discharge_time` | long |  |
| `ActiveEnergy` | `srum.active_energy` | long |  |
| `CsAcTime` | `srum.cs_ac_time` | long |  |
| `CsDcTime` | `srum.cs_dc_time` | long |  |
| `CsDischargeTime` | `srum.cs_discharge_time` | long |  |
| `CsEnergy` | `srum.cs_energy` | long |  |
| (derived) | `process.executable` | keyword | `ExeInfo` lower-cased, when it is a path |
| (derived) | `process.name` | keyword | file name of `process.executable` |

## Upgrading from the inferred-type importer

The importer refuses to append to a `srum-<hostname>` index built by the earlier version, which stored each CSV column under its own name with an inferred type. Delete the index and reload the host. Old column names map to `srum.<snake_case>`, except `Sid` → `user.id` and `UserName` → `user.name`.
