# Amcache schema (`amcache-*`)

`amcache2sofelk.py` writes every AmcacheParser column to a fixed field with a fixed type. The types
live in two index templates, which the importer installs on every run:

| Template | File | Applies to |
|---|---|---|
| Component `sofelk-toolkit-common` | `Windows/index_templates/component-toolkit-common.json` | shared by every toolkit custom-artifact index |
| Index template `sofelk-toolkit-amcache` (priority 200) | `Windows/index_templates/index-amcache.json` | `amcache-*` |

Naming rules:

- ECS names where the meaning matches: `file.*` for the binary, driver or shortcut a row describes, `package.*` for installed programs.
- Everything else is `amcache.<snake_case_column>`.
- All strings are `keyword` (exact match, ES|QL-friendly). `file.path` also has a `file.path.text` full-text sub-field.
- Root mapping is `dynamic: false`, so nothing outside the template becomes a field by accident.
- Columns the importer does not know (for example from a newer AmcacheParser) go to `amcache.unmapped.<snake_case_column>` as keyword, and the run summary lists them.
- A value that does not fit its type (for example text in a `long` column) is not dropped: it is stored as `"Column=value"` in `amcache.malformed`, and the run summary counts it.

## Fields on every document

| Field | Type | Content |
|---|---|---|
| `@timestamp` | date | Chosen per section, see below; ingest time if the row has none |
| `host.name` | keyword | Normalized `--hostname` |
| `case` | keyword | `--case`, if given |
| `event.dataset` | keyword | `amcache.<section>`, e.g. `amcache.unassociated_file_entries` |
| `kape.source_file` | keyword | CSV file name |
| `kape.timestamp_source` | keyword | Column `@timestamp` came from |
| `kape.timestamp_meaning` | keyword | What that column means forensically |
| `file.name` | keyword | From `Name` / `DriverName`, otherwise the last part of `file.path` (lower-cased) |
| `file.extension` | keyword | From `FileExtension`, otherwise from `file.name` |

`@timestamp` source per section:

| Section | First choice | Fallback |
|---|---|---|
| Associated / Unassociated file entries | `FileKeyLastWriteTimestamp` | `KeyLastWriteTimestamp` |
| Program entries | `InstallDate` | `KeyLastWriteTimestamp` |
| All other sections | `KeyLastWriteTimestamp` | `FileKeyLastWriteTimestamp` |

None of these is proof of execution: an Amcache file key's last write is often close to first execution, but not always.

## Column to field, per section

Built from the RD01 KAPE AmcacheParser output. Column names are matched case-insensitively.

### AssociatedFileEntries (`event.dataset: amcache.associated_file_entries`)

| AmcacheParser column | Field | Type | Notes |
|---|---|---|---|
| `ApplicationName` | `amcache.application_name` | keyword |  |
| `ProgramId` | `amcache.program_id` | keyword |  |
| `FileKeyLastWriteTimestamp` | `amcache.file_key_last_write` | date |  |
| `SHA1` | `file.hash.sha1` | keyword | lower-cased, legacy `0000` prefix removed |
| `IsOsComponent` | `amcache.is_os_component` | boolean |  |
| `FullPath` | `file.path` | keyword | lower-cased, `/` → `\` |
| `Name` | `file.name` | keyword | lower-cased |
| `FileExtension` | `file.extension` | keyword | lower-cased, no dot |
| `LinkDate` | `amcache.link_date` | date |  |
| `ProductName` | `file.pe.product` | keyword |  |
| `Size` | `file.size` | long |  |
| `Version` | `file.pe.file_version` | keyword |  |
| `ProductVersion` | `amcache.product_version` | keyword |  |
| `LongPathHash` | `amcache.long_path_hash` | keyword |  |
| `BinaryType` | `amcache.binary_type` | keyword |  |
| `IsPeFile` | `amcache.is_pe_file` | boolean |  |
| `BinFileVersion` | `amcache.bin_file_version` | keyword |  |
| `BinProductVersion` | `amcache.bin_product_version` | keyword |  |
| `Usn` | `amcache.usn` | long |  |
| `Language` | `amcache.language` | long |  |
| `Description` | `file.pe.description` | keyword |  |

### DeviceContainers (`event.dataset: amcache.device_containers`)

| AmcacheParser column | Field | Type | Notes |
|---|---|---|---|
| `KeyName` | `amcache.key_name` | keyword |  |
| `KeyLastWriteTimestamp` | `amcache.key_last_write` | date |  |
| `Categories` | `amcache.categories` | keyword |  |
| `DiscoveryMethod` | `amcache.discovery_method` | keyword |  |
| `FriendlyName` | `amcache.friendly_name` | keyword |  |
| `Icon` | `amcache.icon` | keyword |  |
| `IsActive` | `amcache.is_active` | boolean |  |
| `IsConnected` | `amcache.is_connected` | boolean |  |
| `IsMachineContainer` | `amcache.is_machine_container` | boolean |  |
| `IsNetworked` | `amcache.is_networked` | boolean |  |
| `IsPaired` | `amcache.is_paired` | boolean |  |
| `Manufacturer` | `amcache.manufacturer` | keyword |  |
| `ModelId` | `amcache.model_id` | keyword |  |
| `ModelName` | `amcache.model_name` | keyword |  |
| `ModelNumber` | `amcache.model_number` | keyword |  |
| `PrimaryCategory` | `amcache.primary_category` | keyword |  |
| `State` | `amcache.state` | long |  |

### DevicePnps (`event.dataset: amcache.device_pnps`)

| AmcacheParser column | Field | Type | Notes |
|---|---|---|---|
| `KeyName` | `amcache.key_name` | keyword |  |
| `KeyLastWriteTimestamp` | `amcache.key_last_write` | date |  |
| `BusReportedDescription` | `amcache.bus_reported_description` | keyword |  |
| `Class` | `amcache.class` | keyword |  |
| `ClassGuid` | `amcache.class_guid` | keyword |  |
| `Compid` | `amcache.compid` | keyword |  |
| `ContainerId` | `amcache.container_id` | keyword |  |
| `Description` | `amcache.description` | keyword |  |
| `DriverId` | `amcache.driver_id` | keyword |  |
| `DriverPackageStrongName` | `amcache.driver_package_strong_name` | keyword |  |
| `DriverName` | `amcache.driver_name` | keyword |  |
| `DriverVerDate` | `amcache.driver_ver_date` | date | MM-DD-YYYY → date |
| `DriverVerVersion` | `amcache.driver_ver_version` | keyword |  |
| `Enumerator` | `amcache.enumerator` | keyword |  |
| `HWID` | `amcache.hwid` | keyword |  |
| `Inf` | `amcache.inf` | keyword |  |
| `InstallState` | `amcache.install_state` | long |  |
| `Manufacturer` | `amcache.manufacturer` | keyword |  |
| `MatchingId` | `amcache.matching_id` | keyword |  |
| `Model` | `amcache.model` | keyword |  |
| `ParentId` | `amcache.parent_id` | keyword |  |
| `ProblemCode` | `amcache.problem_code` | long |  |
| `Provider` | `amcache.provider` | keyword |  |
| `Service` | `amcache.service` | keyword |  |
| `Stackid` | `amcache.stack_id` | keyword |  |

### DriveBinaries (`event.dataset: amcache.drive_binaries`)

| AmcacheParser column | Field | Type | Notes |
|---|---|---|---|
| `KeyName` | `amcache.key_name` | keyword |  |
| `KeyName` | `file.path` | keyword | lower-cased, `/` → `\` |
| `KeyLastWriteTimestamp` | `amcache.key_last_write` | date |  |
| `DriverTimeStamp` | `amcache.link_date` | date |  |
| `DriverLastWriteTime` | `file.mtime` | date |  |
| `DriverName` | `amcache.driver_name` | keyword |  |
| `DriverName` | `file.name` | keyword | lower-cased |
| `DriverInBox` | `amcache.driver_in_box` | boolean |  |
| `DriverIsKernelMode` | `amcache.driver_is_kernel_mode` | boolean |  |
| `DriverSigned` | `amcache.driver_signed` | boolean |  |
| `DriverCheckSum` | `amcache.driver_checksum` | long |  |
| `DriverCompany` | `file.pe.company` | keyword |  |
| `DriverId` | `amcache.driver_id` | keyword |  |
| `DriverPackageStrongName` | `amcache.driver_package_strong_name` | keyword |  |
| `DriverType` | `amcache.driver_type` | long |  |
| `DriverVersion` | `file.pe.file_version` | keyword |  |
| `ImageSize` | `amcache.image_size` | long |  |
| `Inf` | `amcache.inf` | keyword |  |
| `Product` | `file.pe.product` | keyword |  |
| `ProductVersion` | `amcache.product_version` | keyword |  |
| `Service` | `amcache.service` | keyword |  |
| `WdfVersion` | `amcache.wdf_version` | keyword |  |

### DriverPackages (`event.dataset: amcache.driver_packages`)

| AmcacheParser column | Field | Type | Notes |
|---|---|---|---|
| `KeyName` | `amcache.key_name` | keyword |  |
| `KeyLastWriteTimestamp` | `amcache.key_last_write` | date |  |
| `Date` | `amcache.driver_date` | date |  |
| `Class` | `amcache.class` | keyword |  |
| `Directory` | `amcache.directory` | keyword |  |
| `DriverInBox` | `amcache.driver_in_box` | boolean |  |
| `Hwids` | `amcache.hwid` | keyword |  |
| `Inf` | `amcache.inf` | keyword |  |
| `Provider` | `amcache.provider` | keyword |  |
| `SubmissionId` | `amcache.submission_id` | keyword |  |
| `SYSFILE` | `amcache.sys_file` | keyword |  |
| `Version` | `amcache.version` | keyword |  |

### ProgramEntries (`event.dataset: amcache.program_entries`)

| AmcacheParser column | Field | Type | Notes |
|---|---|---|---|
| `ProgramId` | `amcache.program_id` | keyword |  |
| `KeyLastWriteTimestamp` | `amcache.key_last_write` | date |  |
| `Name` | `package.name` | keyword |  |
| `Version` | `package.version` | keyword |  |
| `Publisher` | `amcache.publisher` | keyword |  |
| `InstallDateArpLastModified` | `amcache.install_date_arp_last_modified` | date |  |
| `InstallDate` | `package.installed` | date |  |
| `InstallDateMsi` | `amcache.install_date_msi` | date |  |
| `OSVersionAtInstallTime` | `amcache.os_version_at_install_time` | keyword |  |
| `InstallDateFromLinkFile` | `amcache.install_date_from_link_file` | date |  |
| `BundleManifestPath` | `amcache.bundle_manifest_path` | keyword |  |
| `HiddenArp` | `amcache.hidden_arp` | boolean |  |
| `InboxModernApp` | `amcache.inbox_modern_app` | boolean |  |
| `Language` | `amcache.language` | long |  |
| `ManifestPath` | `amcache.manifest_path` | keyword |  |
| `MsiPackageCode` | `amcache.msi_package_code` | keyword |  |
| `MsiProductCode` | `amcache.msi_product_code` | keyword |  |
| `PackageFullName` | `amcache.package_full_name` | keyword |  |
| `ProgramInstanceId` | `amcache.program_instance_id` | keyword |  |
| `RegistryKeyPath` | `amcache.registry_key_path` | keyword |  |
| `RootDirPath` | `package.path` | keyword |  |
| `Type` | `amcache.type` | keyword |  |
| `Source` | `amcache.source` | keyword |  |
| `StoreAppType` | `amcache.store_app_type` | keyword |  |
| `UninstallString` | `amcache.uninstall_string` | keyword |  |
| `Manufacturer` | `amcache.manufacturer` | keyword |  |

### ShortCuts (`event.dataset: amcache.shortcuts`)

| AmcacheParser column | Field | Type | Notes |
|---|---|---|---|
| `KeyName` | `amcache.key_name` | keyword |  |
| `LnkName` | `file.path` | keyword | lower-cased, `/` → `\` |
| `KeyLastWriteTimestamp` | `amcache.key_last_write` | date |  |

### UnassociatedFileEntries (`event.dataset: amcache.unassociated_file_entries`)

| AmcacheParser column | Field | Type | Notes |
|---|---|---|---|
| `ApplicationName` | `amcache.application_name` | keyword |  |
| `ProgramId` | `amcache.program_id` | keyword |  |
| `FileKeyLastWriteTimestamp` | `amcache.file_key_last_write` | date |  |
| `SHA1` | `file.hash.sha1` | keyword | lower-cased, legacy `0000` prefix removed |
| `IsOsComponent` | `amcache.is_os_component` | boolean |  |
| `FullPath` | `file.path` | keyword | lower-cased, `/` → `\` |
| `Name` | `file.name` | keyword | lower-cased |
| `FileExtension` | `file.extension` | keyword | lower-cased, no dot |
| `LinkDate` | `amcache.link_date` | date |  |
| `ProductName` | `file.pe.product` | keyword |  |
| `Size` | `file.size` | long |  |
| `Version` | `file.pe.file_version` | keyword |  |
| `ProductVersion` | `amcache.product_version` | keyword |  |
| `LongPathHash` | `amcache.long_path_hash` | keyword |  |
| `BinaryType` | `amcache.binary_type` | keyword |  |
| `IsPeFile` | `amcache.is_pe_file` | boolean |  |
| `BinFileVersion` | `amcache.bin_file_version` | keyword |  |
| `BinProductVersion` | `amcache.bin_product_version` | keyword |  |
| `Usn` | `amcache.usn` | long |  |
| `Language` | `amcache.language` | long |  |
| `Description` | `file.pe.description` | keyword |  |

### Older Amcache layout (Windows 8 / early Windows 10 `File` key)

| AmcacheParser column | Field | Type | Notes |
|---|---|---|---|
| `ProgramName` | `amcache.application_name` | keyword |  |
| `FileIDLastWriteTimestamp` | `amcache.file_key_last_write` | date |  |
| `VolumeID` | `amcache.volume_id` | keyword |  |
| `VolumeIDLastWriteTimestamp` | `amcache.volume_id_last_write` | date |  |
| `FileID` | `amcache.file_id` | keyword |  |
| `MFTEntryNumber` | `amcache.mft_entry_number` | long |  |
| `MFTSequenceNumber` | `amcache.mft_sequence_number` | long |  |
| `FileSize` | `file.size` | long |  |
| `FileVersionString` | `file.pe.file_version` | keyword |  |
| `FileVersionNumber` | `amcache.file_version_number` | keyword |  |
| `FileDescription` | `file.pe.description` | keyword |  |
| `SizeOfImage` | `amcache.image_size` | long |  |
| `PEHeaderHash` | `amcache.pe_header_hash` | keyword |  |
| `PEHeaderChecksum` | `amcache.pe_header_checksum` | long |  |
| `CompanyName` | `file.pe.company` | keyword |  |
| `Created` | `file.created` | date |  |
| `LastModified` | `file.mtime` | date |  |
| `LastModified2` | `amcache.last_modified2` | date |  |
| `CompileTime` | `amcache.compile_time` | date |  |
| `LanguageID` | `amcache.language` | long |  |
## Changing the schema

1. Edit the column map in `amcache2sofelk.py` (`COLUMNS` / `SECTION_COLUMNS`) and the matching field in `index-amcache.json`. The importer refuses to run if the two disagree.
2. Adding a field is safe for existing indexes: the importer pushes new fields to an existing `amcache-*` index on its next run.
3. Changing an existing field's type is not: bump `toolkit_schema_version`, then delete and reload the affected `amcache-<hostname>` indexes.

## Upgrading from the inferred-type importer

Indexes created by the earlier version of `amcache2sofelk.py` used raw column names (`FullPath`, `SHA1`, `KeyLastWriteTimestamp`, ...) at the top level with types inferred per run. The importer refuses to append to such an index. Delete it (`DELETE amcache-<hostname>`) and reload the host. Queries written against the old names need updating:

| Old field | New field |
|---|---|
| `FullPath` | `file.path` (lower-cased) |
| `SHA1` | `file.hash.sha1` (already the normalized value before) |
| `Name` (file entries) | `file.name` |
| `FileKeyLastWriteTimestamp` | `amcache.file_key_last_write` |
| `KeyLastWriteTimestamp` | `amcache.key_last_write` |
| `ProgramId` | `amcache.program_id` |
| `ProductName` | `file.pe.product` |
| `Size` | `file.size` |
| `LinkDate` | `amcache.link_date` |
| `<Column>` (anything else) | `amcache.<snake_case_column>` |
