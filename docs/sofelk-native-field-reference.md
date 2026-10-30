# SOF-ELK native field reference

This is the reference for the four artifact types that SOF-ELK parses out of the box and that the toolkit also ingests: MFTECmd (`filesystem`), EvtxECmd (`evtxlogs`), LECmd (`lnkfiles`) and PECmd (`prefetch`). For each one it lists the field names and types that SOF-ELK's own Logstash pipeline produces, and checks the toolkit's JSON importers against them. Mapping templates and ES|QL queries should build on these names.

How it was built:

- **Native side:** read from the SOF-ELK source tree (`sof-elk-main/`). That covers `configfiles/6501`–`6505` (parsers), `8005-postprocess-kape.conf`, `1000`/`1001` preprocessing, `9900` output, `lib/filebeat_inputs/kape.yml`, `lib/elasticsearch_templates/`, `kibana/data_views/`, `supporting-scripts/*_flags_to_array.rb` and `doc/ecs_fields.csv`.
- **Toolkit side:** a dry run of `Windows/json_importers/*2sofelk.py` (as of `main` at `eea5b10`) over the RD01 KAPE CSV exports. Every transformed document was walked to record which fields appear, with what Python type and how often. Nothing was sent to Elasticsearch.
- The same tables are in [`sofelk-native-fields.csv`](sofelk-native-fields.csv), one row per field, for use by scripts.

Status legend: **match** = same name and type as native. **differs** = name or type differs from native. **broken (CSV)** = the toolkit loses or corrupts the value when the input is CSV (JSON input follows the native logic). **lost (both)** = neither native SOF-ELK nor the toolkit keeps it.

---

## 1. Index layer

### 1.1 Index names and patterns

| Artifact | `labels.type` | Native index (Logstash `9900`) | Toolkit index | Data View | Index template |
|---|---|---|---|---|---|
| MFTECmd `$MFT` / `$J` | `kape_filesystem` | `filesystem-YYYY.MM` | `filesystem-<host>` | `filesystem-*` | `index-filesystem.json` |
| EvtxECmd (and Hayabusa) | `kape_evtxlogs` / `hayabusa` | `evtxlogs-YYYY.MM` | `evtxlogs-<host>` | `evtxlogs-*` | `index-evtxlogs.json` |
| LECmd | `kape_lnkfiles` | `lnkfiles-YYYY.MM` | `lnkfiles-<host>` | `lnkfiles-*` | `index-lnkfiles.json` |
| PECmd | `kape_prefetch` | `prefetch-YYYY.MM` | `prefetch-<host>` | `prefetch-*` | **none** |

- Native index names come from `%{[sof-elk][base_index]}-%{+YYYY.MM}`, where the month is the month of the **event** `@timestamp`. One host's data is spread across many monthly indexes, and all hosts share them. The toolkit's `<prefix>-<host>` indexes still match the same `*-*` index templates and Data Views, so native and toolkit data can sit side by side under one Data View.
- Every Data View uses `@timestamp` as its time field. The Kibana `kape` Data View is `filefolderaccess-*,filesystem-*,lnkfiles-*,evtxlogs-*`. It does **not** include `prefetch-*`, and no current pipeline writes `filefolderaccess-*`.
- Filebeat picks up only `*_MFTECmd*_Output.json(.gz)`, `*_LECmd_Output.json(.gz)`, `*_EvtxECmd_Output.json(.gz)` and `*_PECmd_Output.json(.gz)`. `_PECmd_Output_Timeline` is excluded. Natively, SOF-ELK has no CSV path for these four tools.

### 1.2 What the index templates actually define

The SOF-ELK templates are thin. Almost every type in the tables below comes from **dynamic mapping of whatever JSON Logstash emits**, not from an explicit mapping.

| Component (`component_templates/`) | Effect | Used by |
|---|---|---|
| `settings-common` | 1 shard, 0 replicas (`auto_expand_replicas 0-1`), `best_compression` | filesystem, evtxlogs, lnkfiles |
| `mappings-corecommon` | `@timestamp` date; `@version`, `path`, `original_message`, `sof-elk.base_index`, `sof-elk.path` keyword; `log.file.inode`/`device_id` unsigned_long; `*_rawvalue` → text | filesystem, evtxlogs, lnkfiles |
| `mappings-string` | empty | filesystem, evtxlogs, lnkfiles |
| `mappings-final` | every other string → `text` (norms off) + `.keyword` (`ignore_above: 256`) | filesystem, evtxlogs, lnkfiles |
| index-level settings | `mapping.total_fields.limit: 5000` | filesystem, evtxlogs (lnkfiles keeps the default of 1000) |

The `ip`, `port`, `geohash`, `guid` and `zeekuid` components are **not** attached to any of these four. `remote.ip` in `evtxlogs` is therefore a string, not an `ip`.

`prefetch-*` has **no** index template at all. Natively it gets plain Elasticsearch defaults: 1 replica (yellow health on a single-node VM), strings as `text` + `.keyword` (ignore_above 256), and date detection on.

Effective native types, as used in the tables:

- **date**: the pipeline runs a `date {}` filter on the field (ISO8601 output), or the field is an ISO8601 string that Elasticsearch's default `date_detection` picks up.
- **long**: a JSON number from the tool, or a Logstash `convert => integer`.
- **boolean**: JSON `true`/`false`. `1001-preprocess-json.conf` also unquotes `"true"`/`"false"`.
- **text+keyword**: any other string. Use `<field>.keyword` for exact match, `STATS ... BY` and sorting.

### 1.3 How the toolkit creates its indexes

`sof_elk_json_bulk_common.Elasticsearch.ensure_index` creates each index explicitly, with `number_of_replicas: 0`, `total_fields.limit: 5000`, `ignore_malformed: true`, **`date_detection: false`**, `numeric_detection: false`, a `strings_as_text_and_keyword` dynamic template (`ignore_above: 2048`) and the explicit `MAPPINGS` of each importer.

Two consequences:

1. **Template merge.** When the SOF-ELK index templates are installed, `filesystem-<host>`, `evtxlogs-<host>` and `lnkfiles-<host>` also receive the template's settings and dynamic templates. Dynamic templates are evaluated in order and the template's `string_fields` (`ignore_above: 256`) comes first. So on a real SOF-ELK VM, `.keyword` subfields of these three indexes probably end up at 256, not 2048. `prefetch-<host>` has no template, so it keeps 2048. Check with `GET filesystem-<host>/_mapping` before relying on `.keyword` for long paths, script blocks or command lines.
2. **No date detection.** Any timestamp the importer does not convert explicitly stays a string. Natively it would often become a `date`. The fields affected are marked **differs** below (`file.update_timestamp`, `file.tracker.creation`, the `event_data` `*Time` fields).

`ignore_malformed: true` means that a value which does not fit its mapped type is dropped from the index without an error. The `_source` keeps the value but it cannot be searched. A broken timestamp therefore fails silently.

---

## 2. Field tables

Toolkit types are what Elasticsearch maps from the toolkit's documents: explicit `MAPPINGS` first, otherwise dynamic. Row counts quoted in the notes are from the RD01 dry run.

### 2.1 `filesystem` (MFTECmd: `6501-kape_mftecmd.conf`)

RD01 dry run: 428,361 `$MFT` rows, 365,943 `$J` rows, plus 9,369 rows from `$Boot` and `$SDS` (see 3.6).

| Field | Source column | Native type | Toolkit type | Status | Note |
|---|---|---|---|---|---|
| `@timestamp` | LastModified0x10, else Created0x10, else UpdateTimestamp | date | date | match | Falls back to ingest time when none parse ($Boot/$SDS rows; Python < 3.11, see 3.4) |
| `file.stdinfo.created` | Created0x10 | date | date | match |  |
| `file.stdinfo.mtime` | LastModified0x10 | date | date | match |  |
| `file.stdinfo.accessed` | LastAccess0x10 | date | date | match |  |
| `file.stdinfo.ctime` | LastRecordChange0x10 | date | date | match | MFT record change time, not creation |
| `file.filename.created` | Created0x30, else Created0x10 | date | date | **differs** | MFTECmd blanks 0x30 when equal to 0x10; the toolkit restores it, SOF-ELK leaves it absent |
| `file.filename.mtime` | LastModified0x30, else LastModified0x10 | date | date | **differs** | MFTECmd blanks 0x30 when equal to 0x10; the toolkit restores it, SOF-ELK leaves it absent |
| `file.filename.accessed` | LastAccess0x30, else LastAccess0x10 | date | date | **differs** | MFTECmd blanks 0x30 when equal to 0x10; the toolkit restores it, SOF-ELK leaves it absent |
| `file.filename.ctime` | LastRecordChange0x30, else LastRecordChange0x10 | date | date | **differs** | MFTECmd blanks 0x30 when equal to 0x10; the toolkit restores it, SOF-ELK leaves it absent |
| `file.name` | FileName ($MFT) / Name ($J) | text+keyword | text+keyword | match |  |
| `file.directory` | ParentPath | text+keyword | text+keyword | match | Removed when empty |
| `file.path` | file.directory + '\' + file.name | text+keyword | text+keyword | match | Built in 8005-postprocess-kape.conf |
| `file.extension` | Extension (leading dot removed) | text+keyword | text+keyword | match | For ADS rows, taken from file.name |
| `file.fork_name` | ADS stream name parsed from file.name | text+keyword | text+keyword | match | Only when kape.mft.isads is true |
| `file.inode` | EntryNumber | long | long | match |  |
| `file.sequence_number` | SequenceNumber | long | long | match |  |
| `file.parent.inode` | ParentEntryNumber | long | long | match |  |
| `file.parent.sequence_number` | ParentSequenceNumber | long | long | match |  |
| `file.size` | FileSize | long | long | match | Set to 0 when missing |
| `file.reference_count` | ReferenceCount | long | long | match |  |
| `file.reparse.target` | ReparseTarget | text+keyword | text+keyword | match |  |
| `file.uid` | SecurityId | long | long | match | Security descriptor ID, not a SID |
| `file.object_id` | ObjectIdFileDroid | text+keyword | text+keyword | match |  |
| `file.stream_name` | LoggedUtilStream | text+keyword | text+keyword | match |  |
| `file.fork_contents` | ZoneIdContents | text+keyword | text+keyword | match | Zone.Identifier text (ZoneId, ReferrerUrl, HostUrl) |
| `file.logfile.sequence_number` | LogfileSequenceNumber | long | long | match |  |
| `file.update_sequence_number` | UpdateSequenceNumber | long | long | match | $J USN |
| `file.update_reasons` | UpdateReasons ($J), lowercased, split on \| | text+keyword (array) | text+keyword (array) | match |  |
| `file.update_timestamp` | UpdateTimestamp ($J) | date (dynamic date detection on ISO string) | text+keyword | **differs** | Not converted in place by either; toolkit disables date_detection |
| `file.offset_to_data` | OffsetToData ($J) | long | long | match |  |
| `file.source_file` | SourceFile | text+keyword | text+keyword | match |  |
| `file.attributes.<flag>` | SiFlags ($MFT, integer) / FileAttributes ($J, names joined by \|) | boolean x19 | boolean x19 | match | $MFT CSV gives names (`Hidden\|System`), not an integer; the toolkit accepts both |
| `file.type` | isDirectory -> dir / file | text+keyword | text+keyword | match | Toolkit reads both isDirectory (JSON) and IsDirectory (CSV) |
| `kape.mft.fn_same_as_si` | (derived) names of blank 0x30 times restored from 0x10 | (absent) | keyword (array) | **differs** | Toolkit only; `created`, `mtime`, `accessed`, `ctime` |
| `kape.mft.inuse` | InUse | boolean | boolean | match |  |
| `kape.mft.hasads` | HasAds | boolean | boolean | match |  |
| `kape.mft.isads` | IsAds | boolean | boolean | match |  |
| `kape.mft.copied` | Copied | boolean | boolean | match |  |
| `kape.mft.timestomped` | Timestomped | boolean | (absent) | **lost (both)** | Current MFTECmd emits SI<FN and uSecZeros instead; neither pipeline keeps them |
| `kape.mft.name_type` | NameType | text+keyword | text+keyword | match | Windows / DosWindows / Posix / Dos |
| `tags` | filesystem_mft or filesystem_j | text+keyword | keyword | match |  |

`file.attributes.<flag>` is one boolean per NTFS flag (`ntfs_flags_to_array.rb`): `readonly`, `hidden`, `system`, `archive`, `device`, `normal`, `temporary`, `sparsefile`, `reparsepoint`, `compressed`, `offline`, `notcontentindexed`, `encrypted`, `integritystream`, `virtual`, `noscrubdata`, `hasea`, `directory`, `indexview`. `8005` also tries to convert `file.attributes._rawvalue` to a string, but the Ruby script never writes `_rawvalue`, so the field never exists.

### 2.2 `evtxlogs` (EvtxECmd: `6504-kape_evtxecmd.conf`)

RD01 dry run: 249,672 events, 295 distinct `winlog.payload.event_data.*` names, 40 distinct `winlog.payload.user_data.*` paths.

| Field | Source column | Native type | Toolkit type | Status | Note |
|---|---|---|---|---|---|
| `@timestamp` | TimeCreated | date | date | match | Falls back to ingest time silently if TimeCreated does not parse |
| `winlog.time_created` | TimeCreated | date (dynamic) | date | match |  |
| `winlog.event_id` | EventId | long | long | match | TO_STRING before IN (...) in ES\|QL |
| `winlog.record_id` | RecordNumber | long | long | match |  |
| `winlog.channel` | Channel | text+keyword | text+keyword | match |  |
| `winlog.provider_name` | Provider | text+keyword | text+keyword | match |  |
| `winlog.computer_name` | Computer | text+keyword | text+keyword | match | FQDN from the event, e.g. rd01.shieldbase.com |
| `winlog.user.identifier` | UserId | text+keyword | text+keyword | match | Toolkit also copies it to `user.id` |
| `user.id` | copy of winlog.user.identifier | (never set) | text+keyword | **differs** | Native copy reads a misspelled source field, so it is always empty natively |
| `winlog.user.name` | UserName | text+keyword | text+keyword | match |  |
| `winlog.process.pid` | ProcessId | long | long | match | Process that logged the event, not the subject process |
| `winlog.process.thread.id` | ThreadId | long | long | match |  |
| `winlog.remote_host` | RemoteHost | text+keyword | text+keyword | match |  |
| `remote.ip` | IP part of RemoteHost | text+keyword (+ remote.geo.*, remote.as.*) | text+keyword | **differs** | Toolkit adds no GeoIP/ASN enrichment |
| `remote.port` | port part of RemoteHost | text+keyword | keyword | **differs** | Minor: keyword only |
| `winlog.keywords` | Keywords split on ', ' | text+keyword (array) | text+keyword (array) | match |  |
| `kape.log_level` | Level | text+keyword | text+keyword | match |  |
| `kape.map_description` | MapDescription | text+keyword | text+keyword | match |  |
| `kape.executable_info` | ExecutableInfo | text+keyword | text+keyword | match |  |
| `file.source_file` | SourceFile | text+keyword | text+keyword | match | Source .evtx path |
| `winlog.payload.event_data.<Name>` | Payload EventData.Data[@Name] = #text | text+keyword | text+keyword | match | 295 distinct names on RD01; all strings |
| `winlog.payload.event_data.SystemTime/LoaderTime/OldTime/NewTime` | Payload EventData.Data | date (space replaced by T, then date detection) | text+keyword | **differs** | Toolkit skips the 8005 space-to-T fix |
| `winlog.payload.event_data.string` | EventData.Data when it is a plain string, split on ', ' | text+keyword (array) | text+keyword (array) | match |  |
| `winlog.payload.event_data.binary` | EventData.Binary | text+keyword | text+keyword | match |  |
| `winlog.payload.user_data.*` | Payload UserData | object (dynamic) | object; user_data.EventData forced to text | **differs** | Toolkit flattens UserData.EventData to a JSON string to avoid object/text conflicts |
| `winlog.event_data.<ActionName\|TaskName\|Path\|...>` | Payload root keys (13 named in 6504) | text+keyword | text+keyword | match |  |
| `winlog.payload_data.<Name>` | PayloadData1-6 'Name: value' | text+keyword | text+keyword | **differs** | Native grok is unanchored; toolkit regex is anchored, see 3.3 |
| `message` | 'KAPE map used: ' + MapDescription | text+keyword | text+keyword | match |  |
| `tags` | _grokparsefail_6504-0N on PayloadData parse failures | text+keyword | keyword | match |  |

Columns that both pipelines drop: `EventRecordId`, `ChunkNumber`, `HiddenRecord`, `ExtraDataOffset`, and the raw `PayloadData1`–`6` strings (only the parsed `winlog.payload_data.*` keys are kept). `winlog.event_data.*` (13 fixed names taken from the Payload root) and `winlog.payload.event_data.*` (all `EventData.Data` names) are separate trees. Hunting queries almost always want `winlog.payload.event_data.*`.

### 2.3 `lnkfiles` (LECmd: `6503-kape_lecmd.conf`)

RD01 dry run: 294 shortcuts.

| Field | Source column | Native type | Toolkit type | Status | Note |
|---|---|---|---|---|---|
| `@timestamp` | SourceModified | date | date | match |  |
| `file.created` | SourceCreated | date | date | match | .lnk file itself |
| `file.mtime` | SourceModified | date | date | match |  |
| `file.accessed` | SourceAccessed | date | date | match |  |
| `file.path` | SourceFile | text+keyword | text+keyword | match |  |
| `file.directory / file.name` | split from file.path | text+keyword | text+keyword | match |  |
| `file.extension` | constant 'lnk' | text+keyword | text+keyword | match |  |
| `file.size` | FileSize | long | long | match | Target size recorded in the .lnk |
| `file.target.created` | TargetCreated | date | date | match | Removed when empty |
| `file.target.mtime` | TargetModified | date | date | match |  |
| `file.target.accessed` | TargetAccessed | date | date | match |  |
| `file.target.path` | copy of local_path, else absolute_path | text+keyword | text (no .keyword) | **differs** | Toolkit maps text only, so no file.target.path.keyword |
| `file.target.local_path` | LocalPath | text+keyword | text+keyword | match |  |
| `file.target.absolute_path` | TargetIDAbsolutePath | text+keyword | text+keyword | match |  |
| `file.target.network_path` | NetworkPath | text+keyword | text+keyword | match |  |
| `file.target.common_path` | CommonPath | text+keyword | text+keyword | match |  |
| `file.target.relative_path` | RelativePath | text+keyword | text+keyword | match |  |
| `file.target.working_directory` | WorkingDirectory | text+keyword | text+keyword | match |  |
| `file.target.path.arguments` | Arguments | (lost) | (lost) | **lost (both)** | Overwritten by the file.target.path copy, see 3.5 |
| `file.target.drivetype` | DriveType | text+keyword | text+keyword | match | Removed when '(None)' |
| `file.target.volume.label` | VolumeLabel | text+keyword | text+keyword | match |  |
| `volume.serial_number` | VolumeSerialNumber | text+keyword | text+keyword | match | Pivot to prefetch volume.serial_number |
| `file.target.inode` | TargetMFTEntryNumber | long | long | match | CSV value is hex (0x44EF2); toolkit parses hex and decimal |
| `file.target.sequence_number` | TargetMFTSequenceNumber | long | long | match | Same hex handling |
| `file.tracker.machine_id` | MachineID | text+keyword | text+keyword | match | NetBIOS name of the creating machine |
| `file.tracker.mac` | MachineMACAddress | text+keyword | text+keyword | match |  |
| `file.tracker.mac_vendor` | MACVendor | text+keyword | text+keyword | match |  |
| `file.tracker.creation` | TrackerCreatedOn | date if ISO (dynamic detection), else text | text+keyword | **differs** | Native date{} targets a misspelled field, so neither converts it |
| `file.header_flags.<flag>` | HeaderFlags | boolean x27 | boolean x27 | match |  |
| `file.attributes.<flag>` | FileAttributes | boolean x19 | boolean x19 | match |  |
| `file.extra_blocks` | ExtraBlocks_Present (JSON) / ExtraBlocksPresent (CSV) | text+keyword (array) | text+keyword (array) | match | Toolkit maps both column names |

`file.header_flags.<flag>` is one boolean per LNK header flag (`data_flags_to_array.rb`): `hastargetidlist`, `haslinkinfo`, `hasname`, `hasrelativepath`, `hasworkingdir`, `hasarguments`, `hasiconlocation`, `isunicode`, `forcenolinkinfo`, `hasexpstring`, `runinseparateprocess`, `reserved0`, `hasdarwinid`, `runasuser`, `hasexpicon`, `nopidlalias`, `reserved1`, `runwithshimlayer`, `forcenolinktrack`, `enabletargetmetadata`, `disablelinkpathtracking`, `disableknownfoldertracking`, `disableknownfolderalias`, `allowlinktolink`, `unaliasonsave`, `preferenvironmentpath`, `keeplocalidlistforunctarget`.

### 2.4 `prefetch` (PECmd: `6505-kape_pecmd.conf`)

RD01 dry run: 400 prefetch files, with 1,653 previous-run timestamps between them.

| Field | Source column | Native type | Toolkit type | Status | Note |
|---|---|---|---|---|---|
| `@timestamp` | LastRun, else SourceModified | date | date | match |  |
| `file.path` | SourceFilename | text+keyword | text+keyword | match | .pf path |
| `file.directory / file.name` | split from file.path | text+keyword | text+keyword | match |  |
| `file.extension` | constant 'pf' | text+keyword | text+keyword | match |  |
| `file.stdinfo.ctime` | SourceCreated | date | date | match | Native puts the .pf creation time in ctime, not created |
| `file.stdinfo.mtime` | SourceModified | date | date | match |  |
| `file.stdinfo.accessed` | SourceAccessed | date | date | match |  |
| `file.target.path` | ExecutableName | text+keyword | text+keyword | match | Executable name only, no directory |
| `file.size` | Size | long | long | match |  |
| `kape.prefetch.hash` | Hash | text+keyword | text+keyword | match |  |
| `kape.prefetch.version` | Version | text+keyword | text+keyword | match |  |
| `kape.prefetch.run_count` | RunCount | long | long | match |  |
| `kape.prefetch.last_run` | LastRun | date | date | match | 0001-01-01 sentinel removed |
| `prefetch.previous_runs` | PreviousRun0-7 | date (array) | date (array) | match | Top-level prefetch.*, not kape.prefetch.* |
| `kape.prefetch.volume.name` | Volume0Name | text+keyword | text+keyword | match | Volume1+ columns are dropped by both |
| `kape.prefetch.volume.created` | Volume0Created | date | date | match |  |
| `volume.serial_number` | Volume0Serial | text+keyword | text+keyword | match |  |
| `kape.prefetch.directories` | Directories split on ', ' | text+keyword (array) | text+keyword (array) | match |  |
| `kape.prefetch.files_loaded` | FilesLoaded split on ', ' | text+keyword (array) | text+keyword (array) | match |  |
| `kape.prefetch.parsing_error` | ParsingError | boolean | boolean | match |  |
| `message` | 'Prefetch: <exe> executed <n> time(s)' | text+keyword | text+keyword | match |  |

### 2.5 Fields common to all four

| Field | Source column | Native type | Toolkit type | Status | Note |
|---|---|---|---|---|---|
| `labels.type` | kape_filesystem / kape_evtxlogs / kape_lnkfiles / kape_prefetch | text+keyword | keyword | match | Filebeat label; toolkit sets the same values |
| `log.file.path` | Filebeat source path | text+keyword | keyword | match | Toolkit writes the importer's input path |
| `sof-elk.path` | 'filebeat: <path>' | keyword | keyword | match |  |
| `host.name` | Filebeat host (removed in 1000-preprocess-all.conf) | (never set) | keyword | **differs** | Toolkit-only; added by the bulk-hardening change |
| `case` | - | (never set) | keyword | **differs** | Toolkit-only; added by the bulk-hardening change |
| `@version, sof-elk.base_index, sof-elk.processing_time, agent.*, ecs.version, input.type, log.offset` | Logstash / Filebeat metadata | various | (absent) | **differs** | Pipeline bookkeeping; not useful for hunting |

---

## 3. Discrepancies found in the RD01 dry run

These are differences between the toolkit and native SOF-ELK, or data problems that the dry run exposed. Items marked **Fixed** have since been corrected in the toolkit; the rest are still open. They are listed so the template and ES|QL work knows what to expect, and so each can be picked up as its own fix.

### 3.1 RD01 EvtxECmd CSV has no usable dates

Every one of the 249,672 `TimeCreated` values in `EventLogs/20261025081931_EvtxECmd_Output.csv` looks like `43:24.1` (minutes:seconds.tenths). This is the pattern a CSV shows after it has been opened and re-saved in Excel. The importer cannot parse it. Every event then gets `@timestamp` = ingest time and `winlog.time_created` is omitted. The importer now prints a warning with the count and an example value (`winlog.time_created=249672 (e.g. '43:24.1')`). Any `evtxlogs-rd01` built from this file has no usable timeline. Re-export with EvtxECmd (JSON preferred) or use the original KAPE CSV.

### 3.2 MFTECmd CSV: attributes and directory flag

- **Fixed.** `$MFT` CSV writes `SiFlags` as names (`Archive|SparseFile|ReparsePoint`), not as the integer that the JSON output and SOF-ELK's `source_type => "int"` expect. The importer used to set every `file.attributes.*` flag to `false` for all 428,361 `$MFT` rows. It now reads names as well as integers (454,318 flags set on RD01).
- **Fixed.** The CSV header is `IsDirectory`, but the importer read only `isDirectory` (the JSON spelling), so `file.type` was `file` for every row. It now reads both (RD01: 97,743 `dir`, 330,618 `file`).
- The CSV-only timestomping indicators `SI<FN` and `uSecZeros` are discarded. `kape.mft.timestomped` is mapped natively, but current MFTECmd no longer emits a `Timestomped` column, so neither pipeline populates it.

### 3.3 EvtxECmd: field name and PayloadData parsing

- **Fixed.** Native `6504` renames `UserId` to **`winlog.user.identifier`**. The toolkit wrote **`winlog.user.identifer`** (misspelled) and now writes `winlog.user.identifier`. Its code comment blames the Logstash rename, but the misspelling is actually in `8005`'s `copy` to `user.id`. Natively that copy reads a field that never exists, so `user.id` is never set. The toolkit does set `user.id`, which is useful, but the `winlog.user.*` name does not match.
- Native grok `%{WORD:name}: %{GREEDYDATA:value}` is unanchored. The toolkit's regex is anchored at the start of the value. Values with a space in the label (`Command Name: Remove-AppxProvisionedPackage`, `Host Name: ConsoleHost`, `Script Name: ...`) are parsed natively as `winlog.payload_data.Name`. The toolkit fails on them and only adds a `_grokparsefail_6504-0N` tag. On RD01 that is **130,759 PayloadData values** that native SOF-ELK would have kept.
- `winlog.payload.event_data.SystemTime`, `LoaderTime`, `OldTime` and `NewTime`: `8005` replaces the space with `T` so that Elasticsearch detects them as dates. The toolkit skips this and has date detection off, so they stay text.

### 3.4 Python < 3.11 cannot parse EZ Tools timestamps

**Fixed.** `parse_timestamp` now parses the ISO shapes itself, so Python 3.9, 3.10 and 3.13 give identical output on RD01. Empty or unparseable date values are left out and counted in a warning, instead of being sent as raw text. Original finding:

`parse_timestamp` relies on `datetime.fromisoformat`. Before Python 3.11 that function rejects the 7-digit fractional seconds that MFTECmd, PECmd and EvtxECmd write (`2023-01-23 06:51:25.5665168`). On Python 3.9 those values come back as `None`: `@timestamp` falls back to ingest time and the MACB fields are dropped by `ignore_malformed`. The README says Python 3.9+ is supported. The RD01 dry run used Python 3.13, where parsing works.

### 3.5 LECmd CSV: hex MFT references, extra blocks, arguments

- **Fixed** (RD01: 235 `file.target.inode`, 193 `file.target.sequence_number`). In LECmd CSV, `TargetMFTEntryNumber` and `TargetMFTSequenceNumber` are hex strings (`0x44EF2`). Native Ruby `Integer()` parses hex. The toolkit popped the value before `int()` fails, so **both fields are dropped** (235 of 294 RD01 shortcuts had a value). That removes the LNK→MFT pivot on `file.target.inode` = `file.inode`.
- **Fixed.** The CSV column is `ExtraBlocksPresent`. The importer only mapped the JSON name `ExtraBlocks_Present`, so `file.extra_blocks` is never written from CSV.
- `Arguments` is renamed to `file.target.path.arguments` and then overwritten when `file.target.path` is copied from `local_path` or `absolute_path`. **Both** pipelines therefore lose the command-line arguments. If there is no path to copy, natively `file.target.path` becomes an object and conflicts with its text mapping. The toolkit instead turns it into the JSON string `{"arguments":"..."}`. RD01 has 9 shortcuts with arguments.
- The toolkit maps `file.target.path` as `text` with no `.keyword`, so it cannot be used for `STATS ... BY` or exact match. Native gives it `.keyword`.

### 3.6 Other differences

- **Empty CSV cells are indexed as `""`.** JSON exports omit empty fields; CSV rows carry every column. In CSV mode the importers write `""` for every empty column (e.g. all MFT `file.reparse.target`, `file.fork_contents`; LECmd `file.target.network_path`). In ES|QL, `field IS NOT NULL` is true for those documents, so add `AND field != ""`.
- **`$Boot` and `$SDS` rows land in `filesystem`.** The `*_MFTECmd*_Output.*` glob matches `MFTECmd_$Boot_Output.csv` and `MFTECmd_$SDS_Output.csv`. Their 9,369 rows have none of the MFT fields, get `file.type: file`, `file.size: 0` and `@timestamp` = ingest time. The native Filebeat glob would do the same for JSON. Excluding them, or routing `$SDS` to its own index, would keep `filesystem` clean.
- **Host attribution.** Native Logstash removes `host.name` from Filebeat events (`1000-preprocess-all.conf`), so native KAPE documents can only be attributed by `log.file.path` or `winlog.computer_name`. The toolkit adds `host.name` (and `case`), via the bulk-hardening change. Keep `FROM ... METADATA _index` in queries regardless, because it works for both.

---

## 4. Artifacts without native SOF-ELK support

SOF-ELK has no parser, index template or Data View for anything else the toolkit ingests: `amcache`, `shimcache`, `registry`, `shellbag`, `jumplist`, `browsinghistory`, `recyclebin`, `recentfilecache`, `sqlitedb`, `srum`, `sum`, `activitiescache`, `clrusagelogs`. Those need the explicit custom templates. When they do, reuse the native names above for the concepts they share, so that a pivot works across indexes with the same field:

| Concept | Native field to reuse | Native type |
|---|---|---|
| Full path of the artifact's subject file | `file.path` (+ `file.directory`, `file.name`, `file.extension`) | text+keyword |
| Executable referenced by an execution artifact | `file.target.path` | text+keyword |
| File size | `file.size` | long |
| NTFS MFT entry / sequence | `file.inode` / `file.sequence_number` (target side: `file.target.inode`) | long |
| Volume serial | `volume.serial_number` | text+keyword |
| SHA-1 or other hash | `file.hash.sha1` (ECS; not used natively yet) | keyword |
| Source artifact path | `file.source_file` | text+keyword |
| Run count / last run | `kape.prefetch.run_count` / `kape.prefetch.last_run` pattern | long / date |
| Account SID / name | `user.id` / `user.name` | text+keyword |

Other native DFIR pipelines that the toolkit might target later: `plaso-*` (`6601-plaso.conf`), Hayabusa into `evtxlogs-*` (`6650-hayabusa.conf`), and Volatility into `volatility-*` (`6620`–`6625`).
