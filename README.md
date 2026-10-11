# SOF-ELK Import Toolkit

This package contains a recursive wrapper and sixteen standalone Python importers for loading forensic CSV and JSON exports directly into Elasticsearch indexes used by SOF-ELK without relying on Logstash or Filebeat. The importers do not run KAPE, NirSoft, or Eric Zimmerman tools; they ingest exports that those tools have already produced.

## Contents

```text
sof_elk_all_importers/
├── SOF-ELK_ImportWrapper.py
├── SOF-ELK_CreateDataViews.py
├── README.md
├── csv_importers/
│   ├── nirsoft_bhv2sofelk.py
│   ├── jlecmd2sofelk.py
│   ├── sbecmd2sofelk.py
│   ├── amcache2sofelk.py
│   ├── shimcache2sofelk.py
│   ├── rbcmd2sofelk.py
│   ├── recentfilecache2sofelk.py
│   ├── sqlecmd2sofelk.py
│   ├── srumecmd2sofelk.py
│   ├── sumecmd2sofelk.py
│   ├── wxtcmd2sofelk.py
│   └── recmd2sofelk.py
└── json_importers/
    ├── mftecmd2sofelk.py
    ├── evtxecmd2sofelk.py
    ├── lecmd2sofelk.py
    ├── pecmd2sofelk.py
    └── sof_elk_json_bulk_common.py
```

Requirements: Python 3.9+ and network access from the runtime to the Elasticsearch HTTP(S) endpoint. The scripts use Python's standard library; no `pip install` is required. Keep each script in its supplied folder. In particular, keep `sof_elk_json_bulk_common.py` beside the four importers in `json_importers/`, and keep `sof_elk_csv_bulk_common.py` beside the CSV importers if it is present in your package version.

## Quick start: use the wrapper

The wrapper accepts a root directory and evidence hostname. It searches that directory and its subdirectories, identifies supported input files, and calls the relevant standalone importer(s). It displays progress and child-process output on stdout, reports failures, continues attempting other discovered importer groups, and returns a non-zero final exit status if any import fails or is skipped.

Run a dry run first:

```bash
python3 SOF-ELK_ImportWrapper.py /cases/IR-2026-042 WS01 --dry-run
```

NirSoft BrowsingHistoryView exports need the timezone offset of the machine that ran BrowsingHistoryView. Supply it explicitly; the wrapper does not guess:

```bash
python3 SOF-ELK_ImportWrapper.py /cases/IR-2026-042 WS01 --bhv-tz +08:00 --date-order dmy --dry-run
```

For an actual import, remove `--dry-run` and specify your Elasticsearch endpoint when it is not the default:

```bash
python3 SOF-ELK_ImportWrapper.py /cases/IR-2026-042 WS01 --es http://192.168.233.128:9200
```

Wrapper options:

| Option | Purpose |
|---|---|
| `--es URL` | Elasticsearch base URL; defaults to `http://localhost:9200`. |
| `--user USER` / `--password PASSWORD` | Optional HTTP Basic authentication. |
| `--insecure` | Skip TLS certificate verification. Use only for a trusted endpoint. |
| `--batch-size N` | Documents per bulk request; default `2000`. |
| `--workers N` | Concurrent bulk workers; default `2`. |
| `--case ID` | Optional incident/case ID passed to importers that support it. |
| `--local-tz +HH:MM` | Offset used to convert KAPE CSV columns marked `LOCAL`; without it, such columns are generally retained as text. |
| `--bhv-tz +HH:MM\|UTC` | Offset for the computer that ran BrowsingHistoryView, or `UTC` if its GMT option was enabled. |
| `--date-order dmy\|mdy\|ymd` | Optional BrowsingHistoryView regional date order where it cannot be inferred. |
| `--dry-run` | Validate and preview records without sending them to Elasticsearch. |
| `--sample-docs N` | Number of transformed sample documents shown by each importer where supported in dry-run mode. |

The wrapper stages selected inputs using links when supported (falling back as needed) so it can invoke importers with the correct basenames and source-detection behavior. The staging directory is temporary and is removed after the run. The wrapper itself should remain at the package root so that it can locate both importer subdirectories.

## Index names and inputs

Index hostnames are normalized to lowercase because Elasticsearch index names must be lowercase. The defaults below can be overridden with `--index` when running a CSV importer directly. The four Eric Zimmerman importers in `json_importers/` also accept CSV in current versions, in addition to their original JSON/JSON.GZ formats.

| Script | Tool / evidence type | Input format | Default index |
|---|---|---|---|
| `csv_importers/nirsoft_bhv2sofelk.py` | NirSoft BrowsingHistoryView | CSV; also TXT/TSV | `browsinghistory-<hostname>` |
| `csv_importers/jlecmd2sofelk.py` | Eric Zimmerman JLECmd Jump Lists | CSV | `jumplist-<hostname>` |
| `csv_importers/sbecmd2sofelk.py` | Eric Zimmerman SBECmd ShellBags | CSV | `shellbag-<hostname>` |
| `csv_importers/amcache2sofelk.py` | Eric Zimmerman AmcacheParser | CSV | `amcache-<hostname>` |
| `csv_importers/shimcache2sofelk.py` | Eric Zimmerman AppCompatCacheParser / ShimCache | CSV | `shimcache-<hostname>` |
| `csv_importers/recmd2sofelk.py` | Eric Zimmerman RECmd batch and plugin results | CSV | `registry-<hostname>` |
| `csv_importers/rbcmd2sofelk.py` | Eric Zimmerman RBCmd | CSV | `recyclebin-<hostname>` |
| `csv_importers/recentfilecache2sofelk.py` | Eric Zimmerman RecentFileCacheParser | CSV | `recentfilecache-<hostname>` |
| `csv_importers/sqlecmd2sofelk.py` | Eric Zimmerman SQLECmd | CSV | `sqlitedb-<hostname>` |
| `csv_importers/srumecmd2sofelk.py` | Eric Zimmerman SrumECmd | CSV | `srum-<hostname>` |
| `csv_importers/sumecmd2sofelk.py` | Eric Zimmerman SumECmd | CSV | `sum-<hostname>` |
| `csv_importers/wxtcmd2sofelk.py` | Eric Zimmerman WxTCmd | CSV | `activitiescache-<hostname>` |
| `json_importers/mftecmd2sofelk.py` | Eric Zimmerman MFTECmd | JSON / JSON.GZ / CSV | `filesystem-<hostname>` |
| `json_importers/evtxecmd2sofelk.py` | Eric Zimmerman EvtxECmd | JSON / JSON.GZ / CSV | `evtxlogs-<hostname>` |
| `json_importers/lecmd2sofelk.py` | Eric Zimmerman LECmd | JSON / JSON.GZ / CSV | `lnkfiles-<hostname>` |
| `json_importers/pecmd2sofelk.py` | Eric Zimmerman PECmd | JSON / JSON.GZ / CSV | `prefetch-<hostname>` |

The per-host index names are intended to be discovered by the corresponding Kibana wildcard Data Views, such as `filesystem-*`, `evtxlogs-*`, `lnkfiles-*`, `prefetch-*`, `browsinghistory-*`, `jumplist-*`, `shellbag-*`, `amcache-*`, `shimcache-*`, `registry-*`, `recyclebin-*`, `recentfilecache-*`, `sqlitedb-*`, `srum-*`, `sum-*`, and `activitiescache-*`. These per-host names intentionally differ from SOF-ELK's conventional monthly `base_index-YYYY.MM` Logstash output names.

## CSV importers: direct use

CSV importers do a type-inference pass before ingestion, convert recognized values, establish or extend mappings, and send documents through Elasticsearch's `_bulk` API. They retain the source-specific fields and metadata implemented by the importer, but the legacy KAPE CSV importers deliberately do not write the `forensic_tag` field in indexed documents. Source-specific classification may still be used internally by the importer.

All twelve CSV importers accept an input file or directory, search directories recursively, and support `--hostname`, `--case`, `--es`, `--batch-size`, `--workers`, `--user`, `--password`, `--insecure`, `--dry-run`, and `--sample-docs`. The KAPE CSV importers also support `--local-tz` where applicable. Most CSV importers use source filename clues and/or characteristic CSV headers to recognize the appropriate output type.

### 1. `nirsoft_bhv2sofelk.py`

Loads NirSoft BrowsingHistoryView exports into `browsinghistory-<hostname>` by default. It detects UTF-8, UTF-8 BOM, UTF-16, or CP1252 encoding; comma, tab, or semicolon delimiters; and headerless exports. It infers boolean, integer, date, and string fields from the CSV values. It adds normalized `@timestamp`, `Visit_Time_local` when the chosen visit time is converted, `host.name`, `user.name` derived from User Profile when available, `url.domain` / `url.scheme`, `ingest.source_file`, `ingest.timestamp_source`, and optional `case` metadata. Document IDs are deterministic from the host and row content, with a counter to preserve identical rows while preventing duplicate records on a repeat import.

Timestamp interpretation must use the timezone of the machine that ran BrowsingHistoryView (unless its GMT option was enabled), not necessarily the suspect host. If date order is ambiguous, the script stops before live loading and asks for `--date-order` rather than guessing.

Example:

```bash
python3 csv_importers/nirsoft_bhv2sofelk.py /cases/IR-2026-042/BrowsingHistory.csv --hostname WS01 --tz +08:00 --dry-run
python3 csv_importers/nirsoft_bhv2sofelk.py /cases/IR-2026-042/BrowsingHistory.csv --hostname WS01 --tz +08:00
```

### 2. `jlecmd2sofelk.py`

Loads JLECmd AutomaticDestinations and CustomDestinations CSV outputs into `jumplist-<hostname>`. It identifies Automatic versus Custom Jump Lists primarily from the filename and also considers CSV headers. It infers field types, normalizes EZ Tools timestamps, chooses a per-row `@timestamp` using the original FileFolderAccess priorities, extracts `user.name` from `SourceFile` paths where possible, and adds `kape.source_file`, `kape.timestamp_source`, and optional `case`. LOCAL time columns remain text unless `--local-tz` is supplied. The script merges same-named columns to a compatible type across both Jump List variants and stores conflicting values as strings. Stable IDs allow re-importing the same rows without duplication.

Examples:

```bash
python3 csv_importers/jlecmd2sofelk.py /cases/IR-2026-042/FileFolderAccess --hostname WS01 --dry-run
python3 csv_importers/jlecmd2sofelk.py /cases/IR-2026-042/FileFolderAccess --hostname WS01
```

Expected filename clues include `*_AutomaticDestinations.csv` and `*_CustomDestinations.csv`; field headers are also used to recognize the content.

### 3. `sbecmd2sofelk.py`

Loads SBECmd ShellBags CSV outputs into `shellbag-<hostname>`. It detects ShellBags by characteristic fields such as `BagPath`, or `AbsolutePath` together with `ShellType`, and can also use an SBECmd filename clue. It infers types and timestamp values, extracts a user name from `SourceFile` paths or filenames when available, and adds `host.name`, `kape.source_file`, `kape.timestamp_source`, and optional `case`. It supports `--local-tz`, dry-run preview, compatible mapping updates, and stable document IDs.

Example:

```bash
python3 csv_importers/sbecmd2sofelk.py /cases/IR-2026-042/ShellBags --hostname WS01 --dry-run
python3 csv_importers/sbecmd2sofelk.py /cases/IR-2026-042/ShellBags --hostname WS01
```

SBECmd filenames can vary by export workflow, so ensure its CSV headers identify the output correctly.

### 4. `amcache2sofelk.py`

Loads AmcacheParser section CSVs into `amcache-<hostname>`. It recognizes section names in timestamp-prefixed filenames such as `*_Amcache_ProgramEntries.csv`, `*_Amcache_AssociatedFileEntries.csv`, and `*_Amcache_UnassociatedFileEntries.csv`, while also inspecting characteristic headers. Fields are typed from source values; incompatible types found across Amcache sections are handled as strings. Timestamps are normalized, with `@timestamp` selected by section, and `kape.source_file`, `kape.timestamp_source`, `host.name`, and optional `case` are added. `--local-tz` controls how columns explicitly marked LOCAL are interpreted.

Example:

```bash
python3 csv_importers/amcache2sofelk.py /cases/IR-2026-042/ProgramExecution --hostname WS01 --dry-run
python3 csv_importers/amcache2sofelk.py /cases/IR-2026-042/ProgramExecution --hostname WS01
```

### 5. `shimcache2sofelk.py`

Loads AppCompatCacheParser / ShimCache CSVs into `shimcache-<hostname>`. It recognizes filename clues such as `AppCompatCache` or `ShimCache` and characteristic headers such as `CacheEntryPosition` and `LastModifiedTimeUTC`. Timestamp fields are normalized where recognized, and the importer adds the host and KAPE source metadata. This importer treats the chosen event time as the file metadata time represented by ShimCache; it should not be interpreted as proof that a program executed at that time.

Example:

```bash
python3 csv_importers/shimcache2sofelk.py /cases/IR-2026-042/ProgramExecution --hostname WS01 --dry-run
python3 csv_importers/shimcache2sofelk.py /cases/IR-2026-042/ProgramExecution --hostname WS01
```

### 6. `recmd2sofelk.py`

Loads RECmd batch output and plugin-detail CSVs into `registry-<hostname>`. It derives plugin tags and, where present, hive information from the filename after removing the KAPE timestamp prefix. It infers types per plugin and reconciles them across the common index; disagreements become strings to avoid index mapping conflicts. It converts EZ Tools timestamps to ISO 8601, selects a suitable date field for `@timestamp`, and adds `kape.source_file`, optional `kape.source_hive`, `kape.timestamp_source`, `host.name`, and optional `case`. LOCAL timestamp fields remain text unless `--local-tz` is supplied. Stable IDs make repeat imports idempotent for the same file and row.

Examples:

```bash
python3 csv_importers/recmd2sofelk.py /cases/IR-2026-042/Registry --hostname WS01 --dry-run
python3 csv_importers/recmd2sofelk.py /cases/IR-2026-042/Registry --hostname WS01
```

Filename examples include `*_RECmd_Batch_Kroll_Batch_Output.csv` and timestamp-prefixed plugin files such as `*_UserAssist__C_Users_bob_NTUSER.DAT.csv`. The script derives plugin/hive metadata from the actual filename pattern; confirm files from your tool version with a dry run.

### 7. `rbcmd2sofelk.py`

Loads RBCmd CSV output into `recyclebin-<hostname>`. The importer uses RBCmd/Recycle Bin filename clues and characteristic deletion-related columns to select input, then infers compatible Elasticsearch field types, normalizes recognized timestamps, and adds source/host/case metadata supported by the common CSV ingestion layer. The primary `@timestamp` candidates are deletion-related timestamps, followed by a generic `Timestamp` or `SourceCreated` field when present.

Example:

```bash
python3 csv_importers/rbcmd2sofelk.py /cases/IR-2026-042/RecycleBin --hostname WS01 --dry-run
python3 csv_importers/rbcmd2sofelk.py /cases/IR-2026-042/RecycleBin --hostname WS01
```

Expected filename clues include names containing `RBCmd` or `RecycleBin`.

### 8. `recentfilecache2sofelk.py`

Loads RecentFileCacheParser CSV output into `recentfilecache-<hostname>`. It identifies files using RecentFileCache/RecentFileCacheParser filename clues and characteristic columns such as `SourceFile`, `SourceModified`, and file-name collections. Recognized timestamps are normalized, with `SourceModified`, `SourceCreated`, `SourceAccessed`, and then a generic `Timestamp` used as preferred time candidates.

Example:

```bash
python3 csv_importers/recentfilecache2sofelk.py /cases/IR-2026-042/RecentFileCache --hostname WS01 --dry-run
python3 csv_importers/recentfilecache2sofelk.py /cases/IR-2026-042/RecentFileCache --hostname WS01
```

### 9. `sqlecmd2sofelk.py`

Loads SQLECmd SQLite-report CSV output into `sqlitedb-<hostname>`. Because SQLECmd output varies with the SQLite map/report, the importer uses both filename clues and characteristic columns such as `SourceFile`, `Query`, `Database`, and `Table`. Timestamp candidates are `Timestamp`, `LastWriteTime`, `LastModified`, `Modified`, `Created`, and `Accessed`, in that order.

Example:

```bash
python3 csv_importers/sqlecmd2sofelk.py /cases/IR-2026-042/SQLite --hostname WS01 --dry-run
python3 csv_importers/sqlecmd2sofelk.py /cases/IR-2026-042/SQLite --hostname WS01
```

### 10. `srumecmd2sofelk.py`

Loads SrumECmd CSV reports into `srum-<hostname>`. It identifies SrumECmd output from the filename or characteristic SRUM columns such as `Id`, `Timestamp`, `ExeInfo`, `UserId`, `AppId`, `BytesReceived`, `BytesSent`, or `NetworkType`. Preferred time candidates include `Timestamp`, `EventTimestamp`, `StartTime`, `EndTime`, `ConnectedTime`, and `ConnectStartTime`.

Example:

```bash
python3 csv_importers/srumecmd2sofelk.py /cases/IR-2026-042/SRUM --hostname WS01 --dry-run
python3 csv_importers/srumecmd2sofelk.py /cases/IR-2026-042/SRUM --hostname WS01
```

### 11. `sumecmd2sofelk.py`

Loads SumECmd / User Access Logging CSV output into `sum-<hostname>`. Filename clues are the primary recognition method because SUM output schemas vary by report mode. Preferred timestamp candidates are `Timestamp`, `LastAccessTime`, `LastAccessed`, `LastUsed`, `LastModified`, and `Created`.

Example:

```bash
python3 csv_importers/sumecmd2sofelk.py /cases/IR-2026-042/SUM --hostname WS01 --dry-run
python3 csv_importers/sumecmd2sofelk.py /cases/IR-2026-042/SUM --hostname WS01
```

### 12. `wxtcmd2sofelk.py`

Loads WxTCmd Windows Timeline CSV output into `activitiescache-<hostname>`. It recognizes WxTCmd output using filename clues such as `WxTCmd`, `ActivityOperations`, or `ActivityPackage`, and characteristic columns such as `Id`, `ActivityTypeOrg`, `ActivityType`, `Executable`, and `StartTime`. Preferred timestamp candidates are `StartTime`, `LastModifiedTime`, `CreatedTime`, `EndTime`, `ExpirationTime`, and `Timestamp`.

Example:

```bash
python3 csv_importers/wxtcmd2sofelk.py /cases/IR-2026-042/WindowsTimeline --hostname WS01 --dry-run
python3 csv_importers/wxtcmd2sofelk.py /cases/IR-2026-042/WindowsTimeline --hostname WS01
```

WxTCmd can emit multiple related CSV report types, so inspect the dry-run discovery summary to confirm that the intended files were selected.

## JSON importers: direct use

The four importers under `json_importers/` implement the main field transformations in the corresponding SOF-ELK Logstash filters and shared preprocessing/postprocessing rules. In current versions they can ingest both the original JSON/JSON.GZ exports and corresponding CSV outputs. JSON input is parsed incrementally, so a whole export does not need to be loaded into memory. Keep `sof_elk_json_bulk_common.py` alongside all four scripts.

Accepted JSON data files are `.json` and `.json.gz`. JSON input may be a top-level JSON array, a single JSON object, or a sequence of whitespace-separated/NDJSON objects. For CSV input, the scripts use the shared CSV bulk helper and the same index and host conventions as their JSON path. When a directory is supplied, a tool-specific filename pattern is used for JSON files; CSV discovery is format-aware and header-aware. PECmd timeline JSON is excluded.

The four importers support `--hostname`, `--es`, `--user`, `--password`, `--insecure`, `--batch-size`, `--workers`, `--dry-run`, and `--sample-docs`. For CSV paths, `--case` and `--local-tz` are also available where supported by the shared CSV ingestion layer.

### 13. `mftecmd2sofelk.py`

Loads MFTECmd JSON or CSV into `filesystem-<hostname>`. JSON directory searches use MFTECmd output filename patterns, including `*_MFTECmd*_Output.json` and gzip equivalents; CSV discovery also accepts MFTECmd output CSVs. The importer transforms standard-information and filename MACB timestamps into `file.stdinfo.*` and `file.filename.*`, creates `file.name`, `file.path`, and `file.type`, translates `kape.mft.*`, converts NTFS attributes to boolean properties, handles alternate data streams, splits update reasons, and selects `@timestamp` from the most appropriate available MFT/USN time field.

Example:

```bash
python3 json_importers/mftecmd2sofelk.py /cases/IR-2026-042 --hostname WS01 --dry-run
python3 json_importers/mftecmd2sofelk.py /cases/IR-2026-042 --hostname WS01 --es http://localhost:9200
```

### 14. `evtxecmd2sofelk.py`

Loads EvtxECmd JSON or CSV into `evtxlogs-<hostname>`. JSON directory searches use `*_EvtxECmd_Output.json` and gzip equivalents; CSV discovery also accepts EvtxECmd output CSVs. The importer maps Windows event fields to `winlog.*` and KAPE fields, parses `Payload` JSON where present, expands supported event-data values, maps UserData/Binary, copies the repository-specific `winlog.user.identifer` value to `user.id` where present, parses remote IP/port where possible, splits keywords, and constructs the summary `message`.

Heterogeneous `UserData.EventData` values are normalized to a consistent text representation before indexing so object/string variations do not create Elasticsearch mapping conflicts.

Example:

```bash
python3 json_importers/evtxecmd2sofelk.py /cases/IR-2026-042 --hostname WS01 --dry-run
python3 json_importers/evtxecmd2sofelk.py /cases/IR-2026-042 --hostname WS01 --workers 2
```

### 15. `lecmd2sofelk.py`

Loads LECmd JSON or CSV into `lnkfiles-<hostname>`. JSON directory searches use `*_LECmd_Output.json` and gzip equivalents; CSV discovery also accepts LECmd output CSVs. The importer maps source/origin and target timestamps and paths into the SOF-ELK `file.*` layout; applies local/absolute target path precedence; handles header flags, attributes, extra blocks, empty target times, and `(None)` drive type; converts target MFT entry/sequence numbers; and selects source LNK modification time for `@timestamp`.

Non-string target structures, including argument-only targets, are normalized before indexing so `file.target.path` remains compatible with the existing Elasticsearch text mapping.

Example:

```bash
python3 json_importers/lecmd2sofelk.py /cases/IR-2026-042 --hostname WS01 --dry-run
python3 json_importers/lecmd2sofelk.py /cases/IR-2026-042 --hostname WS01 --batch-size 3000 --workers 3
```

### 16. `pecmd2sofelk.py`

Loads PECmd JSON or CSV into `prefetch-<hostname>`. JSON directory searches use `*_PECmd_Output.json` and gzip equivalents; CSV discovery also accepts PECmd output CSVs. `*_PECmd_Output_Timeline.json` and its CSV equivalent are deliberately excluded, since they are flattened timeline views of records already represented by regular output. The importer maps Prefetch and executable fields, splits `Directories` and `FilesLoaded`, removes configured .NET unset sentinels, converts timestamps and numeric fields, merges supported `PreviousRunN` values into `prefetch.previous_runs`, builds the summary `message`, and chooses `@timestamp` from LastRun and then source file modification time.

Example:

```bash
python3 json_importers/pecmd2sofelk.py /cases/IR-2026-042 --hostname WS01 --dry-run
python3 json_importers/pecmd2sofelk.py /cases/IR-2026-042 --hostname WS01
```

## Shared field, timestamp, and index behavior

- CSV importers preserve the source-specific field transformations and type/timestamp behavior implemented for each importer. The original KAPE-derived CSV importers omit `forensic_tag` from stored documents as requested. The four JSON/CSV hybrid importers preserve their source-specific Logstash-derived transformations where implemented.
- The evidence hostname is used to form each target index name. It is normalized to lowercase because Elasticsearch index names must be lowercase.
- The scripts create an index if it does not exist, define explicit mappings for recognized non-string fields, and use dynamic string mappings. Existing mappings are checked before writing. CSV importers route incompatible field types to `<field>_text` where supported. JSON/CSV hybrid importers report bulk indexing rejections and exit non-zero when any documents are rejected.
- Importers use deterministic document IDs based on host and stable file/record properties so rerunning the same exports does not create duplicate logical documents. BrowsingHistoryView additionally uses a counter to preserve identical rows.
- `--dry-run` previews parsing/transformation and prints sample documents, but it does not prove that a live Elasticsearch cluster will accept every mapping. Always test representative output from your installed tool versions before loading production evidence.

## Timestamp and data-quality cautions

1. **BrowsingHistoryView timezone:** use the timezone offset of the machine that ran the utility, unless its GMT/UTC export setting was enabled. This may not be the evidence host's timezone.
2. **Regional dates:** if BrowsingHistoryView dates are ambiguous between day/month and month/day, supply `--date-order dmy` or `mdy` to match the exporting machine. Mixed/inconsistent formats are reported rather than silently guessed.
3. **KAPE LOCAL values:** provide `--local-tz +HH:MM` if columns explicitly marked LOCAL should be converted to UTC. Without an offset, those fields are retained as text where the importer specifies that behavior.
4. **Forensic time meaning:** a timestamp used as `@timestamp` is not necessarily an execution time. In particular, ShimCache's last-modified time is file metadata and not proof of program execution; Amcache timestamps can describe registry-key updates or installation activity rather than definitive execution.
5. **Source output differences:** filename clues and CSV headers can differ between utility versions and export settings. Run a dry run and inspect the discovery summary and transformed sample documents before live indexing.
6. **Mixed JSON/CSV runs:** the wrapper can discover different formats for the same tool. Avoid supplying duplicate exports of the same evidence unless you intentionally want the deterministic ID behavior to reconcile/reload them.

## Authentication and TLS

The importers accept an Elasticsearch URL and optional HTTP Basic credentials. Use `--insecure` only if the endpoint is trusted and TLS certificate validation cannot be configured properly; it disables certificate checking. Be careful not to expose passwords in shell history or process listings on shared systems. For production, prefer a suitably scoped ingest account and secured transport.

## Kibana Data View creator

`SOF-ELK_CreateDataViews.py` creates the twelve Kibana Data Views that are not included out-of-box in the stock SOF-ELK distribution but are required for the additional direct-import indexes used by this package:

| Script / data source | Kibana Data View | Indexes created by importer |
|---|---|---|
| NirSoft BrowsingHistoryView | `browsinghistory-*` | `browsinghistory-<hostname>` |
| JLECmd | `jumplist-*` | `jumplist-<hostname>` |
| SBECmd | `shellbag-*` | `shellbag-<hostname>` |
| AmcacheParser | `amcache-*` | `amcache-<hostname>` |
| AppCompatCacheParser / ShimCache | `shimcache-*` | `shimcache-<hostname>` |
| RECmd | `registry-*` | `registry-<hostname>` |
| RBCmd | `recyclebin-*` | `recyclebin-<hostname>` |
| RecentFileCacheParser | `recentfilecache-*` | `recentfilecache-<hostname>` |
| SQLECmd | `sqlitedb-*` | `sqlitedb-<hostname>` |
| SrumECmd | `srum-*` | `srum-<hostname>` |
| SumECmd | `sum-*` | `sum-<hostname>` |
| WxTCmd | `activitiescache-*` | `activitiescache-<hostname>` |

The script deliberately does not create the `filesystem-*`, `evtxlogs-*`, `lnkfiles-*`, or `prefetch-*` Data Views because those are already available in SOF-ELK out-of-box.

The script uses Kibana's Data Views API and is standard-library only. By default it is idempotent: an existing Data View is detected and left unchanged. Use `--overwrite` to delete and recreate the twelve managed views. The Data Views are configured to use `@timestamp` as the time field and `allowNoIndex=true`, so they can be created before the first corresponding Elasticsearch index exists.

### Usage

Preview the twelve Data Views without modifying Kibana:

```bash
python3 SOF-ELK_CreateDataViews.py --dry-run
```

Create them on the local Kibana instance:

```bash
python3 SOF-ELK_CreateDataViews.py
```

Specify a Kibana URL:

```bash
python3 SOF-ELK_CreateDataViews.py --kibana https://kibana.example.com
```

Use HTTP Basic authentication when required:

```bash
python3 SOF-ELK_CreateDataViews.py \
    --kibana https://kibana.example.com \
    --user elastic \
    --password 'your-password'
```

For a Kibana endpoint using a certificate that cannot be verified by the local Python trust store, use `--insecure`:

```bash
python3 SOF-ELK_CreateDataViews.py \
    --kibana https://kibana.example.com \
    --insecure
```

Force recreation of the twelve managed Data Views:

```bash
python3 SOF-ELK_CreateDataViews.py --overwrite
```

### Options

- `--kibana URL`: Kibana base URL. Default: `http://localhost:5601`.
- `--user USER`: HTTP Basic authentication username.
- `--password PASSWORD`: HTTP Basic authentication password.
- `--insecure`: disable TLS certificate verification.
- `--overwrite`: delete and recreate the twelve managed Data Views if they already exist.
- `--dry-run`: display the Data Views that would be managed without making API changes.

Run the Data View creator after Kibana is available and before using the corresponding indexes in Discover. Because `allowNoIndex` is enabled, it is also safe to create the Data Views before the direct-import scripts have created their first host-specific indexes.

## Efficiency and Big-O considerations

The wrapper's filesystem discovery is linear in the number of filesystem entries visited, `O(F)`. CSV parsing and transformation are linear in the total input size and number of rows, `O(S)`, and JSON parsing is linear in total JSON bytes, also `O(S)`, assuming bounded individual record size.

Bulk ingestion reduces the number of Elasticsearch HTTP requests from approximately one request per document to `O(ceil(N/B))` requests, where `N` is the number of documents and `B` is the bulk batch size. The importers keep working memory bounded by the largest individual record plus the configured batches and concurrent workers, rather than loading an entire evidence export into RAM.

The wrapper walks the directory tree once and classifies files from lightweight filename/header checks before invoking the importers. It therefore avoids running every importer against every file. The direct Elasticsearch architecture also avoids the additional filebeat/Logstash processing path used by the stock SOF-ELK ingestion workflow.

For large evidence collections, start with the default `--batch-size 2000` and `--workers 2`, then increase gradually while monitoring Elasticsearch CPU, heap, disk I/O, rejected writes, and bulk request latency. A very large batch can reduce HTTP overhead but increase transient memory consumption and the cost of a failed request; more workers increase parallelism but can saturate a small SOF-ELK VM.

## Validation status and limitations

The toolkit has been checked using Python syntax/help tests, synthetic dry-run tests, wrapper discovery tests, and archive integrity checks during development. Real-world testing has also exposed heterogeneous EVTX and LECmd values, which are normalized in the current hybrid importers before Elasticsearch indexing. No claim is made that every output schema from every version/configuration of every forensic utility will be identical to the tested samples.

No full production-scale comparison against a live stock SOF-ELK Logstash pipeline has been performed for every source. The direct importers mirror the relevant SOF-ELK configurations and the previously developed source-specific importer logic, but they do not reproduce every Filebeat runtime-only field, every Logstash parser-failure side effect, or every possible mapping outcome from heterogeneous third-party output. Validate the exact tool versions, export settings, filenames, headers, timestamps, and mappings used in your environment before loading production evidence.
