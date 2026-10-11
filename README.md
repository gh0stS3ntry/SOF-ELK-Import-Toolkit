# SOF-ELK Import Toolkit

This package contains a recursive wrapper and ten standalone Python importers for loading forensic CSV and JSON exports directly into Elasticsearch indexes used by SOF-ELK without relying on Logstash or Filebeat. The importers do not run KAPE, NirSoft, or Eric Zimmerman tools; they ingest exports that those tools have already produced.

## Contents

```text
sof_elk_all_importers/
├── SOF-ELK_ImportWrapper.py
├── README.md
├── csv_importers/
│   ├── nirsoft_bhv2sofelk.py
│   ├── jlecmd2sofelk.py
│   ├── sbecmd2sofelk.py
│   ├── amcache2sofelk.py
│   ├── shimcache2sofelk.py
│   └── recmd2sofelk.py
└── json_importers/
    ├── mftecmd2sofelk.py
    ├── evtxecmd2sofelk.py
    ├── lecmd2sofelk.py
    ├── pecmd2sofelk.py
    └── sof_elk_json_bulk_common.py
```

Requirements: Python 3.9+ and network access from the runtime to the Elasticsearch HTTP(S) endpoint. The scripts use Python's standard library; no `pip install` is required. Keep each script in its supplied folder. In particular, keep `sof_elk_json_bulk_common.py` beside the four JSON importers.

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

For an actual import, remove `--dry-run`:

```bash
python3 SOF-ELK_ImportWrapper.py /cases/IR-2026-042 WS01 --es http://localhost:9200
```

Wrapper options:

| Option | Purpose |
|---|---|
| `--es URL` | Elasticsearch base URL; defaults to `http://localhost:9200`. |
| `--user USER` / `--password PASSWORD` | Optional HTTP Basic authentication. |
| `--insecure` | Skip TLS certificate verification. Use only for a trusted endpoint. |
| `--batch-size N` | Documents per bulk request; default `2000`. |
| `--workers N` | Concurrent bulk workers for JSON importers; default `2`. |
| `--case ID` | Optional incident/case ID passed to importers that support it. |
| `--local-tz +HH:MM` | Offset used to convert KAPE CSV columns marked `LOCAL`; without it, such columns are generally retained as text. |
| `--bhv-tz +HH:MM\|UTC` | Offset for the computer that ran BrowsingHistoryView, or `UTC` if its GMT option was enabled. |
| `--date-order dmy\|mdy\|ymd` | Optional BrowsingHistoryView regional date order where it cannot be inferred. |
| `--dry-run` | Validate and preview records without sending them to Elasticsearch. |
| `--sample-docs N` | Number of transformed sample documents shown by each JSON importer in dry-run mode. |

The wrapper stages selected inputs using links when supported (falling back as needed) so it can invoke importers with the correct basenames and source-detection behavior. The staging directory is temporary and is removed after the run. The wrapper itself should remain at the package root so that it can locate both importer subdirectories.

## Index names and inputs

Index hostnames are normalized to lowercase because Elasticsearch index names must be lowercase. The defaults below can be overridden with `--index` when running a CSV importer directly. The JSON importers use their prescribed per-host index names.

| Script | Tool / evidence type | Input format | Default index |
|---|---|---|---|
| `csv_importers/nirsoft_bhv2sofelk.py` | NirSoft BrowsingHistoryView | CSV; also TXT/TSV | `browsinghistory-<hostname>` |
| `csv_importers/jlecmd2sofelk.py` | Eric Zimmerman JLECmd Jump Lists | CSV | `jumplist-<hostname>` |
| `csv_importers/sbecmd2sofelk.py` | Eric Zimmerman SBECmd ShellBags | CSV | `shellbag-<hostname>` |
| `csv_importers/amcache2sofelk.py` | Eric Zimmerman AmcacheParser | CSV | `amcache-<hostname>` |
| `csv_importers/shimcache2sofelk.py` | Eric Zimmerman AppCompatCacheParser / ShimCache | CSV | `shimcache-<hostname>` |
| `csv_importers/recmd2sofelk.py` | Eric Zimmerman RECmd batch and plugin results | CSV | `registry-<hostname>` |
| `json_importers/mftecmd2sofelk.py` | Eric Zimmerman MFTECmd | JSON / JSON.GZ | `filesystem-<hostname>` |
| `json_importers/evtxecmd2sofelk.py` | Eric Zimmerman EvtxECmd | JSON / JSON.GZ | `evtxlogs-<hostname>` |
| `json_importers/lecmd2sofelk.py` | Eric Zimmerman LECmd | JSON / JSON.GZ | `lnkfiles-<hostname>` |
| `json_importers/pecmd2sofelk.py` | Eric Zimmerman PECmd | JSON / JSON.GZ | `prefetch-<hostname>` |

The per-host index names are intended to be discovered by the corresponding Kibana wildcard Data Views, such as `filesystem-*`, `evtxlogs-*`, `lnkfiles-*`, `prefetch-*`, `registry-*`, `jumplist-*`, and so on. These per-host names intentionally differ from SOF-ELK's conventional monthly `base_index-YYYY.MM` Logstash output names.

## CSV importers: direct use

CSV importers do a type-inference pass before ingestion, convert recognized values, establish or extend mappings, and send documents through Elasticsearch's `_bulk` API. They retain the legacy source-specific fields and metadata from the original CSV scripts, but deliberately do not write the `forensic_tag` field in indexed documents. Source-specific classification may still be used internally by the importer.

All six accept one or more CSV files or directories, search directories recursively, and support `--hostname`, `--case`, `--index`, `--es`, `--batch-size`, `--user`, `--password`, `--insecure`, and `--dry-run`. The KAPE CSV importers also support `--local-tz`.

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

## JSON importers: direct use

The JSON importers implement the main field transformations in the corresponding SOF-ELK Logstash filters and shared preprocessing/postprocessing rules. They parse JSON incrementally, so they do not load an entire export into memory. Keep `sof_elk_json_bulk_common.py` alongside all four scripts. Accepted data files are `.json` and `.json.gz`. Input may be a top-level JSON array, a single JSON object, or a sequence of whitespace-separated/NDJSON objects. When a directory is supplied, a tool-specific filename pattern is used; an explicitly named JSON file may be accepted even when its name differs. PECmd timeline JSON is excluded.

The JSON importers support `--hostname`, `--es`, `--user`, `--password`, `--insecure`, `--batch-size`, `--workers`, `--dry-run`, and `--sample-docs`. Defaults are 2,000 documents per bulk request and two concurrent bulk workers. For a constrained SOF-ELK VM, begin with these defaults or use `--workers 1`, then increase gradually while monitoring Elasticsearch heap, CPU, disk I/O, and indexing rejections.

### 7. `mftecmd2sofelk.py`

Loads MFTECmd JSON into `filesystem-<hostname>`. Directory searches use MFTECmd output filename patterns, including `*_MFTECmd*_Output.json` and gzip equivalents. The importer transforms standard-information and filename MACB timestamps into `file.stdinfo.*` and `file.filename.*`, creates `file.name`, `file.path`, and `file.type`, translates `kape.mft.*`, converts NTFS attributes to boolean properties, handles alternate data streams, splits update reasons, and selects `@timestamp` from the most appropriate available MFT/USN time field.

Example:

```bash
python3 json_importers/mftecmd2sofelk.py /cases/IR-2026-042 --hostname WS01 --dry-run
python3 json_importers/mftecmd2sofelk.py /cases/IR-2026-042 --hostname WS01 --es http://localhost:9200
```

### 8. `evtxecmd2sofelk.py`

Loads EvtxECmd JSON into `evtxlogs-<hostname>`. Directory searches use `*_EvtxECmd_Output.json` and gzip equivalents. The importer maps Windows event fields to `winlog.*` and KAPE fields, parses `Payload` JSON, expands `EventData.Data` name/value pairs and the supported `PayloadDataN` values, maps UserData/Binary, copies the repository-specific `winlog.user.identifer` value to `user.id`, parses remote IP/port where possible, splits keywords, and constructs the summary `message`.

Example:

```bash
python3 json_importers/evtxecmd2sofelk.py /cases/IR-2026-042 --hostname WS01 --dry-run
python3 json_importers/evtxecmd2sofelk.py /cases/IR-2026-042 --hostname WS01 --workers 2
```

### 9. `lecmd2sofelk.py`

Loads LECmd JSON into `lnkfiles-<hostname>`. Directory searches use `*_LECmd_Output.json` and gzip equivalents. The importer maps source/origin and target timestamps and paths into the SOF-ELK `file.*` layout; applies local/absolute target path precedence; handles header flags, attributes, extra blocks, empty target times, and `(None)` drive type; converts target MFT entry/sequence numbers; and selects source LNK modification time for `@timestamp`.

Example:

```bash
python3 json_importers/lecmd2sofelk.py /cases/IR-2026-042 --hostname WS01 --dry-run
python3 json_importers/lecmd2sofelk.py /cases/IR-2026-042 --hostname WS01 --batch-size 3000 --workers 3
```

### 10. `pecmd2sofelk.py`

Loads PECmd JSON into `prefetch-<hostname>`. Directory searches use `*_PECmd_Output.json` and gzip equivalents. `*_PECmd_Output_Timeline.json` is deliberately excluded, since it is a flattened timeline view of records already represented by regular output. The importer maps Prefetch and executable fields, splits `Directories` and `FilesLoaded`, removes configured .NET unset sentinels, converts timestamps and numeric fields, merges supported `PreviousRunN` values into `prefetch.previous_runs`, builds the summary `message`, and chooses `@timestamp` from LastRun and then source file modification time.

Example:

```bash
python3 json_importers/pecmd2sofelk.py /cases/IR-2026-042 --hostname WS01 --dry-run
python3 json_importers/pecmd2sofelk.py /cases/IR-2026-042 --hostname WS01
```

## Shared field, timestamp, and index behavior

- CSV importers preserve the original importer field transformations and type/timestamp behavior where applicable. They omit `forensic_tag` from stored documents as requested. JSON importers reproduce source-specific Logstash transformations where implemented, with the JSON envelope fields available in their inputs.
- The evidence hostname is used to form each target index name. It is normalized to lowercase. The JSON importers do not automatically add `host.name` where the referenced Logstash pipeline removed Filebeat's `host.name` and did not replace it for that source type; check source-specific output if a host field is needed in queries.
- The scripts create an index if it does not exist, define explicit mappings for recognized non-string fields, and use dynamic string mappings. Existing mappings are checked before writing. For incompatible types, the CSV importers route the incompatible field to a `<field>_text` field. JSON importers report bulk indexing rejections and exit non-zero when any documents are rejected.
- JSON importers use deterministic document IDs based on host and stable file/record properties so rerunning the same exports overwrites the same logical documents. CSV importers also use deterministic IDs based on their source rows; the BrowsingHistoryView importer uses a counter to preserve identical rows.
- `--dry-run` previews parsing/transformation and prints sample documents but does not prove that a live Elasticsearch cluster will accept all mappings. Always test representative output from your installed tool versions before loading production evidence.

## Timestamp and data-quality cautions

1. **BrowsingHistoryView timezone:** use the timezone offset of the machine that ran the utility, unless its GMT/UTC export setting was enabled. This may not be the evidence host's timezone.
2. **Regional dates:** if all BrowsingHistoryView dates are ambiguous between day/month and month/day, supply `--date-order dmy` or `mdy` to match the exporting machine. Mixed/inconsistent formats are reported rather than silently guessed.
3. **KAPE LOCAL values:** provide `--local-tz +HH:MM` if columns explicitly marked LOCAL should be converted to UTC. Without an offset, those fields are retained as text where the importer specifies that behavior.
4. **Forensic time meaning:** a timestamp used as `@timestamp` is not necessarily an execution time. In particular, ShimCache's last-modified time is file metadata and not proof of program execution; Amcache timestamps can describe registry-key updates or installation activity rather than definitive execution.
5. **Source output differences:** filename clues and CSV headers can differ between utility versions and export settings. Run a dry run and inspect the output before live indexing.

## Authentication and TLS

The importers accept an Elasticsearch URL and optional HTTP Basic credentials. Use `--insecure` only if the endpoint is trusted and TLS certificate validation cannot be configured properly; it disables certificate checking. Be careful not to expose passwords in shell history or process listings on shared systems. For production, prefer a suitably scoped ingest account and secured transport.

## Validation status and limitations

The scripts have been checked using syntax/help and synthetic dry-run tests as described during their creation. No representative user-provided forensic export set or live Elasticsearch deployment was available for a field-by-field comparison and production-scale ingestion test. The implementations mirror the relevant SOF-ELK configuration and original importer logic, but do not reproduce every Filebeat runtime-only field, every Logstash parser-failure side effect, or every mapping outcome that can arise from heterogeneous source data. Validate each relevant tool format and timezone behavior before a production import.
