# SOF-ELK Import Toolkit

This package contains a recursive wrapper and seventeen standalone Python importers for Windows forensic artifacts, four importers for AWS logs (CloudTrail, VPC Flow Logs, ALB/ELB access logs and AWS WAF; see [`AWS/README.md`](AWS/README.md)), a generic CSV importer for any other CSV export ([`Generic-CSV/README.md`](Generic-CSV/README.md)), Linux importers for the systemd journal, text syslog, web server logs, browser history and FTP logs in UAC collections and collected root filesystems ([`Linux/README.md`](Linux/README.md)), and an ES|QL hunting pack with checklists ([`hunting/`](hunting/README.md)), for loading forensic CSV and JSON exports directly into Elasticsearch indexes used by SOF-ELK without relying on Logstash or Filebeat. The importers do not run KAPE, NirSoft, or Eric Zimmerman tools; they ingest exports that those tools have already produced.

## Contents

```text
sof_elk_all_importers/
├── SOF-ELK_ImportWrapper.py
├── SOF-ELK_CreateDataViews.py
├── SOF-ELK_DeleteIndexes.py
├── SOF-ELK_ConfigureRemoteIngest.sh
├── Install-ForensicELK.ps1
├── README.md
├── Windows
│   ├── common/
│   │   └── sof_elk_es_client.py
│   ├── csv_importers/
│   │   ├── nirsoft_bhv2sofelk.py
│   │   ├── jlecmd2sofelk.py
│   │   ├── sbecmd2sofelk.py
│   │   ├── amcache2sofelk.py
│   │   ├── shimcache2sofelk.py
│   │   ├── rbcmd2sofelk.py
│   │   ├── recentfilecache2sofelk.py
│   │   ├── sqlecmd2sofelk.py
│   │   ├── srumecmd2sofelk.py
│   │   ├── sumecmd2sofelk.py
│   │   ├── wxtcmd2sofelk.py
│   │   ├── recmd2sofelk.py
│   │   ├── clrusagelogs2sofelk.py
│   │   ├── sof_elk_csv_bulk_common.py
│   │   ├── sof_elk_index_templates.py
│   │   └── sof_elk_template_importer.py
│   ├── index_templates/
│   │   ├── component-toolkit-common.json
│   │   ├── index-amcache.json
│   │   ├── index-jumplist.json
│   │   ├── index-registry.json
│   │   ├── index-shellbag.json
│   │   └── index-shimcache.json
│   └── json_importers/
│       ├── mftecmd2sofelk.py
│       ├── evtxecmd2sofelk.py
│       ├── lecmd2sofelk.py
│       ├── pecmd2sofelk.py
│       └── sof_elk_json_bulk_common.py
├── AWS
│   ├── cloudtrail2sofelk.py
│   ├── vpcflow2sofelk.py
│   ├── alb2sofelk.py
│   ├── waf2sofelk.py
│   ├── sof_elk_aws_common.py
│   ├── index_templates/
│   ├── tests/
│   └── README.md
├── Generic-CSV
│   ├── genericcsv2sofelk.py
│   ├── index_templates/
│   │   └── index-genericcsv.json
│   ├── tests/
│   └── README.md
├── Linux
│   ├── linux2sofelk.py      (runs every Linux importer on one collection)
│   ├── journal2sofelk.py
│   ├── syslog2sofelk.py
│   ├── httpd2sofelk.py
│   ├── browser2sofelk.py
│   ├── vsftpd2sofelk.py
│   ├── common/
│   │   ├── sof_elk_linux_common.py
│   │   └── sof_elk_linux_messages.py
│   ├── index_templates/
│   ├── tests/
│   └── README.md
├── sof-elk-templates/     (SOF-ELK's native index templates, loaded by Install-ForensicELK.ps1)
├── sof-elk-kibana/        (SOF-ELK's out-of-box Data Views and Kibana defaults, used by SOF-ELK_CreateDataViews.py)
├── docs/schemas/
└── hunting/
    ├── queries/          (Windows queries by tactic; AWS queries under queries/aws/)
    ├── checklists/
    └── tools/
```

Requirements: Python 3.9+ and network access from the runtime to the Elasticsearch HTTP(S) endpoint. The scripts use Python's standard library; no `pip install` is required. Keep each script in its supplied folder. Every importer loads the shared Elasticsearch client from `Windows/common/sof_elk_es_client.py`, so keep `common/` beside `csv_importers/` and `json_importers/`. Also keep `sof_elk_json_bulk_common.py` beside the four importers in `json_importers/`, and keep `sof_elk_csv_bulk_common.py` beside the CSV importers in `csv_importers/` (the RecentFileCacheParser, SQLECmd, and SumECmd importers require it). The AWS, generic CSV and Linux importers load the same client from `Windows/common/`, so keep `AWS/`, `Generic-CSV/`, `Linux/` and `Windows/` side by side.

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
| `--workers N` | Concurrent bulk workers; default `2`. Passed to the four JSON importers only. |
| `--case ID` | Optional incident/case ID passed to every importer and stored in each document's `case` field. |
| `--local-tz +HH:MM` | Offset used to convert KAPE CSV columns marked `LOCAL`; without it, such columns are generally retained as text. Passed to every CSV importer except BrowsingHistoryView (which uses `--bhv-tz`) and the CLR usage-log importer (which has no LOCAL columns). |
| `--bhv-tz +HH:MM\|UTC` | Offset for the computer that ran BrowsingHistoryView, or `UTC` if its GMT option was enabled. |
| `--date-order dmy\|mdy\|ymd` | Optional BrowsingHistoryView regional date order where it cannot be inferred. |
| `--dry-run` | Validate and preview records without sending them to Elasticsearch. |
| `--sample-docs N` | Number of transformed sample documents shown in dry-run mode. Passed to the four JSON importers only. |
| `--max-retries N` | Retries for a failed Elasticsearch request or a rejected bulk item; default `5`, `0` disables retrying. Passed to every importer. |
| `--retry-backoff SECONDS` | Base delay for exponential backoff between retries; default `2`. Passed to every importer. |
| `--timeout SECONDS` | Time to wait for each Elasticsearch HTTP response; default `300`. Passed to every importer. |
| `--log-file PATH` | Append every importer's command line, retries, per-batch bulk results, and item-level errors to this file. Passed to every importer. |

**Linux (UAC) collections.** The wrapper also recognises UAC output, either a folder holding `uac.log` (with `[root]/`, `journal/`, `live_response/` or `bodyfile/` beside it) or a `.zip` with `uac.log` at its top, and runs `Linux/linux2sofelk.py` on each collection with the wrapper's host name, `--case`, Elasticsearch, retry, log and dry-run options. `--local-tz` is not passed: the Linux importers read the time zone from the evidence. A UAC collection is not searched for Windows exports. If a collection has binary journal files but no `journalctl -o json` export, that collection is reported as failed (exit status `3`) with the commands to make the export; see [`Linux/README.md`](Linux/README.md).

The wrapper stages selected inputs using links when supported (falling back as needed) so it can invoke importers with the correct basenames and source-detection behavior. The staging directory is temporary and is removed after the run. The wrapper itself should remain at the package root so that it can locate both importer subdirectories.

## Index names and inputs

Hostnames are normalized the same way by every importer: lowercased (Elasticsearch index names must be lowercase), with any run of characters other than `a-z`, `0-9`, `.`, `_`, and `-` replaced by `-`, and leading/trailing `.`, `_`, `-` removed. For example, `WS 01` becomes `ws-01`. The normalized name is used in the index name and in every document's `host.name`. Every importer writes one index per evidence host, named `<prefix>-<hostname>`. When running the JLECmd, SBECmd, AmcacheParser, ShimCache, RECmd, or BrowsingHistoryView importer directly, `--index` can change the prefix, but the name must still end in `-<hostname>` (for example `amcache-test-ws01` for host `WS01`); any other value is rejected. The other importers always use the default. The four Eric Zimmerman importers in `json_importers/` also accept CSV in current versions, in addition to their original JSON/JSON.GZ formats.

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
| `Linux/journal2sofelk.py` | systemd journal (`journalctl -o json` export) | JSON lines | `logstash-<hostname>` (`event.dataset` `syslog.journal`) |
| `Linux/syslog2sofelk.py` | text syslog under `/var/log` (Debian, RHEL, SUSE and Alpine layouts, rotated and compressed) | text | `logstash-<hostname>` (`event.dataset` `syslog.file`) |
| `Linux/httpd2sofelk.py` | Apache httpd, nginx and lighttpd access and error logs | text | `httpdlog-<hostname>` (`event.dataset` `apache.access`, `nginx.error`, ...) |
| `Linux/browser2sofelk.py` | Firefox and Chromium-family history and downloads | SQLite | `browsinghistory-<hostname>` (`event.dataset` `browsinghistory`, `browsinghistory.download`) |
| `Linux/vsftpd2sofelk.py` | vsftpd and xferlog FTP server logs | text | `logstash-<hostname>` (`event.dataset` `ftp.vsftpd`, `ftp.xferlog`) |

The per-host index names are intended to be discovered by the corresponding Kibana wildcard Data Views, such as `filesystem-*`, `evtxlogs-*`, `lnkfiles-*`, `prefetch-*`, `browsinghistory-*`, `jumplist-*`, `shellbag-*`, `amcache-*`, `shimcache-*`, `registry-*`, `recyclebin-*`, `recentfilecache-*`, `sqlitedb-*`, `srum-*`, `sum-*`, and `activitiescache-*`, and `clrusagelogs-*`. These per-host names intentionally differ from SOF-ELK's conventional monthly `base_index-YYYY.MM` Logstash output names.

## CSV importers: direct use

CSV importers do a type-inference pass before ingestion, convert recognized values, establish or extend mappings, and send documents through Elasticsearch's `_bulk` API. They retain the source-specific fields and metadata implemented by the importer, but the legacy KAPE CSV importers deliberately do not write the `forensic_tag` field in indexed documents. Source-specific classification may still be used internally by the importer.

All thirteen CSV importers accept an input file or directory, search directories recursively, and support `--hostname`, `--case`, `--es`, `--batch-size`, `--user`, `--password`, `--insecure`, `--dry-run`, and the retry/logging options described under [Retries and logging](#retries-and-logging). The remaining options differ by importer:

| Importer(s) | Inputs | Additional options |
|---|---|---|
| `jlecmd`, `sbecmd`, `amcache`, `shimcache`, `recmd`, `rbcmd`, `srumecmd`, `wxtcmd` | one or more files/folders | `--index`, `--local-tz` |
| `nirsoft_bhv` | one or more files/folders | `--index`, `--tz` (required), `--date-order` |
| `recentfilecache`, `sqlecmd`, `sumecmd` | one file or folder | `--local-tz`, `--workers`, `--sample-docs` |
| `clrusagelogs` | one file or folder | `--sample-docs` |

Most CSV importers use source filename clues and/or characteristic CSV headers to recognize the appropriate output type. When given a folder, the RecentFileCacheParser and SQLECmd importers select a CSV if its filename contains a tool clue or its header matches the same signature the wrapper uses; SumECmd relies on filename clues only.

### 1. `nirsoft_bhv2sofelk.py`

Loads NirSoft BrowsingHistoryView exports into `browsinghistory-<hostname>` with a fixed schema, installing the `sofelk-toolkit-browsinghistory` index template (`browsinghistory-*`). It detects UTF-8, UTF-8 BOM, UTF-16, or CP1252 encoding; comma, tab, or semicolon delimiters; and headerless exports. The URL is ECS `url.original` (with `url.domain` / `url.scheme`), the profile owner is `user.name`, and the other columns are `browsinghistory.<snake_case>`; `Visit Time` becomes `browsinghistory.visit_time` (UTC, also `@timestamp`) and the exported text is kept in `browsinghistory.visit_time_local`. Each document carries `event.dataset: browsinghistory`, `host.name`, `kape.source_file`, `kape.timestamp_source`, `kape.timestamp_meaning`, and optional `case`. Field reference: [`docs/schemas/browsinghistory.md`](docs/schemas/browsinghistory.md). An index created by the earlier inferred-type version is refused; delete it and reload the host. Document IDs are deterministic from the host and row content, with a counter to preserve identical rows while preventing duplicate records on a repeat import.

Timestamp interpretation must use the timezone of the machine that ran BrowsingHistoryView (unless its GMT option was enabled), not necessarily the suspect host. If date order is ambiguous, the script stops before live loading and asks for `--date-order` rather than guessing.

Example:

```bash
python3 Windows/csv_importers/nirsoft_bhv2sofelk.py /cases/IR-2026-042/BrowsingHistory.csv --hostname WS01 --tz +08:00 --dry-run
python3 Windows/csv_importers/nirsoft_bhv2sofelk.py /cases/IR-2026-042/BrowsingHistory.csv --hostname WS01 --tz +08:00
```

The wrapper treats a file as a BrowsingHistoryView export only if its header has `URL` plus at least two BrowsingHistoryView-specific columns (such as `Visit Time`, `Web Browser`, or `History File`), or if it is a headerless file named like `BrowsingHistory*` whose first value is a URL. Older wrapper versions matched any `Url` or `Title` column, so RECmd plugin CSVs (TypedURLs, SCSI) were also loaded into `browsinghistory-<hostname>`. Those indexes were built by the inferred-type importer, which the current importer refuses, so deleting and reloading the host also removes the stray RECmd rows.

### 2. `jlecmd2sofelk.py`

Loads JLECmd AutomaticDestinations and CustomDestinations CSV outputs into `jumplist-<hostname>` with a fixed schema, installing the `sofelk-toolkit-jumplist` index template (`jumplist-*`). It identifies Automatic versus Custom Jump Lists primarily from the filename and also considers CSV headers; `event.dataset` is `jumplist.automatic` or `jumplist.custom`. The embedded LNK target goes to ECS `file.path` (lower-cased, from `LocalPath`), `file.created`, `file.mtime`, `file.accessed` and `file.size`; the other columns are `jumplist.<snake_case>` (for example `jumplist.app_id`, `jumplist.entry_last_modified`, `jumplist.source.path`). `@timestamp` is the DestList entry's `LastModified`, falling back to the jump list file's `SourceModified`. `user.name` comes from the `SourceFile` path. Field reference: [`docs/schemas/jumplist.md`](docs/schemas/jumplist.md). `--local-tz` is accepted but not used (JLECmd output is UTC). An index created by the earlier inferred-type version is refused; delete it and reload the host. Stable IDs allow re-importing the same rows without duplication.

Examples:

```bash
python3 Windows/csv_importers/jlecmd2sofelk.py /cases/IR-2026-042/FileFolderAccess --hostname WS01 --dry-run
python3 Windows/csv_importers/jlecmd2sofelk.py /cases/IR-2026-042/FileFolderAccess --hostname WS01
```

Expected filename clues include `*_AutomaticDestinations.csv` and `*_CustomDestinations.csv`; field headers are also used to recognize the content.

### 3. `sbecmd2sofelk.py`

Loads SBECmd ShellBags CSV outputs into `shellbag-<hostname>` with a fixed schema, installing the `sofelk-toolkit-shellbag` index template (`shellbag-*`). It detects ShellBags by characteristic fields such as `BagPath`, or `AbsolutePath` together with `ShellType`, and can also use an SBECmd filename clue. Columns map to `shellbag.<snake_case>` (for example `shellbag.absolute_path`, `shellbag.last_interacted`), and the folder's MAC times from the shell item go to ECS `file.created`, `file.mtime` and `file.accessed`. `@timestamp` is `LastInteracted`, falling back to the bag key's `LastWriteTime`. `user.name` and `shellbag.hive` come from SBECmd's `<user>_NTUSER.csv` / `<user>_UsrClass.csv` file names. Field reference: [`docs/schemas/shellbag.md`](docs/schemas/shellbag.md). `--local-tz` is accepted but not used. An index created by the earlier inferred-type version is refused; delete it and reload the host.

Example:

```bash
python3 Windows/csv_importers/sbecmd2sofelk.py /cases/IR-2026-042/ShellBags --hostname WS01 --dry-run
python3 Windows/csv_importers/sbecmd2sofelk.py /cases/IR-2026-042/ShellBags --hostname WS01
```

SBECmd filenames can vary by export workflow, so ensure its CSV headers identify the output correctly.

### 4. `amcache2sofelk.py`

Loads AmcacheParser section CSVs into `amcache-<hostname>` with a fixed schema. It recognizes section names in timestamp-prefixed filenames such as `*_Amcache_ProgramEntries.csv`, `*_Amcache_AssociatedFileEntries.csv`, and `*_Amcache_UnassociatedFileEntries.csv`, while also inspecting characteristic headers.

Every column maps to a fixed field and type defined in `Windows/index_templates/index-amcache.json` (composed with `component-toolkit-common.json`): ECS names where they fit (`file.path`, `file.name`, `file.hash.sha1`, `file.size`, `file.pe.*`, `package.*`) and `amcache.<snake_case>` for the rest. Each document carries `event.dataset` (e.g. `amcache.program_entries`), `host.name`, `kape.source_file`, `kape.timestamp_source`, `kape.timestamp_meaning`, and optional `case`. Before loading, the importer installs the `sofelk-toolkit-amcache` index template (pattern `amcache-*`) and creates the index from it, so every host's index has identical types. Unknown columns go to `amcache.unmapped.*`; values that do not fit their type are kept in `amcache.malformed`. The full column-to-field reference is in [`docs/schemas/amcache.md`](docs/schemas/amcache.md).

AmcacheParser timestamps are UTC, so `--local-tz` is accepted (the wrapper passes it) but not used. An `amcache-<hostname>` index created by the earlier inferred-type version is refused; delete it and reload the host.

Example:

```bash
python3 Windows/csv_importers/amcache2sofelk.py /cases/IR-2026-042/ProgramExecution --hostname WS01 --dry-run
python3 Windows/csv_importers/amcache2sofelk.py /cases/IR-2026-042/ProgramExecution --hostname WS01
```

### 5. `shimcache2sofelk.py`

Loads AppCompatCacheParser / ShimCache CSVs into `shimcache-<hostname>` with a fixed schema, the same way as the Amcache importer: it installs the `sofelk-toolkit-shimcache` index template (`shimcache-*`) and maps each column to a fixed field. The entry's path goes to `file.path` (lower-cased; the original is kept in `shimcache.path`), and `LastModifiedTimeUTC` goes to `file.mtime` and `@timestamp`. That time is the file's $SI last-modified time, **not proof of execution**. Recognized by filename clues such as `AppCompatCache` or `ShimCache` and by the `CacheEntryPosition` + `LastModifiedTimeUTC` headers. Field reference: [`docs/schemas/shimcache.md`](docs/schemas/shimcache.md). An index created by the earlier inferred-type version is refused; delete it and reload the host.

Example:

```bash
python3 Windows/csv_importers/shimcache2sofelk.py /cases/IR-2026-042/ProgramExecution --hostname WS01 --dry-run
python3 Windows/csv_importers/shimcache2sofelk.py /cases/IR-2026-042/ProgramExecution --hostname WS01
```

### 6. `recmd2sofelk.py`

Loads RECmd batch output and plugin-detail CSVs into `registry-<hostname>` with a fixed schema, installing the `sofelk-toolkit-registry` index template (`registry-*`). The batch CSV's columns map to fixed fields: ECS `registry.key`, `registry.value`, `registry.data.type` and `registry.data.strings`, plus `registry.<snake_case>` for the rest. Plugin-detail CSVs (one schema per plugin) share `registry.key` with the batch CSV and put their other columns under `registry.plugin.<snake_case>`. Those are keywords, except known timestamp columns, which are dates and feed `@timestamp`. `event.dataset` names the plugin (`registry.userassist`, `registry.services`, ...). `user.name` is added for per-user hives, and `kape.source_hive` from plugin file names. Field reference: [`docs/schemas/registry.md`](docs/schemas/registry.md). `--local-tz` is accepted but not used: `*LOCAL` columns stay keywords. An index created by the earlier inferred-type version is refused; delete it and reload the host.

Examples:

```bash
python3 Windows/csv_importers/recmd2sofelk.py /cases/IR-2026-042/Registry --hostname WS01 --dry-run
python3 Windows/csv_importers/recmd2sofelk.py /cases/IR-2026-042/Registry --hostname WS01
```

Filename examples include `*_RECmd_Batch_Kroll_Batch_Output.csv` and timestamp-prefixed plugin files such as `*_UserAssist__C_Users_bob_NTUSER.DAT.csv`. The script derives plugin/hive metadata from the actual filename pattern; confirm files from your tool version with a dry run.

### 7. `rbcmd2sofelk.py`

Loads RBCmd CSV output (`$I` and INFO2 records) into `recyclebin-<hostname>` with a fixed schema, installing the `sofelk-toolkit-recyclebin` index template (`recyclebin-*`). The deleted file's original path is ECS `file.path` (lower-cased; the original case is in `recyclebin.original_path`), its size is `file.size`, and `DeletedOn` is `recyclebin.deleted_on` and `@timestamp`. `user.id` is the SID of the `$Recycle.Bin\<SID>` folder. `event.dataset` is `recyclebin`. Field reference: [`docs/schemas/recyclebin.md`](docs/schemas/recyclebin.md). An index created by the earlier inferred-type version is refused; delete it and reload the host.

Example:

```bash
python3 Windows/csv_importers/rbcmd2sofelk.py /cases/IR-2026-042/RecycleBin --hostname WS01 --dry-run
python3 Windows/csv_importers/rbcmd2sofelk.py /cases/IR-2026-042/RecycleBin --hostname WS01
```

CSVs are selected by a file name containing `RBCmd` or `RecycleBin`, or by the `SourceName`, `FileName` and `DeletedOn` columns.

### 8. `recentfilecache2sofelk.py`

Loads RecentFileCacheParser CSV output into `recentfilecache-<hostname>`. It identifies files using RecentFileCache/RecentFileCacheParser filename clues and characteristic columns such as `SourceFile`, `SourceModified`, and file-name collections. Recognized timestamps are normalized, with `SourceModified`, `SourceCreated`, `SourceAccessed`, and then a generic `Timestamp` used as preferred time candidates.

Example:

```bash
python3 Windows/csv_importers/recentfilecache2sofelk.py /cases/IR-2026-042/RecentFileCache --hostname WS01 --dry-run
python3 Windows/csv_importers/recentfilecache2sofelk.py /cases/IR-2026-042/RecentFileCache --hostname WS01
```

### 9. `sqlecmd2sofelk.py`

Loads SQLECmd SQLite-report CSV output into `sqlitedb-<hostname>`. Because SQLECmd output varies with the SQLite map/report, the importer uses both filename clues and characteristic columns such as `SourceFile`, `Query`, `Database`, and `Table`. Timestamp candidates are `Timestamp`, `LastWriteTime`, `LastModified`, `Modified`, `Created`, and `Accessed`, in that order.

Example:

```bash
python3 Windows/csv_importers/sqlecmd2sofelk.py /cases/IR-2026-042/SQLite --hostname WS01 --dry-run
python3 Windows/csv_importers/sqlecmd2sofelk.py /cases/IR-2026-042/SQLite --hostname WS01
```

### 10. `srumecmd2sofelk.py`

Loads SrumECmd CSV reports into `srum-<hostname>` with a fixed schema, installing the `sofelk-toolkit-srum` index template (`srum-*`). Each SRUM table becomes an `event.dataset` such as `srum.app_resource_use_info` or `srum.network_connections`, taken from the `SrumECmd_<Table>_Output` file name or, for renamed files, the columns. The shared identity columns go to `srum.*`, `user.id` (SID) and `user.name`; when `ExeInfo` is a path it is also ECS `process.executable` / `process.name`. Counters are `srum.<snake_case>` longs. `@timestamp` is the SRUM record `Timestamp` (when Windows wrote the record, roughly hourly), not when the activity started. Field reference: [`docs/schemas/srum.md`](docs/schemas/srum.md). An index created by the earlier inferred-type version is refused; delete it and reload the host.

If SrumECmd reports a dirty database (`SRUDB.dat` was copied from a live system), repair a copy first with `esentutl /r sru /i` in its folder and then `esentutl /p SRUDB.dat`, and re-run SrumECmd.

Example:

```bash
python3 Windows/csv_importers/srumecmd2sofelk.py /cases/IR-2026-042/SRUM --hostname WS01 --dry-run
python3 Windows/csv_importers/srumecmd2sofelk.py /cases/IR-2026-042/SRUM --hostname WS01
```

### 11. `sumecmd2sofelk.py`

Loads SumECmd / User Access Logging CSV output into `sum-<hostname>`. Filename clues are the primary recognition method because SUM output schemas vary by report mode. Preferred timestamp candidates are `Timestamp`, `LastAccessTime`, `LastAccessed`, `LastUsed`, `LastModified`, and `Created`.

Example:

```bash
python3 Windows/csv_importers/sumecmd2sofelk.py /cases/IR-2026-042/SUM --hostname WS01 --dry-run
python3 Windows/csv_importers/sumecmd2sofelk.py /cases/IR-2026-042/SUM --hostname WS01
```

### 12. `wxtcmd2sofelk.py`

Loads WxTCmd Windows Timeline CSV output into `activitiescache-<hostname>` with a fixed schema, installing the `sofelk-toolkit-activitiescache` index template (`activitiescache-*`). The per-user `<user>_Activity.csv`, `<user>_ActivityOperations.csv` and `<user>_Activity_PackageIDs.csv` files become `event.dataset` values `activitiescache.activity`, `activitiescache.operations` and `activitiescache.package_ids`, and the user from the file name is `user.name`. Columns are `activitiescache.<snake_case>` with fixed types. `@timestamp` is `StartTime`, falling back to `LastModifiedTime`; PackageIDs rows use ingest time because their only date is an expiry. Field reference: [`docs/schemas/activitiescache.md`](docs/schemas/activitiescache.md). An index created by the earlier inferred-type version is refused; delete it and reload the host.

Example:

```bash
python3 Windows/csv_importers/wxtcmd2sofelk.py /cases/IR-2026-042/WindowsTimeline --hostname WS01 --dry-run
python3 Windows/csv_importers/wxtcmd2sofelk.py /cases/IR-2026-042/WindowsTimeline --hostname WS01
```

### 13. `clrusagelogs2sofelk.py`

Loads the CSV produced by `ConvertUsageLogsTo-CSV.ps1` into `clrusagelogs-<hostname>`. The expected columns are `User`, `AssemblyName`, `FirstExecutionTimestamp`, `LastExecutionTimestamp`, and `File`. The importer validates the expected schema, converts the execution timestamps to Elasticsearch-compatible values, uses `LastExecutionTimestamp` as the preferred `@timestamp` with `FirstExecutionTimestamp` as fallback, preserves the user, assembly name, source file, and CLR usage-log information, and uses deterministic IDs for repeatable imports. `case` is a flat keyword, as in every other index; a `clrusagelogs-<hostname>` index created when `case` was an object is refused, so delete it and reload the host.

Example:

```bash
python3 Windows/csv_importers/clrusagelogs2sofelk.py /cases/IR-2026-042/CLRUsageLogs.csv --hostname WS01 --dry-run
python3 Windows/csv_importers/clrusagelogs2sofelk.py /cases/IR-2026-042/CLRUsageLogs.csv --hostname WS01
```

The wrapper can identify this output from its filename and the characteristic five-column header, so a standalone invocation is normally only needed when testing or troubleshooting the importer.

## JSON importers: direct use

The four importers under `Windows/json_importers/` implement the main field transformations in the corresponding SOF-ELK Logstash filters and shared preprocessing/postprocessing rules. In current versions they can ingest both the original JSON/JSON.GZ exports and corresponding CSV outputs. JSON input is parsed incrementally, so a whole export does not need to be loaded into memory. Keep `sof_elk_json_bulk_common.py` alongside all four scripts in `Windows/json_importers/`.

[`docs/sofelk-native-field-reference.md`](docs/sofelk-native-field-reference.md) lists the native SOF-ELK field names and types for these four indexes, and the known differences between them and these importers.

Accepted JSON data files are `.json` and `.json.gz`. JSON input may be a top-level JSON array, a single JSON object, or a sequence of whitespace-separated/NDJSON objects. For CSV input, the scripts read rows with `iter_csv_records` in `sof_elk_json_bulk_common.py` and apply the same transformation, index, and host conventions as their JSON path. When a directory is supplied, a tool-specific filename pattern is used for JSON files; CSV discovery is format-aware and header-aware. PECmd timeline JSON is excluded.

The four importers support `--hostname`, `--case`, `--es`, `--user`, `--password`, `--insecure`, `--batch-size`, `--workers`, `--dry-run`, `--sample-docs`, and the retry/logging options described under [Retries and logging](#retries-and-logging). They do not support `--local-tz` or `--index`, for either JSON or CSV input.

Timestamps are parsed with the standard library on Python 3.9 and later, including the 7-digit fractional seconds that EZ Tools write (`2023-01-23 06:51:25.5665168`). All dates are stored as UTC ISO 8601 with millisecond precision. A date field that is empty or cannot be parsed is left out of the document rather than sent as raw text. After each file the importer prints a `WARNING` line (also written to `--log-file`) with the number of omitted empty and unparseable values per field, one example of a bad value, and the number of records whose `@timestamp` fell back to ingest time. A large unparseable count usually means the CSV was re-saved in Excel (see `docs/sofelk-native-field-reference.md`, section 3.1).

Every document gets `host.name` (the normalized hostname, mapped as `keyword`) and, when `--case` is given, `case` (`keyword`), the same fields the CSV importers write. ES|QL queries can therefore filter `filesystem-*`, `evtxlogs-*`, `lnkfiles-*`, and `prefetch-*` by `host.name` and `case` as well as by `_index`. When an importer appends to an index created by an earlier version, it first adds the `host.name`/`case` keyword mappings; documents loaded before that do not have these fields until they are re-imported (deterministic IDs make the re-import overwrite them).

### 14. `mftecmd2sofelk.py`

Loads MFTECmd JSON or CSV into `filesystem-<hostname>`. JSON directory searches use MFTECmd output filename patterns, including `*_MFTECmd*_Output.json` and gzip equivalents; CSV discovery also accepts MFTECmd output CSVs. The importer transforms standard-information and filename MACB timestamps into `file.stdinfo.*` and `file.filename.*`, creates `file.name`, `file.path`, and `file.type`, translates `kape.mft.*`, converts NTFS attributes to boolean properties, handles alternate data streams, splits update reasons, and selects `@timestamp` from the most appropriate available MFT/USN time field.

MFTECmd leaves a `$FILE_NAME` (0x30) time blank when it is identical to the `$STANDARD_INFORMATION` (0x10) time (on RD01, none of the 845,298 populated 0x30 values equals its 0x10 value). The importer restores those blanks from the matching `file.stdinfo.*` value, so every `$MFT` document has all eight MACB times, and lists the restored ones in `kape.mft.fn_same_as_si` (keyword array of `created`, `mtime`, `accessed`, `ctime`). A `file.filename.*` value is therefore equal to `file.stdinfo.*` exactly when its name is in that list. `$J` records carry only `file.update_timestamp` (also used for `@timestamp`), and `$Boot`/`$SDS` records have no timestamps, so their `@timestamp` is the ingest time. Indexes loaded by an earlier version lack the restored values; delete the `filesystem-<hostname>` index and re-import.

Example:

```bash
python3 Windows/json_importers/mftecmd2sofelk.py /cases/IR-2026-042 --hostname WS01 --dry-run
python3 Windows/json_importers/mftecmd2sofelk.py /cases/IR-2026-042 --hostname WS01 --es http://localhost:9200
```

### 15. `evtxecmd2sofelk.py`

Loads EvtxECmd JSON or CSV into `evtxlogs-<hostname>`. JSON directory searches use `*_EvtxECmd_Output.json` and gzip equivalents; CSV discovery also accepts EvtxECmd output CSVs. The importer maps Windows event fields to `winlog.*` and KAPE fields, parses `Payload` JSON where present, expands supported event-data values, maps UserData/Binary, writes `UserId` to `winlog.user.identifier` (the native SOF-ELK name) and also copies it to `user.id`, parses remote IP/port where possible, splits keywords, and constructs the summary `message`.

Heterogeneous `UserData.EventData` values are normalized to a consistent text representation before indexing so object/string variations do not create Elasticsearch mapping conflicts.

Example:

```bash
python3 Windows/json_importers/evtxecmd2sofelk.py /cases/IR-2026-042 --hostname WS01 --dry-run
python3 Windows/json_importers/evtxecmd2sofelk.py /cases/IR-2026-042 --hostname WS01 --workers 2
```

### 16. `lecmd2sofelk.py`

Loads LECmd JSON or CSV into `lnkfiles-<hostname>`. JSON directory searches use `*_LECmd_Output.json` and gzip equivalents; CSV discovery also accepts LECmd output CSVs. The importer maps source/origin and target timestamps and paths into the SOF-ELK `file.*` layout; applies local/absolute target path precedence; handles header flags, attributes, extra blocks, empty target times, and `(None)` drive type; converts target MFT entry/sequence numbers; and selects source LNK modification time for `@timestamp`.

Non-string target structures, including argument-only targets, are normalized before indexing so `file.target.path` remains compatible with the existing Elasticsearch text mapping.

Example:

```bash
python3 Windows/json_importers/lecmd2sofelk.py /cases/IR-2026-042 --hostname WS01 --dry-run
python3 Windows/json_importers/lecmd2sofelk.py /cases/IR-2026-042 --hostname WS01 --batch-size 3000 --workers 3
```

### 17. `pecmd2sofelk.py`

Loads PECmd JSON or CSV into `prefetch-<hostname>`. JSON directory searches use `*_PECmd_Output.json` and gzip equivalents; CSV discovery also accepts PECmd output CSVs. `*_PECmd_Output_Timeline.json` and its CSV equivalent are deliberately excluded, since they are flattened timeline views of records already represented by regular output. The importer maps Prefetch and executable fields, splits `Directories` and `FilesLoaded`, removes configured .NET unset sentinels, converts timestamps and numeric fields, merges supported `PreviousRunN` values into `prefetch.previous_runs`, builds the summary `message`, and chooses `@timestamp` from LastRun and then source file modification time.

Example:

```bash
python3 Windows/json_importers/pecmd2sofelk.py /cases/IR-2026-042 --hostname WS01 --dry-run
python3 Windows/json_importers/pecmd2sofelk.py /cases/IR-2026-042 --hostname WS01
```

## Shared field, timestamp, and index behavior

- CSV importers preserve the source-specific field transformations and type/timestamp behavior implemented for each importer. The original KAPE-derived CSV importers omit `forensic_tag` from stored documents as requested. The four JSON/CSV hybrid importers preserve their source-specific Logstash-derived transformations where implemented.
- The evidence hostname is used to form each target index name. It is normalized to lowercase because Elasticsearch index names must be lowercase.
- The AmcacheParser, ShimCache, RECmd, JLECmd, SBECmd, RBCmd, WxTCmd, SrumECmd and BrowsingHistoryView importers use a fixed, template-defined schema (see [`docs/schemas/`](docs/schemas/)). The other scripts create an index if it does not exist, define explicit mappings for recognized non-string fields, and use dynamic string mappings. Existing mappings are checked before writing. CSV importers route incompatible field types to `<field>_text` where supported. JSON/CSV hybrid importers report bulk indexing rejections and exit non-zero when any documents are rejected.
- Importers use deterministic document IDs based on host and stable file/record properties so rerunning the same exports does not create duplicate logical documents. Identical rows within one file are kept as separate documents (by row position, or by a counter for BrowsingHistoryView).
- **Upgrade note:** the document-ID scheme changed for the RECmd, JLECmd, SBECmd, and CLR usage-log importers. If a host was loaded with an earlier version of these importers, delete that host's documents (or its index) before re-importing, otherwise the old and new IDs produce duplicates.
- `--dry-run` previews parsing/transformation and prints sample documents, but it does not prove that a live Elasticsearch cluster will accept every mapping. Always test representative output from your installed tool versions before loading production evidence.

## Retries and logging

All importers send Elasticsearch traffic through the shared client in `Windows/common/sof_elk_es_client.py` (standard library and `urllib` only):

- **Whole-request retry.** Connection errors, timeouts, and HTTP `429`, `500`, `502`, `503`, and `504` responses are retried with exponential backoff and full jitter (delay up to `--retry-backoff` × 2^attempt, capped at 60 seconds). A `Retry-After` header is honored. If Elasticsearch is still unreachable after `--max-retries`, the importer stops with an error.
- **Per-item retry.** When a `_bulk` request succeeds but individual documents are rejected with `429`, `502`, `503`, or `504` (typically `es_rejected_execution_exception` when the write queue is full), only those documents are re-sent, with the same backoff. Documents rejected for other reasons, such as mapping errors, are not retried and are counted as item errors.
- **Safe to replay.** Every importer sends `index` actions with deterministic document IDs, so a retried batch overwrites itself instead of creating duplicates.
- **Logging.** Retries and failures are printed to stderr. With `--log-file PATH`, each importer appends its command line (password masked), start and finish summary, every retry, a per-batch bulk summary, and every item-level error (`_id`, status, and reason) to that file. The wrapper passes the same file to all importers, so one run produces one log.

| Option | Default | Purpose |
|---|---|---|
| `--max-retries N` | `5` | Retries per request and per rejected bulk item; `0` disables retrying. |
| `--retry-backoff SECONDS` | `2` | Base delay for exponential backoff. |
| `--timeout SECONDS` | `300` | Time to wait for each Elasticsearch HTTP response. |
| `--log-file PATH` | none | Append detailed run information to this file. |

## Timestamp and data-quality cautions

1. **BrowsingHistoryView timezone:** use the timezone offset of the machine that ran the utility, unless its GMT/UTC export setting was enabled. This may not be the evidence host's timezone.
2. **Regional dates:** if BrowsingHistoryView dates are ambiguous between day/month and month/day, supply `--date-order dmy` or `mdy` to match the exporting machine. Mixed/inconsistent formats are reported rather than silently guessed.
3. **KAPE LOCAL values:** provide `--local-tz +HH:MM` if columns explicitly marked LOCAL should be converted to UTC. Without an offset, those fields are retained as text where the importer specifies that behavior.
4. **Forensic time meaning:** a timestamp used as `@timestamp` is not necessarily an execution time. In particular, ShimCache's last-modified time is file metadata and not proof of program execution; Amcache timestamps can describe registry-key updates or installation activity rather than definitive execution.
5. **Source output differences:** filename clues and CSV headers can differ between utility versions and export settings. Run a dry run and inspect the discovery summary and transformed sample documents before live indexing.
6. **Linux syslog years and time zones:** classic syslog lines have no year and no zone. The Linux importers take the zone from the evidence's `/etc/localtime` and infer the year from each file's modification time, so a collection that did not keep modification times needs `--year`. Check `event.timezone` and the earliest and latest `@timestamp` per file after loading. The journal is not affected: its timestamps are UTC.
7. **Journal and text syslog overlap:** on hosts where rsyslog writes alongside journald, most events are in both `event.dataset` values. Filter on one when counting.
8. **Mixed JSON/CSV runs:** the wrapper can discover different formats for the same tool. Avoid supplying duplicate exports of the same evidence unless you intentionally want the deterministic ID behavior to reconcile/reload them.

## Authentication and TLS

The importers accept an Elasticsearch URL and optional HTTP Basic credentials. Use `--insecure` only if the endpoint is trusted and TLS certificate validation cannot be configured properly; it disables certificate checking. Be careful not to expose passwords in shell history or process listings on shared systems. For production, prefer a suitably scoped ingest account and secured transport.

## Kibana Data View creator

`SOF-ELK_CreateDataViews.py` creates two sets of Kibana Data Views.

**SOF-ELK's out-of-box Data Views** (skip with `--toolkit-only`). A plain Elasticsearch/Kibana, such as the one `Install-ForensicELK.ps1` builds, has none of them. They are loaded from unmodified copies of SOF-ELK's `kibana/data_views/*.json` in [`sof-elk-kibana/data_views/`](sof-elk-kibana/data_views), with the same ids, titles and field formats: `all-records`, `appleul-*`, `aws-*`, `azure-*`, `evtxlogs-*`, `filesystem-*`, `gcp-*`, `gws-*`, `httpdlog-*`, `icsnpp-*`, `kape` (`filefolderaccess-*,filesystem-*,lnkfiles-*,evtxlogs-*`), `kubernetes-*`, `lnkfiles-*`, `logstash-*`, `microsoft365-*`, `netflow-*`, `plaso-*`, `prefetch-*`, `volatility-*` and `zeek-*`. On a SOF-ELK VM they already exist and are skipped.

The script also applies SOF-ELK's Kibana advanced settings from `sof-elk-kibana/sof-elk_config.json` (skip with `--skip-kibana-settings`): `dateFormat:tz` = `UTC`, SOF-ELK's date formats, `defaultIndex` = `logstash`, the Discover sample size and row height, the dark-mode setting and the Security IP-reputation links. The Data Views' `@timestamp` format ends in a literal `Z`, so without the UTC time zone Kibana would show local times labelled as UTC. `defaultRoute` is left out because it opens a SOF-ELK dashboard that the script does not install. If Kibana refuses the batch, each setting is retried on its own and failures are reported.

**The toolkit's Data Views**, which stock SOF-ELK does not have:

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
| ConvertUsageLogsTo-CSV.ps1 | `clrusagelogs-*` | `clrusagelogs-<hostname>` |
| `AWS/cloudtrail2sofelk.py` | `aws-cloudtrail-*` | `aws-cloudtrail-<source>` |
| `AWS/vpcflow2sofelk.py` | `aws-vpcflow-*` | `aws-vpcflow-<source>` |
| `AWS/waf2sofelk.py` | `aws-waf-*` | `aws-waf-<source>` |
| `Generic-CSV/genericcsv2sofelk.py` | `genericcsv-*` | `genericcsv-<hostname>` |

The `filesystem-*`, `evtxlogs-*`, `lnkfiles-*` and `prefetch-*` Data Views come from SOF-ELK's set. The AWS importers' indexes get the narrower patterns above, next to SOF-ELK's own `aws-*` Data View (for its Logstash CloudTrail output). `AWS/alb2sofelk.py` writes ALB/ELB access logs to `httpdlog-<source>`, which SOF-ELK's stock `httpdlog-*` Data View already covers. The Linux importers write the journal, text syslog and FTP logs to `logstash-<hostname>` and web server logs to `httpdlog-<hostname>`, which SOF-ELK's stock `logstash-*` (Kibana's default) and `httpdlog-*` Data Views already cover, and browser history to `browsinghistory-<hostname>`, covered by the toolkit's `browsinghistory-*` Data View, so no extra Data View is created for them.

The script uses Kibana's Data Views API and is standard-library only. By default it is idempotent: an existing Data View is detected and left unchanged. Use `--overwrite` to delete and recreate the managed views (SOF-ELK's are recreated with the same ids, so its dashboards keep working on a SOF-ELK VM). The Data Views are configured to use `@timestamp` as the time field and `allowNoIndex=true`, so they can be created before the first corresponding Elasticsearch index exists.

### Usage

Preview the Data Views and settings without modifying Kibana:

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

Force recreation of the managed Data Views:

```bash
python3 SOF-ELK_CreateDataViews.py --overwrite
```

### Options

- `--kibana URL`: Kibana base URL. Default: `http://localhost:5601`.
- `--user USER`: HTTP Basic authentication username.
- `--password PASSWORD`: HTTP Basic authentication password.
- `--insecure`: disable TLS certificate verification.
- `--overwrite`: delete and recreate the managed Data Views if they already exist.
- `--toolkit-only`: only the toolkit's Data Views; leave SOF-ELK's Data Views and Kibana settings alone.
- `--skip-kibana-settings`: create the Data Views but do not apply SOF-ELK's Kibana advanced settings.
- `--dry-run`: display the Data Views that would be managed without making API changes.

Run the Data View creator after Kibana is available and before using the corresponding indexes in Discover. Because `allowNoIndex` is enabled, it is also safe to create the Data Views before the direct-import scripts have created their first host-specific indexes.

## Deleting indexes by host or case

`SOF-ELK_DeleteIndexes.py` deletes the toolkit indexes of one evidence host (`--hostname`), one case (`--case`), or both, for example to reload a host from scratch (several sections above say "delete it and reload the host") or to clear a finished or test case. It is standard-library only and uses the same Elasticsearch client, connection options and retry options as the importers.

Always preview first:

```bash
python3 SOF-ELK_DeleteIndexes.py --hostname RD01 --dry-run --es http://192.168.233.128:9200
python3 SOF-ELK_DeleteIndexes.py --case IR-2026-042 --dry-run --es http://192.168.233.128:9200
```

**By hostname.** The hostname is normalized exactly as the importers do it (`RD01` becomes `rd01`). Matching is strict so that a similar hostname is never caught:

- Only indexes named `<prefix>-<hostname>` are considered: `rd01` matches `amcache-rd01` and `aws-cloudtrail-rd01`, but not `amcache-rd011` or `amcache-rd01-old`.
- Each candidate's documents are checked. When they carry `host.name` (Windows, Generic-CSV and Linux importers) or `labels.evidence_source` (AWS importers), the index is selected only if that value is the hostname. This protects `amcache-ws-01` (host `ws-01`) when you delete host `01`.
- An index whose documents do not say which host they came from (empty, closed, or loaded by an older importer) is selected only when its prefix is one of the toolkit's (`amcache`, `filesystem`, `evtxlogs`, `aws-cloudtrail`, `httpdlog`, `genericcsv`, `logstash`, ...) or one given with `--prefix`.

**By case.** The case ID is not part of the index name; the importers store it in each document's `case` field (from their `--case` option). The script searches every non-hidden index for documents with that `case` (upper/lower case ignored) and deletes an index only when **all** of its documents belong to the case. An index that also holds documents from another case, or without a case (for example the same host imported twice under different `--case` values), is listed with its counts and kept, so another case's evidence is never removed; delete those documents by hand with `_delete_by_query` if needed. Documents imported without `--case` cannot be found this way; use `--hostname` for them. Closed indexes cannot be searched and are listed as skipped.

**Both.** `--hostname RD01 --case IR-2026-042` deletes only RD01's indexes whose documents all belong to that case.

The script prints the indexes it will delete (with document count and size) and the matching indexes it leaves alone, with the reason. To delete, it asks you to type the hostname (or, with `--case` alone, the case ID) back; `--yes` skips that prompt (needed when stdin is not a terminal). Each index is deleted with its own request, so it works when wildcard deletes are disabled (`action.destructive_requires_name`). The Kibana Data Views use wildcards such as `amcache-*`, so they are not affected.

```bash
# Delete everything for RD01 after confirming
python3 SOF-ELK_DeleteIndexes.py --hostname RD01 --es http://192.168.233.128:9200

# Delete every index that belongs entirely to case IR-2026-042
python3 SOF-ELK_DeleteIndexes.py --case IR-2026-042 --es http://192.168.233.128:9200

# Only RD01's Amcache and filesystem indexes, without prompting
python3 SOF-ELK_DeleteIndexes.py --hostname RD01 --prefix amcache --prefix filesystem --yes
```

| Option | Purpose |
|---|---|
| `--hostname HOST` | Evidence host name, as given to the importers. |
| `--case ID` | Case ID, as given to the importers with `--case`. At least one of `--hostname` and `--case` is required. |
| `--prefix PREFIX` | Only consider indexes with this prefix; repeatable. Also selects a custom `--index` prefix such as `amcache-test`. |
| `--dry-run` | List the matching indexes and delete nothing. |
| `--yes`, `-y` | Delete without the confirmation prompt. |
| `--es`, `--user`, `--password`, `--insecure` | Connection options, as for the importers. |
| `--max-retries`, `--retry-backoff`, `--timeout`, `--log-file` | Retry and logging options, as for the importers. |

The exit status is `0` on success or when there is nothing to delete, `1` when the prompt is declined or a delete fails, and `2` when Elasticsearch is unreachable. Tests: `python3 tests/test_delete_indexes.py -v`.

## Windows Elasticsearch and Kibana setup

`Install-ForensicELK.ps1` builds a standalone Elasticsearch 9.4.3 and Kibana 9.4.3 instance on a Windows analyst workstation, as an alternative to a SOF-ELK VM. Run it from the directory that should hold the install (keep the path short, such as `C:\Tools`, because the Kibana archive has deeply nested files), ideally from an elevated PowerShell so it can add firewall rules:

```powershell
cd C:\Tools
powershell.exe -ExecutionPolicy Bypass -File C:\path\to\Install-ForensicELK.ps1
```

It creates `forensic-elk\`, downloads both Windows zips from artifacts.elastic.co into it and checks them against Elastic's published SHA-512 checksums, extracts them, writes `elasticsearch.yml` and `kibana.yml` (originals kept as `*.orig`), adds Windows Defender Firewall rules, stages the index templates, writes `forensic-elk\start.bat`, then starts both services, checks that Elasticsearch answers without credentials, and finally deletes the downloaded zip files and their `.sha512` files (keep them with `-KeepDownloads`). Run it from the root of the toolkit checkout (where it lives), because it copies the templates from there. Re-running it is safe: an already-extracted Elasticsearch or Kibana is reused without downloading it again, and the Kibana encryption keys are kept.

| Setting | Value | Why |
| --- | --- | --- |
| `network.host` / `server.host` | `0.0.0.0` | The host (`localhost`) and VMs on the workstation's virtual networks reach TCP/9200 and TCP/5601. |
| `discovery.type` | `single-node` | Standalone node; no production bootstrap checks for the non-loopback bind. |
| `xpack.security.enabled` (and enrollment, HTTP/transport TLS) | `false` | No username or password for the Kibana UI or the REST APIs. Written before the first start, so Elasticsearch never auto-generates TLS certificates or the `elastic` password. |
| `elasticsearch.hosts` | `http://127.0.0.1:9200` | Connects Kibana to Elasticsearch. With security disabled there is no enrolment token to use; this is the whole integration. |
| Index templates | SOF-ELK's native component and index templates from [`sof-elk-templates/`](sof-elk-templates/README.md) (`evtxlogs`, `filesystem`, `lnkfiles`, `aws`, `zeek` and the rest, under SOF-ELK's own names), plus the toolkit's templates from `Windows/`, `AWS/`, `Generic-CSV/` and `Linux/index_templates/` (`sofelk-toolkit-*`; `AWS/index_templates/index-httpdlog.json`, `Linux/index_templates/index-httpdlog.json` and `Linux/index_templates/index-logstash.json` are left out, as their importers never install them as templates over SOF-ELK's own families) | New indexes get the same settings and mappings as on a SOF-ELK VM with the toolkit, even before the first import. Copied to `forensic-elk\templates\` and loaded by `forensic-elk\load-templates.ps1`. |
| Firewall rules (group "Forensic ELK") | Inbound TCP 9200/5601 from `LocalSubnet`, tied to the bundled `java.exe`/`node.exe` | Lets VMs on host-only/NAT/Hyper-V networks connect. Change the scope with `-FirewallRemoteAddress 192.168.56.0/24`, or skip with `-SkipFirewall`. Without Administrator rights the script skips this and warns. |

Other options: `-InstallRoot DIR` (where `forensic-elk` is created; default is the current directory), `-HeapSize 4g` (fixed JVM heap instead of automatic sizing), `-SkipTemplates` (do not stage or load any templates), `-NoStart` (configure only), `-KeepDownloads` (keep the zip files), and `-StartupTimeoutSeconds N` (how long `start.bat` waits for each service; default 300).

### Running selected steps

The setup runs as named steps, in this order: `Install` (create `forensic-elk`, download and extract), `Configure` (`elasticsearch.yml`, `kibana.yml`, heap), `Firewall`, `Templates` (stage templates and write `load-templates.ps1`), `StartScript` (write `start.bat`), `Start` (run `start.bat` and verify) and `Cleanup` (delete the zips). `-Only` runs just the steps you name; every step except `Install` works on an existing `forensic-elk` under `-InstallRoot`.

A `forensic-elk` folder can be copied to another computer as-is (for example on a USB drive): `start.bat`, `load-templates.ps1` and both configuration files use no absolute paths. The firewall rules do not travel with it, because they belong to the computer and name the absolute path of the bundled `java.exe` and `node.exe`. On the new computer, from an elevated PowerShell:

```powershell
.\Install-ForensicELK.ps1 -InstallRoot C:\Tools -Only Firewall
```

`-InstallRoot` is the folder that contains `forensic-elk`. With `-Only Firewall` the script fails if it is not elevated, instead of only warning. Other examples: `-Only Configure, StartScript -HeapSize 8g` changes the heap, and `-Only Templates` re-stages templates after pulling a newer toolkit. Stop Elasticsearch and Kibana before copying the folder, and copy it into a short path.

For later starts, run `forensic-elk\start.bat`. It starts Elasticsearch in its own window, waits for `/_cluster/health`, re-loads the index templates (a PUT per template, so this is idempotent and picks up template changes), then starts Kibana in another window and waits for `/api/status`; a service that is already running is not started twice. Stop a service with Ctrl+C in its window. From a VM, point the toolkit at the workstation's address on that VM's network (the setup script prints each adapter's address):

```bash
python3 SOF-ELK_CreateDataViews.py --kibana http://192.168.56.1:5601
python3 SOF-ELK_ImportWrapper.py /cases/IR-2026-042 WS01 --es http://192.168.56.1:9200
```

Anyone who can reach these ports can read, change and delete every index without credentials, so keep the firewall scope narrow and do not run this on an untrusted network. Templates only apply to indexes created after they load; `prefetch-*` has no SOF-ELK template (as on a SOF-ELK VM), and the PECmd importer creates it with its own explicit mapping. Kibana starts with no Data Views: run `SOF-ELK_CreateDataViews.py` (above) to create SOF-ELK's out-of-box Data Views and the toolkit's, and to apply SOF-ELK's Kibana defaults such as the UTC display time zone. SOF-ELK's dashboards and saved searches are not installed.

## Remote ingest configuration

`SOF-ELK_ConfigureRemoteIngest.sh` prepares a standalone SOF-ELK Elasticsearch node to accept bulk imports from a separate importer VM:

```bash
sudo ./SOF-ELK_ConfigureRemoteIngest.sh 192.168.233.145
```

It validates the importer's IPv4 address, backs up `/etc/elasticsearch/elasticsearch.yml`, sets `network.host: 0.0.0.0` and `discovery.type: single-node`, adds a firewalld rich rule that allows only that IP to reach TCP/9200, restarts Elasticsearch, and checks that the API is listening. It assumes Elasticsearch is configured under `/etc/elasticsearch` and that firewalld manages the host firewall. It does not enable or change Elasticsearch authentication, so restrict network exposure accordingly.

## Efficiency and Big-O considerations

The wrapper's filesystem discovery is linear in the number of filesystem entries visited, `O(F)`. CSV parsing and transformation are linear in the total input size and number of rows, `O(S)`, and JSON parsing is linear in total JSON bytes, also `O(S)`, assuming bounded individual record size.

Bulk ingestion reduces the number of Elasticsearch HTTP requests from approximately one request per document to `O(ceil(N/B))` requests, where `N` is the number of documents and `B` is the bulk batch size. The importers keep working memory bounded by the largest individual record plus the configured batches and concurrent workers, rather than loading an entire evidence export into RAM.

The wrapper walks the directory tree once and classifies files from lightweight filename/header checks before invoking the importers. It therefore avoids running every importer against every file. The direct Elasticsearch architecture also avoids the additional filebeat/Logstash processing path used by the stock SOF-ELK ingestion workflow.

For large evidence collections, start with the default `--batch-size 2000` and `--workers 2`, then increase gradually while monitoring Elasticsearch CPU, heap, disk I/O, rejected writes, and bulk request latency. A very large batch can reduce HTTP overhead but increase transient memory consumption and the cost of a failed request; more workers increase parallelism but can saturate a small SOF-ELK VM.

## Validation status and limitations

The toolkit has been checked using Python syntax/help tests, synthetic dry-run tests, wrapper discovery tests, and archive integrity checks during development. Real-world testing has also exposed heterogeneous EVTX and LECmd values, which are normalized in the current hybrid importers before Elasticsearch indexing. No claim is made that every output schema from every version/configuration of every forensic utility will be identical to the tested samples.

The Linux importers were checked against a real Kali UAC collection (619,334 journal entries, loaded to a mock Elasticsearch with no rejected documents) and synthetic Ubuntu and Rocky 9 fixtures. No real RHEL-family or Ubuntu collection has been tested yet.

No full production-scale comparison against a live stock SOF-ELK Logstash pipeline has been performed for every source. The direct importers mirror the relevant SOF-ELK configurations and the previously developed source-specific importer logic, but they do not reproduce every Filebeat runtime-only field, every Logstash parser-failure side effect, or every possible mapping outcome from heterogeneous third-party output. Validate the exact tool versions, export settings, filenames, headers, timestamps, and mappings used in your environment before loading production evidence.
