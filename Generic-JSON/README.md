# Generic JSON importer

`genericjson2sofelk.py` loads every JSON file under a folder into SOF-ELK's Elasticsearch, for JSON exports that have no dedicated importer in `Windows/`, `AWS/` or `Linux/`. Field names come from the JSON keys. It uses only the Python standard library (3.9+) and the same retrying `_bulk` client as the other importers (`../Windows/common/sof_elk_es_client.py`), so keep `Generic-JSON/` and `Windows/` side by side.

`SOF-ELK_ImportWrapper.py` does not call this script, because it would otherwise load every JSON file that a dedicated importer already handles (EvtxECmd, MFTECmd, CloudTrail, ...). Run it yourself, on a folder that holds only the JSON files you want here.

| Index | Data View | Template |
|---|---|---|
| `genericjson-<hostname>` | `genericjson-*` (created by `SOF-ELK_CreateDataViews.py`) | `index_templates/index-genericjson.json`, installed as `sofelk-toolkit-genericjson` |

## Quick start

```bash
# Look first: read every file, show the fields, the @timestamp choice and two sample documents
python3 Generic-JSON/genericjson2sofelk.py /cases/IR-42/RD01/misc-json --hostname RD01 --dry-run

# Load into the local SOF-ELK
python3 Generic-JSON/genericjson2sofelk.py /cases/IR-42/RD01/misc-json --hostname RD01 --case IR-42

# Kibana Data View genericjson-*, once
python3 SOF-ELK_CreateDataViews.py
```

The folder is searched recursively for `*.json`, `*.jsonl` and `*.ndjson`, and gzip copies of them (`*.json.gz`, ...), in any case. A single file of any name also works. Loading the same files again overwrites the earlier documents instead of duplicating them.

## Accepted layouts

Each file's layout is detected on its own and shown in the summary (`genericjson.layout`):

| Layout | Example | Records |
|---|---|---|
| `array` | `[{...}, {...}]` | each element; the array is streamed, so large files are not loaded into memory at once |
| `lines` | JSON Lines / NDJSON, one object per line | each line; an invalid line is skipped and reported with its line number |
| `object` | one object, or several (pretty-printed) objects one after another | each object |

- **Wrapped records.** A top-level object that holds its records in an array under `Records`, `records`, `value`, `data`, `items`, `results`, `events`, `logs` or `entries` (case-insensitive), such as a CloudTrail file `{"Records": [...]}` or a Microsoft Graph export `{"value": [...]}`, is unwrapped: each element is a record, and the wrapper's other keys are dropped. This applies only to the `object` layout. Use `--records-key KEY` (dotted for nested keys, such as `hits.hits` for an Elasticsearch search result) to name the key yourself, or `--no-unwrap` to load each top-level object as one record.
- A top-level value that is not an object (a string or number in an array) becomes a record with one field, `value`.
- A syntax error outside a JSON Lines file stops that file. The records before it are kept, and the summary shows where the error is.
- The encoding is detected from the byte-order mark (UTF-8 or UTF-16), else UTF-8, else Windows-1252.

## Document layout

Every record becomes one document:

| Field | Value |
|---|---|
| `<key>` … | the record's keys, sanitized (see below); nested objects stay objects, values are keyword strings |
| `@timestamp` | from the timestamp field (see below), else the ingest time |
| `log.file.path` (ECS) | absolute path of the source JSON file on the machine that ran the import |
| `event.sequence` | record number in that file, from 1 |
| `event.dataset` / `event.kind` | `genericjson` / `event` |
| `event.ingested` | time of the import run |
| `event.original` | the record's original JSON text, only with `--keep-original` (stored, not searchable) |
| `host.name` | `--hostname`, lower-cased |
| `case` | `--case`, when given (flat keyword, as in the other importers) |
| `genericjson.file_name` | the file's name |
| `genericjson.relative_path` | path of the file relative to the folder given on the command line |
| `genericjson.layout` | `array`, `lines` or `object` |
| `genericjson.timestamp_source` | the field `@timestamp` came from, or `ingest_time` |

The `_id` is a SHA-1 of the host name, `log.file.path` and the record number, so a re-run of the same files from the same path overwrites. Loading the same files from another path (for example another mount point) creates a second copy, because the path is part of the identity; delete the index first if you move the evidence.

## Field names

The field names are the JSON keys, made valid and ES|QL-friendly the same way as in Generic-CSV:

- **Nesting is kept.** `{"user": {"name": "tdungan"}}` becomes the object field `user.name`, so ES|QL can use `user.name` directly. Objects nested deeper than `--max-depth` levels (default 10) are stored as JSON text in one keyword field.
- Within a key, characters other than letters, digits and `_` become `_`, and leading and trailing `_` are dropped (`Time Created` → `Time_Created`, `@timestamp` → `timestamp`, `_id` → `id`). A dot inside a key is replaced too (`{"user.name": "x"}` → `user_name`), so only real nesting creates objects.
- An empty key becomes `field`. A key starting with a digit gets an `f_` prefix (`1st` → `f_1st`). Keys longer than 255 bytes are cut.
- Top-level keys that the importer writes itself (`host`, `case`, `log`, `event`, `genericjson`, case-insensitively) get a `_json` suffix (`event` → `event_json`). Nested keys are not changed (`process.host` stays).
- Keys that repeat within one object after this (case-insensitively) get `_2`, `_3`, … (`Event ID`, `event id` → `Event_ID`, `event_id_2`).
- The original case is kept (ES|QL field names are case-sensitive).

The import lists every renamed key path, and `--log-file` records the full run.

### Objects and plain values under one key

Elasticsearch cannot map one field as both an object and a plain value. When a key holds an object in some records and a plain value in others, the first shape seen keeps the name, and the other shape is stored beside it:

- a plain value where `user` is an object → `user_value`
- an object where `user` is a plain value → `user_obj` (with its own sub-fields, `user_obj.name`)

A shape already mapped in an existing `genericjson-<hostname>` index wins over the files being loaded. The summary lists every key this happened to.

## Types

Every value is mapped as `keyword` (values over 8191 characters are kept in `_source` but not indexed). Numbers and booleans are stored as the text JSON writes for them (`3`, `1.5`, `true`), so in ES|QL use `TO_LONG(Count)`, `TO_DOUBLE(...)` or `TO_DATETIME(...)` where you need numbers or dates. This is what lets unrelated files share one index safely.

- An array of plain values becomes a multi-valued keyword field (`["a", 1]` → `["a", "1"]`); nested arrays are flattened, and `null` and empty strings are left out.
- An array of objects stays an array of objects (Elasticsearch's default `object` type, not `nested`), so `tags.name` holds every element's `name`.
- An array that mixes objects and plain values becomes a keyword array, with each object as JSON text.
- `null`, empty strings, empty objects and empty arrays are left out.

The index template sets `dynamic: true` with a strings-as-keyword dynamic template, and the importer also maps each new field explicitly before loading.

## Mixed layouts across files

All files in the run go to the one `genericjson-<hostname>` index:

- The index's fields are the union of all keys seen. A document only has the fields of its own record; the others are absent (null in ES|QL).
- The same key path in two files is the same field. Because every value is a keyword, files can never conflict on type.
- Each file picks its own `@timestamp` field, so `@timestamp` means different things in different files. Check `genericjson.timestamp_source` before you put records from several files on one timeline.
- Filter one source with `log.file.path` or `genericjson.file_name`:

```esql
FROM genericjson-* METADATA _index
| STATS records = COUNT(*) BY _index, genericjson.file_name, genericjson.layout, genericjson.timestamp_source
| SORT _index, genericjson.file_name
```

- The index's field limit is 5000. A run that would pass it stops before sending anything; lower `--max-depth`, split the folder with `--exclude`, or load into a separate index with `--index <prefix>-<hostname>`. JSON that uses data as keys (one key per GUID or per file name, for example) is the usual cause.

## Timestamps

- `--timestamp-field NAME` (repeatable) names the field to use, dotted for nested keys (`meta.Modified`). It matches the original key path or the sanitized field path, case-insensitively, and the first one present in a file wins.
- Without it, or when none of the names is in a file, the importer samples the first 500 records. It uses the first field where at least 90% of the non-empty values are dates, preferring fields whose name looks like a time (`TimeCreated`, `eventTime`, `@timestamp`, `ts`). Fields with `local` in the name are skipped. `--no-timestamp-detect` turns the guessing off.
- Accepted values are the same text forms as Generic-CSV (ISO 8601 with or without `T`, a zone or fractional seconds; a date alone; `10/25/2026 8:19 PM`, with `--date-order dmy` for day/month), plus Unix epoch **numbers** in seconds, milliseconds, microseconds or nanoseconds, but only in a field whose name looks like a time, so that ids and counters are never read as dates. Epoch values written as strings are not read as times.
- A time without a zone is read as UTC. Use `--assume-tz +08:00` for an export in local time.
- A record whose timestamp is missing or unreadable gets the ingest time, and the summary counts those records per file.

## Options

| Option | Meaning |
|---|---|
| `directory` | folder searched recursively for JSON files, or one file |
| `--hostname NAME` | evidence host (required); index `genericjson-<hostname>` |
| `--case ID` | case ID added to every document as `case` |
| `--index NAME` | another index name; must end in `-<hostname>` |
| `--records-key KEY` | key whose array holds the records (repeatable, dotted for nested) |
| `--no-unwrap` | do not unwrap `{"Records": [...]}`-style files automatically |
| `--timestamp-field NAME` | field to use for `@timestamp` (repeatable) |
| `--no-timestamp-detect` | do not guess a date field |
| `--assume-tz OFFSET` | zone for times that carry none (default `Z`) |
| `--date-order mdy\|dmy` | day/month order of spreadsheet-style dates |
| `--max-depth N` | object levels kept as objects (default 10) |
| `--keep-original` | store each record's JSON text in `event.original` |
| `--exclude GLOB` | skip files whose name or relative path matches (repeatable), e.g. `--exclude '*CloudTrail-Digest*'` |
| `--es URL` | Elasticsearch URL (default `http://localhost:9200`) |
| `--user`, `--password`, `--insecure` | authentication and TLS, as for the other importers |
| `--batch-size N` | documents per `_bulk` request (default 2000) |
| `--dry-run`, `--sample-docs N` | read everything and show sample documents without sending |
| `--max-retries`, `--retry-backoff`, `--timeout`, `--log-file` | retry and logging behaviour of the shared client (see the top-level README) |

Every file is read twice: once to collect the field shapes and the timestamp field, then to send. An existing `genericjson-*` index that this importer did not create is refused rather than mixed. Exit status is 0 on success and 1 when Elasticsearch rejected any document.

## Tests

```bash
python3 Generic-JSON/tests/test_genericjson.py -v
```

The tests need no Elasticsearch. The importer was also run end to end against the toolkit's mock Elasticsearch with the AWS CloudTrail and VPC Flow test fixtures and a 5,000-line NDJSON file, including a re-run into the existing index.
