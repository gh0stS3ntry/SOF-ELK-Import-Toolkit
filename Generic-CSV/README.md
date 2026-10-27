# Generic CSV importer

`genericcsv2sofelk.py` loads every CSV under a folder into SOF-ELK's Elasticsearch, for CSV exports that have no dedicated importer in `Windows/` or `AWS/`. Field names come from each file's header row. It uses only the Python standard library (3.9+) and the same retrying `_bulk` client as the other importers (`../Windows/common/sof_elk_es_client.py`), so keep `Generic-CSV/` and `Windows/` side by side.

`SOF-ELK_ImportWrapper.py` does not call this script, because it would otherwise load every CSV that a dedicated importer already handles. Run it yourself, on a folder that holds only the CSVs you want here.

| Index | Data View | Template |
|---|---|---|
| `genericcsv-<hostname>` | `genericcsv-*` (created by `SOF-ELK_CreateDataViews.py`) | `index_templates/index-genericcsv.json`, installed as `sofelk-toolkit-genericcsv` |

## Quick start

```bash
# Look first: read every CSV, show the columns, the @timestamp choice and two sample documents
python3 Generic-CSV/genericcsv2sofelk.py /cases/IR-42/RD01/misc-csv --hostname RD01 --dry-run

# Load into the local SOF-ELK
python3 Generic-CSV/genericcsv2sofelk.py /cases/IR-42/RD01/misc-csv --hostname RD01 --case IR-42

# Kibana Data View genericcsv-*, once
python3 SOF-ELK_CreateDataViews.py
```

The folder is searched recursively for `*.csv` (any case). A single `.csv` file also works. Loading the same files again overwrites the earlier documents instead of duplicating them.

## Document layout

Every data row becomes one document:

| Field | Value |
|---|---|
| `<column>` | the cell, as a keyword string, named after the sanitized header (see below); empty cells are left out |
| `@timestamp` | from the timestamp column (see below), else the ingest time |
| `log.file.path` (ECS) | absolute path of the source CSV on the machine that ran the import |
| `event.sequence` | data-row number in that file, from 1 (blank lines are not counted) |
| `event.dataset` / `event.kind` | `genericcsv` / `event` |
| `event.ingested` | time of the import run |
| `host.name` | `--hostname`, lower-cased |
| `case` | `--case`, when given (flat keyword, as in the other importers) |
| `genericcsv.file_name` | the CSV's file name |
| `genericcsv.relative_path` | path of the CSV relative to the folder given on the command line |
| `genericcsv.timestamp_source` | the column `@timestamp` came from, or `ingest_time` |
| `genericcsv.extra_cells` | cells beyond the header's last column, when a row has more cells than its header |

The `_id` is a SHA-1 of the host name, `log.file.path` and the row number, so a re-run of the same files from the same path overwrites. Loading the same files from another path (for example another mount point) creates a second copy, because the path is part of the identity; delete the index first if you move the evidence.

## Field names

Header cells are turned into valid, ES|QL-friendly field names:

- Characters other than letters, digits and `_` become `_` (`Time Created` → `Time_Created`, `user.name` → `user_name`, `Path (Full)` → `Path_Full`). Dots are replaced too, so a CSV column never turns into an object.
- An empty header cell becomes `column_<n>`. A name starting with a digit gets an `f_` prefix (`1st` → `f_1st`).
- Names that the importer writes itself (`host`, `case`, `log`, `event`, `genericcsv`, matched case-insensitively) get a `_csv` suffix (`Host` → `Host_csv`).
- Names that repeat within a file (case-insensitively) get `_2`, `_3`, … (`Event ID`, `event id` → `Event_ID`, `event_id_2`).
- Names longer than 255 bytes are cut to 255.
- The original case is kept, so `TimeCreated` stays `TimeCreated` (ES|QL field names are case-sensitive).

The import lists every renamed header, and `--log-file` records the full run.

## Types

Every CSV column is mapped as `keyword` (values over 8191 characters are kept in `_source` but not indexed). Columns are not type-guessed, so `Count` or `FileSize` are strings: in ES|QL use `TO_LONG(FileSize)` or `TO_DATETIME(...)` where you need numbers or dates. This is what lets unrelated files share one index safely. The index template sets `dynamic: true` with a strings-as-keyword dynamic template, and the importer also maps each new column explicitly before loading.

## Mixed headers across files

All CSVs in the run go to the one `genericcsv-<hostname>` index, whatever their headers:

- The index's fields are the union of all columns seen. A document only has the columns of its own file; columns from other files are simply absent from it (null in ES|QL).
- The same header name in two files is the same field. Because every column is a keyword, two files can never conflict on type, even if one file's `Size` is numeric and another's is text.
- Different spellings are different fields: `UserName` and `User Name` become `UserName` and `User_Name`.
- Each file picks its own `@timestamp` column, so `@timestamp` means different things in different files. Check `genericcsv.timestamp_source` before you put rows from several files on one timeline.
- Filter one source with `log.file.path` or `genericcsv.file_name`:

```esql
FROM genericcsv-* METADATA _index
| STATS rows = COUNT(*) BY _index, genericcsv.file_name, genericcsv.timestamp_source
| SORT _index, genericcsv.file_name
```

- A later run into the same index adds its new columns to the mapping. The index's field limit is 5000; a run that would pass it stops before sending anything. Split the folder with `--exclude`, or load into a separate index with `--index <prefix>-<hostname>`.

## Timestamps

- `--timestamp-column NAME` (repeatable) names the column to use. It matches the original header or the sanitized name, case-insensitively, and the first one present in a file wins.
- Without it, or when none of the names is in a file, the importer samples the first 500 rows. It uses the first column where at least 90% of the non-empty values are dates, preferring columns whose name looks like a time (`TimeCreated`, `LastWriteTimestamp`, `DeletedOn`). Columns with `local` in the name are skipped. `--no-timestamp-detect` turns the guessing off.
- Accepted values are ISO 8601 (`2026-10-25 08:19:00.0483730`, `2026-10-25T08:19:00Z`, `+08:00` offsets, a date alone), and the form Excel writes when it re-saves a CSV (`10/25/2026 8:19 PM`; add `--date-order dmy` for day/month). Epoch numbers are not read as times.
- A time without a zone is read as UTC. Use `--assume-tz +08:00` for an export in local time.
- A row whose timestamp cell is empty or unreadable gets the ingest time, and the summary counts those rows per file.

## Reading CSVs

- The encoding is detected from the byte-order mark (UTF-8 or UTF-16), else UTF-8, else Windows-1252.
- The delimiter is the most common of `,`, tab, `;` and `|` on the header line. An Excel `sep=;` first line is honoured.
- Leading blank lines and PowerShell `#TYPE` or W3C `#Fields` preamble lines are skipped.
- Blank rows are skipped. Quoted cells may contain delimiters and line breaks.

## Options

| Option | Meaning |
|---|---|
| `directory` | folder searched recursively for `*.csv`, or one CSV file |
| `--hostname NAME` | evidence host (required); index `genericcsv-<hostname>` |
| `--case ID` | case ID added to every document as `case` |
| `--index NAME` | another index name; must end in `-<hostname>` |
| `--timestamp-column NAME` | column to use for `@timestamp` (repeatable) |
| `--no-timestamp-detect` | do not guess a date column |
| `--assume-tz OFFSET` | zone for times that carry none (default `Z`) |
| `--date-order mdy\|dmy` | day/month order of spreadsheet-style dates |
| `--exclude GLOB` | skip files whose name or relative path matches (repeatable), e.g. `--exclude '*EvtxECmd*'` |
| `--es URL` | Elasticsearch URL (default `http://localhost:9200`) |
| `--user`, `--password`, `--insecure` | authentication and TLS, as for the other importers |
| `--batch-size N` | documents per `_bulk` request (default 2000) |
| `--dry-run`, `--sample-docs N` | read everything and show sample documents without sending |
| `--max-retries`, `--retry-backoff`, `--timeout`, `--log-file` | retry and logging behaviour of the shared client (see the top-level README) |

An existing `genericcsv-*` index that this importer did not create is refused rather than mixed. Exit status is 0 on success and 1 when Elasticsearch rejected any document.

## Tests

```bash
python3 Generic-CSV/tests/test_genericcsv.py -v
```

The tests need no Elasticsearch. The importer was also run end to end against the toolkit's mock Elasticsearch, with the RD01 KAPE registry, Amcache and RBCmd CSVs.
