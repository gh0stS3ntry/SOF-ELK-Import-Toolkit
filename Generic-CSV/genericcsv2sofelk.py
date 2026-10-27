#!/usr/bin/env python3
"""genericcsv2sofelk.py - load every CSV under a directory into genericcsv-<hostname>.

For CSV exports that have no dedicated importer. The script walks the given folder
recursively, reads each CSV's header row, and indexes one document per data row with
the header names (sanitized for Elasticsearch) as field names:

  * every CSV column is a keyword string, so files with different headers can share
    one index without type conflicts (see Generic-CSV/README.md);
  * log.file.path (ECS) holds the absolute path of the source CSV, and event.sequence
    its data-row number;
  * host.name, the flat `case` keyword and event.dataset=genericcsv are added like the
    other toolkit importers;
  * @timestamp comes from --timestamp-column, or from a date column found
    automatically, or from the ingest time when no column holds usable dates;
  * documents get a deterministic _id (host + file path + row number), so loading the
    same files again overwrites instead of duplicating;
  * traffic goes through the shared retrying _bulk client in
    ../Windows/common/sof_elk_es_client.py.

Standard library only. This importer is deliberately not called by
SOF-ELK_ImportWrapper.py: point it at a folder of CSVs yourself.
"""
from __future__ import annotations

import argparse
import codecs
import csv
import datetime as dt
import fnmatch
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from urllib import error

HERE = Path(__file__).resolve().parent
TEMPLATE_PATH = HERE / "index_templates" / "index-genericcsv.json"
PREFIX = "genericcsv"
TEMPLATE_NAME = f"sofelk-toolkit-{PREFIX}"

# The retrying bulk client is shared with the Windows and AWS importers.
sys.path.insert(0, str(HERE.parent / "Windows" / "common"))
from sof_elk_es_client import EsClient, add_client_arguments, apply_client_arguments, resolve_index  # noqa: E402

try:
    csv.field_size_limit(sys.maxsize)
except OverflowError:
    csv.field_size_limit(2**31 - 1)

# Top-level names the importer writes itself. A CSV column whose sanitized name equals
# one of these (case-insensitively) gets a "_csv" suffix instead of overwriting it.
RESERVED = {"host", "case", "log", "event", "genericcsv"}
MAX_FIELD_BYTES = 255
SAMPLE_ROWS = 500          # rows inspected per file to pick the @timestamp column
DATE_HIT_RATIO = 0.9       # share of sampled non-empty values that must parse as dates

TIME_NAME_RE = re.compile(
    r"time|date|stamp|created|modified|accessed|written|executed|installed|deleted|"
    r"start|end|first|last|seen|when", re.I)
LOCAL_RE = re.compile(r"local", re.I)
ISO_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?\s*(Z|UTC|[+-]\d{2}:?\d{2})?$", re.I)
ISO_DATE_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})$")
SLASH_RE = re.compile(
    r"^(\d{1,2})/(\d{1,2})/(\d{4})(?:\s+(\d{1,2}):(\d{2})(?::(\d{2})(?:\.(\d+))?)?\s*([AaPp][Mm])?)?$")


# --------------------------------------------------------------------------- helpers

def sanitize_hostname(value):
    host = re.sub(r"[^a-z0-9._-]+", "-", (value or "").strip().lower()).strip("._-")
    if not host:
        raise SystemExit("ERROR: --hostname must contain at least one letter or digit")
    return host


def normalize_tz(value):
    """'Z', '+08:00' or '-0500' -> 'Z' / '+08:00' / '-05:00'."""
    v = (value or "Z").strip()
    if v.upper() in ("Z", "UTC"):
        return "Z"
    m = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", v)
    if not m:
        raise SystemExit(f"ERROR: --assume-tz '{value}' must be Z or an offset such as +08:00")
    return f"{m.group(1)}{m.group(2)}:{m.group(3)}"


def parse_time(value, default_tz="Z", date_order="mdy"):
    """ISO 8601 or spreadsheet-style (10/25/2026 8:19 AM) time -> ISO string, else None.

    A value without a time zone is read in default_tz.
    """
    v = (value or "").strip()
    if not v:
        return None
    m = ISO_RE.match(v)
    if m:
        y, mo, d, h, mi, s, frac, tz = m.groups()
        parts = (int(y), int(mo), int(d), int(h), int(mi), int(s or 0))
        if tz:
            tz = "Z" if tz.upper() in ("Z", "UTC") else (tz if ":" in tz else tz[:3] + ":" + tz[3:])
    else:
        m = ISO_DATE_RE.match(v)
        if m:
            parts, frac, tz = (int(m.group(1)), int(m.group(2)), int(m.group(3)), 0, 0, 0), None, None
        else:
            m = SLASH_RE.match(v)
            if not m:
                return None
            a, b, y, h, mi, s, frac, ampm = m.groups()
            mo, d = (int(a), int(b)) if date_order == "mdy" else (int(b), int(a))
            hour = int(h or 0)
            if ampm:
                if not 1 <= hour <= 12:
                    return None
                hour = hour % 12 + (12 if ampm.lower() == "pm" else 0)
            parts, tz = (int(y), mo, d, hour, int(mi or 0), int(s or 0)), None
    try:
        dt.datetime(*parts)
    except ValueError:
        return None
    ms = (frac or "")[:3].ljust(3, "0")
    return "%04d-%02d-%02dT%02d:%02d:%02d.%s%s" % (*parts, ms, tz or default_tz)


def sanitize_columns(header):
    """Header cells -> unique Elasticsearch field names (see README: Field names)."""
    used, out = set(), []
    for n, raw in enumerate(header, 1):
        name = re.sub(r"[^A-Za-z0-9_]+", "_", (raw or "").strip().lstrip("﻿")).strip("_")
        if not name:
            name = f"column_{n}"
        if name[0].isdigit():
            name = "f_" + name
        if name.lower() in RESERVED:
            name += "_csv"
        name = name.encode("utf-8")[:MAX_FIELD_BYTES].decode("utf-8", "ignore")
        base, i = name, 2
        while name.lower() in used:
            name = f"{base}_{i}"
            i += 1
        used.add(name.lower())
        out.append(name)
    return out


def detect_encoding(path):
    with open(path, "rb") as fh:
        head = fh.read(65536)
    if head.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "utf-16"
    try:
        # final=False: the 64 KiB sample may end inside a multi-byte character
        codecs.getincrementaldecoder("utf-8")().decode(head, final=len(head) < 65536)
        return "utf-8"
    except UnicodeDecodeError:
        return "cp1252"


class CsvFile:
    """One CSV: encoding, delimiter, header, and a fresh row iterator on each rows() call."""

    def __init__(self, path):
        self.path = path
        self.encoding = detect_encoding(path)
        self.header, self.delimiter, self.skip = [], ",", 0
        with self.open() as fh:
            delimiter = None
            for line in fh:
                self.skip += 1
                text = line.strip().lstrip("﻿")
                if not text:
                    continue
                low = text.lower()
                if low.startswith("sep=") and len(text) >= 5:   # Excel delimiter hint
                    delimiter = text[4]
                    continue
                if low.startswith("#type") or low.startswith("#fields"):   # PowerShell / W3C preamble
                    continue
                self.delimiter = delimiter or max((",", "\t", ";", "|"), key=text.count)
                self.header = next(csv.reader([line], delimiter=self.delimiter), [])
                break
        while self.header and not (self.header[-1] or "").strip():
            self.header.pop()   # trailing delimiter on the header line
        self.fields = sanitize_columns(self.header)

    def open(self):
        return open(self.path, "r", encoding=self.encoding, errors="replace", newline="")

    def rows(self):
        """(row_number, cells) for each non-blank data row; row_number counts data rows from 1."""
        with self.open() as fh:
            for _ in range(self.skip):
                fh.readline()
            n = 0
            for cells in csv.reader(fh, delimiter=self.delimiter):
                if not any((c or "").strip() for c in cells):
                    continue
                n += 1
                yield n, cells


def find_csv_files(root, excludes):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort(key=str.lower)
        for name in sorted(filenames, key=str.lower):
            if not name.lower().endswith(".csv"):
                continue
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            if any(fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(name, pat) for pat in excludes):
                continue
            out.append(path)
    return out


def choose_timestamp(csvf, wanted, detect, default_tz, date_order):
    """Column index for @timestamp, or None.

    wanted is the --timestamp-column list (first match wins); when none matches and detect
    is true, the first column whose sampled values are nearly all dates is used, preferring
    columns whose name looks like a time (TimeCreated, LastWriteTimestamp, ...).
    """
    fields_low = [f.lower() for f in csvf.fields]
    header_low = [(h or "").strip().lower() for h in csvf.header]
    for name in wanted:
        key = name.strip().lower()
        for idx in range(len(csvf.fields)):
            if key in (fields_low[idx], header_low[idx]):
                return idx
    if not detect:
        return None
    candidates = [i for i, f in enumerate(csvf.fields) if not LOCAL_RE.search(f)]
    named = [i for i in candidates if TIME_NAME_RE.search(csvf.fields[i])]
    others = [i for i in candidates if i not in named]
    hits = {i: 0 for i in candidates}
    seen = {i: 0 for i in candidates}
    for n, cells in csvf.rows():
        if n > SAMPLE_ROWS:
            break
        for i in candidates:
            if i < len(cells) and (cells[i] or "").strip():
                seen[i] += 1
                if parse_time(cells[i], default_tz, date_order):
                    hits[i] += 1
    for i in named + others:
        if seen[i] and hits[i] / seen[i] >= DATE_HIT_RATIO:
            return i
    return None


def make_doc(csvf, row_number, cells, *, abs_path, rel_path, hostname, case, ts_index,
             default_tz, date_order, ingested):
    doc = {}
    for i, field in enumerate(csvf.fields):
        if i < len(cells) and (cells[i] or "").strip():
            doc[field] = cells[i]
    extra = [c for c in cells[len(csvf.fields):] if (c or "").strip()]
    ts = None
    if ts_index is not None and ts_index < len(cells):
        ts = parse_time(cells[ts_index], default_tz, date_order)
    doc["@timestamp"] = ts or ingested
    doc["host"] = {"name": hostname}
    doc["event"] = {"dataset": PREFIX, "kind": "event", "ingested": ingested, "sequence": row_number}
    doc["log"] = {"file": {"path": abs_path}}
    meta = {"file_name": csvf.path.name, "relative_path": rel_path,
            "timestamp_source": csvf.fields[ts_index] if ts else "ingest_time"}
    if extra:
        meta["extra_cells"] = extra
    doc["genericcsv"] = meta
    if case:
        doc["case"] = case
    return doc


def doc_id(hostname, abs_path, row_number):
    material = json.dumps([PREFIX, hostname, abs_path, row_number], ensure_ascii=False)
    return hashlib.sha1(material.encode("utf-8", "replace")).hexdigest()


# --------------------------------------------------------------------------- Elasticsearch

class ES(EsClient):
    def call(self, method, path, body=None):
        return self.request(method, path, body)

    def install_template(self, template):
        status, resp = self.call("PUT", f"/_index_template/{TEMPLATE_NAME}", template)
        if status >= 300:
            sys.exit(f"Could not install index template {TEMPLATE_NAME} ({status}): {json.dumps(resp)[:500]}")

    def prepare_index(self, index, template, columns):
        """Create the index (from the template) or check an existing one; map new columns as keyword."""
        body = template["template"]
        status, _ = self.call("HEAD", f"/{index}")
        state = "appending"
        if status == 404:
            status, resp = self.call("PUT", f"/{index}", {"settings": {"index": {"refresh_interval": "-1"}}})
            if status >= 300:
                sys.exit(f"Could not create index {index} ({status}): {json.dumps(resp)[:500]}")
            state = "created"
        elif status >= 300:
            sys.exit(f"Could not check index {index} (HTTP {status})")
        status, resp = self.call("GET", f"/{index}/_mapping")
        if status >= 300:
            sys.exit(f"Could not read mapping of {index} ({status}): {json.dumps(resp)[:500]}")
        mapping = next(iter(resp.values()), {}).get("mappings", {})
        if mapping.get("_meta", {}).get("toolkit_schema") != PREFIX:
            sys.exit(f"Index '{index}' exists but was not created by this importer, so its field"
                     f" types may differ.\nDelete it and reload:  curl -X DELETE '{self.url}/{index}'\n"
                     f"or load into another index with --index <prefix>-<hostname>.")
        props = mapping.get("properties", {})
        not_keyword = sorted(c for c in columns if c in props and props[c].get("type") != "keyword")
        if not_keyword:
            print(f"WARNING: these columns already exist in '{index}' with a non-keyword type and"
                  f" their values may be rejected or ignored: {', '.join(not_keyword[:20])}")
        new_cols = sorted(c for c in columns if c not in props)
        limit = int(body["settings"]["index"]["mapping"]["total_fields"]["limit"])
        if len(props) + len(new_cols) + 20 > limit:
            sys.exit(f"Index '{index}' would need about {len(props) + len(new_cols) + 20} fields, over"
                     f" its limit of {limit}. Split the folder (--exclude) or load into another"
                     f" index with --index <prefix>-<hostname>.")
        explicit = {"properties": body["mappings"]["properties"]}
        for col in new_cols:
            explicit["properties"][col] = {"type": "keyword", "ignore_above": 8191}
        status, resp = self.call("PUT", f"/{index}/_mapping", explicit)
        if status >= 300:
            sys.exit(f"Could not update the mapping of {index} ({status}): {json.dumps(resp)[:500]}")
        return state, len(new_cols)

    def send(self, lines, stats):
        if not lines:
            return
        status, resp = self.bulk(lines)
        if status >= 300:
            sys.exit(f"Bulk request failed ({status}): {json.dumps(resp)[:500]}")
        for item in resp.get("items", []):
            res = next(iter(item.values()))
            if "error" in res:
                stats["errors"] += 1
                if stats["errors"] <= 5:
                    err = res["error"]
                    print(f"    ! {err.get('reason', err) if isinstance(err, dict) else err}", file=sys.stderr)
            else:
                stats["ok"] += 1
                if res.get("result") == "updated":
                    stats["updated"] += 1
        lines.clear()

    def finish(self, index):
        self.call("PUT", f"/{index}/_settings", {"index": {"refresh_interval": "1s"}})
        self.call("POST", f"/{index}/_refresh")
        status, resp = self.call("POST", f"/{index}/_count", {"query": {"match_all": {}}})
        return resp.get("count") if status < 300 else None


# --------------------------------------------------------------------------- main

def build_parser():
    ap = argparse.ArgumentParser(
        description="Import every CSV under a directory into genericcsv-<hostname>, with field"
                    " names taken from each file's header row.")
    ap.add_argument("directory", help="Folder searched recursively for *.csv files (a single .csv file also works)")
    ap.add_argument("--hostname", required=True, help="Evidence host name; the index is genericcsv-<hostname>")
    ap.add_argument("--case", help="Optional case/incident ID added to every document as `case`")
    ap.add_argument("--index", help="Override the target index; must end in -<hostname>")
    ap.add_argument("--timestamp-column", action="append", default=[], metavar="NAME",
                    help="Header name to use for @timestamp (repeatable; the first one present in"
                         " a file wins). Without it a date column is detected per file.")
    ap.add_argument("--no-timestamp-detect", action="store_true",
                    help="Do not guess a date column; @timestamp is the ingest time unless"
                         " --timestamp-column matches")
    ap.add_argument("--assume-tz", default="Z",
                    help="Time zone for timestamps that carry none (default Z = UTC, e.g. +08:00)")
    ap.add_argument("--date-order", choices=("mdy", "dmy"), default="mdy",
                    help="Day/month order of spreadsheet-style dates such as 10/25/2026 8:19 AM")
    ap.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                    help="Skip files whose name or relative path matches this glob (repeatable),"
                         " e.g. --exclude '*EvtxECmd*'")
    ap.add_argument("--es", default="http://localhost:9200", help="Elasticsearch URL")
    ap.add_argument("--user", help="Elasticsearch username, if security is enabled")
    ap.add_argument("--password")
    ap.add_argument("--insecure", action="store_true", help="Skip TLS certificate checks")
    ap.add_argument("--batch-size", type=int, default=2000, help="Documents per bulk request")
    ap.add_argument("--dry-run", action="store_true", help="Read every file and show sample documents; send nothing")
    ap.add_argument("--sample-docs", type=int, default=2, help="Sample documents shown by --dry-run")
    add_client_arguments(ap)
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    apply_client_arguments(args)
    if args.batch_size < 1:
        sys.exit("--batch-size must be a positive integer")
    hostname = sanitize_hostname(args.hostname)
    index = resolve_index(PREFIX, hostname, args.index)
    default_tz = normalize_tz(args.assume_tz)
    try:
        template = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        sys.exit(f"Cannot read index template {TEMPLATE_PATH}: {exc}")

    root = Path(args.directory).expanduser().resolve()
    if root.is_file():
        files, root = ([root] if root.suffix.lower() == ".csv" else []), root.parent
    elif root.is_dir():
        files = find_csv_files(root, args.exclude)
    else:
        sys.exit(f"No such file or directory: {args.directory}")
    if not files:
        sys.exit(f"No CSV files found under {root}")

    # Pass 1: header, field names and timestamp column of every file.
    plans, columns, renamed = [], {}, {}
    for path in files:
        rel = path.relative_to(root).as_posix()
        try:
            csvf = CsvFile(path)
        except OSError as exc:
            print(f"  ! {rel}: cannot read ({exc}); skipped", file=sys.stderr)
            continue
        if not csvf.header:
            print(f"  - {rel}: empty file; skipped")
            continue
        ts_index = choose_timestamp(csvf, args.timestamp_column, not args.no_timestamp_detect,
                                    default_tz, args.date_order)
        for raw, field in zip(csvf.header, csvf.fields):
            columns.setdefault(field, 0)
            columns[field] += 1
            if (raw or "").strip() != field:
                renamed.setdefault(field, set()).add((raw or "").strip())
        plans.append((csvf, rel, ts_index))
    if not plans:
        sys.exit("No CSV file with a header row was found.")

    print(f"{len(plans)} CSV file(s) under {root} -> index '{index}' (host '{hostname}')")
    print(f"{len(columns)} distinct column(s) across all files, all mapped as keyword")
    if renamed:
        print("Header names changed to valid field names:")
        for field, raws in sorted(renamed.items())[:40]:
            print(f"  {' | '.join(sorted(raws))!s:<40} -> {field}")
        if len(renamed) > 40:
            print(f"  ... and {len(renamed) - 40} more (see --log-file)")
    partial = sorted(f for f, n in columns.items() if n < len(plans))
    if partial and len(plans) > 1:
        print(f"{len(partial)} column(s) appear in only some files; documents from the other files"
              " simply do not have them.")

    es = None
    if not args.dry_run:
        es = ES(args.es, args.user, args.password, args.insecure)
        try:
            status, info = es.call("GET", "/")
        except error.URLError as exc:
            sys.exit(f"\nCannot reach Elasticsearch at {args.es}: {exc.reason}")
        if status >= 300:
            sys.exit(f"\nElasticsearch returned {status}: {json.dumps(info)[:300]}")
        print(f"Connected to Elasticsearch {info.get('version', {}).get('number', '?')} at {args.es}")
        es.install_template(template)
        print(f"Installed index template '{TEMPLATE_NAME}' ({PREFIX}-*)")
        state, n_new = es.prepare_index(index, template, columns)
        print(f"Index '{index}': {state}, {n_new} new column field(s) mapped")

    # Pass 2: stream the rows.
    ingested = dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    total = {"rows": 0, "ok": 0, "errors": 0, "updated": 0, "ingest_ts": 0, "extra": 0}
    samples, lines = [], []
    print()
    for csvf, rel, ts_index in plans:
        abs_path = str(csvf.path)
        rows = no_ts = 0
        try:
            for row_number, cells in csvf.rows():
                doc = make_doc(csvf, row_number, cells, abs_path=abs_path, rel_path=rel,
                               hostname=hostname, case=args.case, ts_index=ts_index,
                               default_tz=default_tz, date_order=args.date_order, ingested=ingested)
                rows += 1
                if doc["genericcsv"]["timestamp_source"] == "ingest_time":
                    no_ts += 1
                if "extra_cells" in doc["genericcsv"]:
                    total["extra"] += 1
                if args.dry_run:
                    if len(samples) < args.sample_docs:
                        samples.append(doc)
                    continue
                lines.append(json.dumps({"index": {"_index": index, "_id": doc_id(hostname, abs_path, row_number)}}))
                lines.append(json.dumps(doc, ensure_ascii=False))
                if len(lines) >= args.batch_size * 2:
                    es.send(lines, total)
        except (OSError, csv.Error) as exc:
            print(f"  ! {rel}: stopped after {rows} row(s): {exc}", file=sys.stderr)
        total["rows"] += rows
        total["ingest_ts"] += no_ts
        ts_note = (f"@timestamp <- {csvf.fields[ts_index]}" if ts_index is not None
                   else "@timestamp <- ingest time")
        if ts_index is not None and no_ts:
            ts_note += f" ({no_ts} row(s) without a usable value use the ingest time)"
        print(f"  {rel}: {rows} row(s), {len(csvf.fields)} column(s), {ts_note}")
    if es is not None:
        es.send(lines, total)

    if total["extra"]:
        print(f"\nnote: {total['extra']} row(s) had more cells than their header; the extra cells"
              " are in genericcsv.extra_cells.")

    if args.dry_run:
        print(f"\n{total['rows']} row(s) read. Sample document(s):")
        for doc in samples:
            print("  " + json.dumps(doc, ensure_ascii=False)[:1500])
        print("\nDry run only - nothing sent.")
        return 0

    new = total["ok"] - total["updated"]
    print(f"\nDone: {total['rows']} row(s) read -> {new} new document(s), {total['updated']} already"
          f" in the index (re-run), {total['errors']} error(s).")
    in_index = es.finish(index)
    if in_index is not None:
        print(f"Index '{index}' now holds {in_index} document(s).")
    print(f"In Kibana, use the '{PREFIX}-*' data view (time field @timestamp).")
    return 1 if total["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
