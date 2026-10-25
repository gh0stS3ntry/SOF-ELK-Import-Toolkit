#!/usr/bin/env python3
"""Shared streaming JSON/CSV and Elasticsearch bulk utilities for SOF-ELK importers."""
from __future__ import annotations
import argparse
import concurrent.futures
import csv
import fnmatch
import gzip
import hashlib
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from sof_elk_es_client import EsClient, add_client_arguments, apply_client_arguments, log  # noqa: E402

CHUNK_SIZE = 1024 * 1024
CSV_SUFFIXES = {".csv"}


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


# EZ Tools write "2023-01-23 06:51:25.5665168" (7-digit fraction, no zone). datetime.fromisoformat
# only accepts that from Python 3.11, so parse the ISO shapes here and keep 3.9+ working.
ISO_TS_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?"
    r"\s*(Z|[+-]\d{2}(?::?\d{2})?)?$",
    re.IGNORECASE,
)


def _format_utc(parsed):
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse_iso(s):
    m = ISO_TS_RE.match(s)
    if not m:
        return None
    year, month, day, hour, minute, second, frac, tz = m.groups()
    micro = int((frac or "0")[:6].ljust(6, "0"))
    tzinfo = timezone.utc
    if tz and tz.upper() != "Z":
        digits = tz[1:].replace(":", "")
        offset = timedelta(hours=int(digits[:2]), minutes=int(digits[2:4] or 0))
        tzinfo = timezone(offset if tz[0] == "+" else -offset)
    try:
        return datetime(int(year), int(month), int(day), int(hour), int(minute), int(second or 0), micro, tzinfo)
    except ValueError:
        return None


def parse_timestamp(value, formats=()):
    """Normalize ISO / common EZ Tools timestamp to UTC ISO8601 milliseconds."""
    if value is None or isinstance(value, (dict, list, bool)):
        return None
    s = str(value).strip()
    if not s:
        return None
    try:
        parsed = _parse_iso(s)
        if parsed is not None:
            return _format_utc(parsed)
    except (OverflowError, ValueError):
        # Year 0001 with a negative offset cannot move to UTC.
        return None
    try:
        return _format_utc(datetime.fromisoformat(s[:-1] + "+00:00" if s.endswith("Z") else s))
    except (OverflowError, ValueError):
        pass
    for fmt in formats:
        try:
            return _format_utc(datetime.strptime(s, fmt))
        except ValueError:
            pass
    return None


class DateStats:
    """Counts date values the importers could not use, so the run can warn instead of dropping them silently."""

    def __init__(self):
        self.reset()

    def reset(self):
        self.empty = {}
        self.invalid = {}
        self.examples = {}
        self.ingest_fallback = 0

    def add_empty(self, field):
        self.empty[field] = self.empty.get(field, 0) + 1

    def add_invalid(self, field, value):
        self.invalid[field] = self.invalid.get(field, 0) + 1
        self.examples.setdefault(field, str(value)[:80])

    def report(self, label, records):
        """Warn (console and --log-file) about omitted dates and ingest-time fallbacks."""
        if self.invalid:
            detail = ", ".join(f"{f}={n} (e.g. {self.examples[f]!r})" for f, n in sorted(self.invalid.items()))
            log.warning("%s: omitted %d unparseable date value(s): %s", label, sum(self.invalid.values()), detail)
        if self.empty:
            detail = ", ".join(f"{f}={n}" for f, n in sorted(self.empty.items()))
            log.warning("%s: omitted %d empty date value(s): %s", label, sum(self.empty.values()), detail)
        if self.ingest_fallback:
            log.warning("%s: @timestamp fell back to ingest time for %d of %d record(s) (no usable source time)",
                        label, self.ingest_fallback, records)

    def merge(self, other):
        for field, n in other.empty.items():
            self.empty[field] = self.empty.get(field, 0) + n
        for field, n in other.invalid.items():
            self.invalid[field] = self.invalid.get(field, 0) + n
            self.examples.setdefault(field, other.examples[field])
        self.ingest_fallback += other.ingest_fallback


# Per-file counters filled by normalize_date_field() and reported by run_import().
DATE_STATS = DateStats()


def get_nested(doc, dotted):
    cur = doc
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def remove_nested(doc, dotted):
    """Remove a dotted field, and any parent objects it leaves empty."""
    parts = dotted.split(".")
    chain = [doc]
    for part in parts[:-1]:
        cur = chain[-1].get(part) if isinstance(chain[-1], dict) else None
        if not isinstance(cur, dict):
            return
        chain.append(cur)
    chain[-1].pop(parts[-1], None)
    for depth in range(len(parts) - 1, 0, -1):
        if chain[depth]:
            break
        chain[depth - 1].pop(parts[depth - 1], None)


def normalize_date_field(doc, dotted, formats=()):
    """Rewrite a date field as UTC ISO8601, or omit it (and count it) when empty or unparseable."""
    value = get_nested(doc, dotted)
    if value is None:
        return None
    normalized = parse_timestamp(value, formats)
    if normalized:
        set_nested(doc, dotted, normalized)
        return normalized
    remove_nested(doc, dotted)
    if isinstance(value, str) and not value.strip():
        DATE_STATS.add_empty(dotted)
    else:
        DATE_STATS.add_invalid(dotted, value)
    return None


def iter_json_records(path, chunk_size=CHUNK_SIZE):
    """Yield records from a top-level JSON array, a JSON object, or concatenated JSON/NDJSON."""
    path = Path(path)
    opener = gzip.open if path.name.lower().endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8-sig", errors="replace", newline="") as fh:
        decoder = json.JSONDecoder()
        buf = ""
        eof = False

        def fill():
            nonlocal buf, eof
            if not eof:
                part = fh.read(chunk_size)
                if part:
                    buf += part
                else:
                    eof = True
            return bool(buf)

        def skip_space(pos):
            while True:
                while pos < len(buf) and buf[pos].isspace():
                    pos += 1
                if pos < len(buf) or eof:
                    return pos
                fill()

        while not buf and not eof:
            fill()
        pos = skip_space(0)
        if pos >= len(buf):
            return
        is_array = buf[pos] == "["
        if is_array:
            pos += 1
        while True:
            pos = skip_space(pos)
            if pos >= len(buf):
                if eof:
                    if is_array:
                        raise ValueError(f"Unexpected end of JSON array in {path}")
                    return
                fill()
                continue
            if is_array:
                if buf[pos] == "]":
                    return
                if buf[pos] == ",":
                    pos += 1
                    continue
            try:
                obj, end = decoder.raw_decode(buf, pos)
            except json.JSONDecodeError as exc:
                if eof:
                    raise ValueError(f"Invalid JSON in {path} near character {pos}: {exc}") from exc
                old_len = len(buf)
                fill()
                if len(buf) == old_len and eof:
                    raise ValueError(f"Invalid or incomplete JSON in {path}: {exc}") from exc
                continue
            if isinstance(obj, dict):
                yield obj
            elif isinstance(obj, list) and not is_array:
                yield {"_value": obj}
            else:
                raise ValueError(f"Expected each top-level record to be a JSON object in {path}; got {type(obj).__name__}")
            pos = end
            if pos >= chunk_size or (pos > 0 and pos > len(buf) // 2):
                buf = buf[pos:]
                pos = 0


def detect_csv_encoding(path: Path) -> str:
    with open(path, "rb") as fh:
        sample = fh.read(4)
    if sample.startswith(b"\xff\xfe") or sample.startswith(b"\xfe\xff"):
        return "utf-16"
    if sample.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    for encoding in ("utf-8", "cp1252"):
        try:
            with open(path, "r", encoding=encoding, errors="strict", newline="") as fh:
                fh.read(65536)
            return encoding
        except UnicodeDecodeError:
            continue
    return "utf-8"


def detect_csv_delimiter(header_line: str) -> str:
    candidates = [",", "\t", ";"]
    return max(candidates, key=header_line.count)


def iter_csv_records(path, int_fields=(), bool_fields=()):
    """Yield CSV rows as dicts, preserving source headers; optionally coerce known scalar types."""
    path = Path(path)
    encoding = detect_csv_encoding(path)
    with open(path, "r", encoding=encoding, errors="replace", newline="") as fh:
        first = fh.readline()
        if not first:
            return
        delimiter = detect_csv_delimiter(first)
        fh.seek(0)
        reader = csv.DictReader(fh, delimiter=delimiter)
        if not reader.fieldnames:
            return
        for row in reader:
            if not any((value or "").strip() for value in row.values()):
                continue
            out = {}
            for raw_key, raw_value in row.items():
                key = (raw_key or "").lstrip("\ufeff")
                value = "" if raw_value is None else raw_value
                if value == "":
                    out[key] = value
                    continue
                if key in bool_fields and value.strip().lower() in {"true", "false"}:
                    out[key] = value.strip().lower() == "true"
                elif key in int_fields:
                    try:
                        out[key] = int(value.strip())
                    except ValueError:
                        out[key] = value
                else:
                    out[key] = value
            yield out


def iter_input_records(path, csv_int_fields=(), csv_bool_fields=()):
    suffix = Path(path).suffix.lower()
    if suffix == ".csv":
        yield from iter_csv_records(path, csv_int_fields, csv_bool_fields)
    else:
        yield from iter_json_records(path)


def normalize_boolean_strings(value):
    """Mirror 1001-preprocess-json's unquoting of JSON true/false string literals."""
    if isinstance(value, dict):
        return {key: normalize_boolean_strings(item) for key, item in value.items()}
    if isinstance(value, list):
        return [normalize_boolean_strings(item) for item in value]
    if isinstance(value, str):
        if value.lower() == "true":
            return True
        if value.lower() == "false":
            return False
    return value


def sanitize_hostname(hostname):
    value = re.sub(r"[^a-z0-9._-]+", "-", hostname.strip().lower()).strip("._-")
    if not value:
        raise ValueError("--hostname must contain at least one letter or digit")
    return value


def stable_filename(path):
    return re.sub(r"^\d{8,}_", "", Path(path).name)


def discover_files(inputs, patterns, exclude_patterns=()):
    """Expand explicit JSON/CSV files and recursively search folders for matching names."""
    found = set()
    for raw in inputs:
        p = Path(raw)
        if not p.exists():
            print(f"WARN: input not found, skipping: {p}", file=sys.stderr)
            continue
        if p.is_file():
            name = p.name.lower()
            if (name.endswith((".json", ".json.gz", ".csv")) and
                    any(fnmatch.fnmatch(name, pat.lower()) for pat in patterns) and
                    not any(fnmatch.fnmatch(name, pat.lower()) for pat in exclude_patterns)):
                found.add(p.resolve())
            else:
                print(f"WARN: input file does not match supported importer patterns, skipping: {p}", file=sys.stderr)
            continue
        for candidate in p.rglob("*"):
            if not candidate.is_file():
                continue
            name = candidate.name.lower()
            if any(fnmatch.fnmatch(name, pat.lower()) for pat in patterns) and not any(
                fnmatch.fnmatch(name, pat.lower()) for pat in exclude_patterns
            ):
                found.add(candidate.resolve())
    return sorted(found, key=lambda x: str(x).lower())


def set_nested(doc, dotted_path, value):
    parts = dotted_path.split(".")
    cur = doc
    for part in parts[:-1]:
        existing = cur.get(part)
        if not isinstance(existing, dict):
            existing = {}
            cur[part] = existing
        cur = existing
    cur[parts[-1]] = value


def base_event(raw, source_path, hostname, label_type, ingest_time):
    source_path = str(Path(source_path).resolve())
    doc = {
        "@timestamp": ingest_time,
        "labels": {"type": label_type},
        "log": {"file": {"path": source_path}},
        "sof-elk": {"path": f"filebeat: {source_path}"},
    }
    original_tags = raw.get("tags")
    tags = []
    if isinstance(original_tags, list):
        tags.extend(x for x in original_tags if x != "json")
    elif isinstance(original_tags, str) and original_tags and original_tags != "json":
        tags.append(original_tags)
    if tags:
        doc["tags"] = list(dict.fromkeys(tags))
    return doc


def add_tag(doc, tag):
    tags = doc.setdefault("tags", [])
    if tag not in tags:
        tags.append(tag)


def copy_renames(raw, doc, renames):
    for source, target in renames.items():
        if source in raw and raw[source] is not None:
            set_nested(doc, target, raw[source])


def document_id(hostname, path, ordinal, raw):
    stable = stable_filename(path)
    payload = json.dumps([hostname, stable, ordinal, raw], ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha1(payload.encode("utf-8", "replace")).hexdigest()


def nested_mapping(dotted_properties):
    root = {}
    for dotted, spec in dotted_properties.items():
        parts = dotted.split(".")
        cur = root
        for part in parts[:-1]:
            node = cur.setdefault(part, {"properties": {}})
            if "properties" not in node:
                node["properties"] = {}
            cur = node["properties"]
        cur[parts[-1]] = spec
    return root


# Fields every JSON importer adds so documents can be attributed without relying on _index.
HOST_CASE_MAPPINGS = {"host.name": {"type": "keyword"}, "case": {"type": "keyword", "ignore_above": 1024}}


class Elasticsearch:
    def __init__(self, url, user=None, password=None, insecure=False):
        self.client = EsClient(url, user, password, insecure)

    def call(self, method, path, body=None, content_type=None):
        """(status, payload); timeouts, connection errors and HTTP 429/5xx are retried."""
        try:
            return self.client.request(method, path, body, content_type or "application/json")
        except OSError as exc:
            raise RuntimeError(f"Elasticsearch request failed: {getattr(exc, 'reason', exc)}") from exc

    def root_info(self):
        status, payload = self.call("GET", "/")
        if status >= 300:
            raise RuntimeError(f"Elasticsearch returned HTTP {status}: {payload}")
        return payload

    def ensure_index(self, index, properties):
        status, _ = self.call("HEAD", f"/{index}")
        if status == 200:
            print(f"Using existing index: {index}")
            # Indexes created before host.name/case were written get explicit keyword mappings.
            status, payload = self.call("PUT", f"/{index}/_mapping", json.dumps(
                {"properties": nested_mapping(HOST_CASE_MAPPINGS)}, separators=(",", ":")))
            if status >= 300:
                print(f"WARN: could not add host.name/case keyword mappings to {index}: {payload}", file=sys.stderr)
            return False
        body = {
            "settings": {
                "number_of_replicas": 0,
                "refresh_interval": "-1",
                "index.mapping.total_fields.limit": 5000,
                "index.mapping.ignore_malformed": True,
            },
            "mappings": {
                "date_detection": False,
                "numeric_detection": False,
                "dynamic_templates": [{"strings_as_text_and_keyword": {
                    "match_mapping_type": "string",
                    "mapping": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 2048}}},
                }}],
                "properties": properties,
            },
        }
        status, payload = self.call("PUT", f"/{index}", json.dumps(body, separators=(",", ":")))
        if status >= 300:
            raise RuntimeError(f"Could not create index {index} (HTTP {status}): {payload}")
        print(f"Created index: {index} (refresh disabled during initial bulk load)")
        return True

    def bulk(self, index, lines):
        """Send one batch; rejected (429/5xx) items are retried by EsClient.bulk."""
        try:
            status, payload = self.client.bulk(lines)
        except OSError as exc:
            raise RuntimeError(f"Bulk request failed: {getattr(exc, 'reason', exc)}") from exc
        if status >= 300:
            raise RuntimeError(f"Bulk request failed (HTTP {status}): {payload}")
        ok = errors_count = 0
        examples = []
        for item in payload.get("items", []):
            result = next(iter(item.values()), {})
            if "error" in result:
                errors_count += 1
                if len(examples) < 5:
                    examples.append(result.get("error", {}).get("reason", str(result.get("error"))))
            else:
                ok += 1
        return ok, errors_count, examples

    def finish_index(self, index, was_created):
        if was_created:
            status, payload = self.call("PUT", f"/{index}/_settings", json.dumps({"index": {"refresh_interval": "1s"}}))
            if status >= 300:
                print(f"WARN: could not restore refresh_interval on {index}: {payload}", file=sys.stderr)
        status, payload = self.call("POST", f"/{index}/_refresh")
        if status >= 300:
            print(f"WARN: refresh failed for {index}: {payload}", file=sys.stderr)


class BulkWriter:
    def __init__(self, es, index, batch_size=2000, workers=2):
        self.es, self.index = es, index
        self.batch_size = max(1, batch_size)
        self.workers = max(1, workers)
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=self.workers)
        self.pending = []
        self.lines = []
        self.in_batch = 0
        self.ok = self.errors = 0
        self.examples = []
        self.submitted = 0

    def add(self, doc_id, doc):
        self.lines.append(json.dumps({"index": {"_index": self.index, "_id": doc_id}}, separators=(",", ":")))
        self.lines.append(json.dumps(doc, ensure_ascii=False, separators=(",", ":")))
        self.in_batch += 1
        if self.in_batch >= self.batch_size:
            self.flush()

    def flush(self):
        if not self.lines:
            return
        payload = self.lines
        self.lines = []
        self.in_batch = 0
        self.pending.append(self.pool.submit(self.es.bulk, self.index, payload))
        self.submitted += 1
        if len(self.pending) >= self.workers * 2:
            self._collect_one()

    def _collect_one(self):
        future = self.pending.pop(0)
        ok, errors_count, examples = future.result()
        self.ok += ok
        self.errors += errors_count
        self.examples.extend(examples[:max(0, 5 - len(self.examples))])

    def finish(self):
        self.flush()
        while self.pending:
            self._collect_one()
        self.pool.shutdown(wait=True)
        return {"ok": self.ok, "errors": self.errors, "batches": self.submitted, "examples": self.examples}


def add_common_arguments(parser, description):
    parser.description = description
    parser.add_argument("paths", nargs="+", help="JSON or CSV output file(s), or folders to search recursively")
    parser.add_argument("--hostname", required=True, help="Evidence host; used in the target index name and host.name")
    parser.add_argument("--case", help="Optional case/incident ID added to every document as case")
    parser.add_argument("--es", default="http://localhost:9200", help="Elasticsearch base URL")
    parser.add_argument("--user", help="Elasticsearch username when authentication is enabled")
    parser.add_argument("--password", help="Elasticsearch password")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS certificate validation")
    parser.add_argument("--batch-size", type=int, default=2000, help="Documents per bulk request")
    parser.add_argument("--workers", type=int, default=2, help="Concurrent bulk requests")
    parser.add_argument("--dry-run", action="store_true", help="Parse/transform records without connecting to Elasticsearch")
    parser.add_argument("--sample-docs", type=int, default=2, help="Print this many transformed sample documents in dry-run mode")
    add_client_arguments(parser)


def add_host_and_case(doc, hostname, case):
    """host.name and case match the CSV importers, so ES|QL can filter every index the same way."""
    host = doc.get("host")
    if not isinstance(host, dict):
        host = doc["host"] = {}
    host["name"] = hostname
    if case:
        doc["case"] = case
    return doc


def run_import(args, label_type, index_prefix, patterns, exclude_patterns, mappings, transform,
               csv_int_fields=(), csv_bool_fields=()):
    apply_client_arguments(args)
    hostname = sanitize_hostname(args.hostname)
    index = f"{index_prefix}-{hostname}"
    case = (args.case or "").strip() or None
    files = discover_files(args.paths, patterns, exclude_patterns)
    if not files:
        raise SystemExit("No matching JSON/CSV output files found (or all input paths were missing).")
    print(f"Tool label: {label_type}\nTarget index: {index}\nFiles: {len(files)}")
    log.info("start: label=%s index=%s files=%d case=%s dry_run=%s", label_type, index, len(files), case, args.dry_run)
    if args.batch_size < 1 or args.workers < 1:
        raise SystemExit("--batch-size and --workers must be positive integers.")
    ingest_time = utc_now()
    dry_samples = max(0, args.sample_docs)
    run_dates = DateStats()
    DATE_STATS.reset()
    if args.dry_run:
        total = 0
        for path in files:
            in_file = 0
            try:
                records = iter_input_records(path, csv_int_fields, csv_bool_fields)
                for record in records:
                    if path.suffix.lower() != ".csv":
                        record = normalize_boolean_strings(record)
                    doc = add_host_and_case(transform(record, path, hostname, label_type, ingest_time), hostname, case)
                    if doc.get("@timestamp") == ingest_time:
                        DATE_STATS.ingest_fallback += 1
                    if total < dry_samples:
                        print(json.dumps(doc, ensure_ascii=False, indent=2)[:12000])
                    total += 1
                    in_file += 1
            except (OSError, ValueError, csv.Error) as exc:
                raise SystemExit(f"Failed to parse {path}: {exc}") from exc
            print(f"  {path.name}: {in_file} record(s)")
            run_dates.merge(DATE_STATS)
            DATE_STATS.report(path.name, in_file)
            DATE_STATS.reset()
        print(f"Dry run complete: {total} record(s) parsed; nothing sent to Elasticsearch.")
        if len(files) > 1:
            run_dates.report("all files", total)
        return

    es = Elasticsearch(args.es, args.user, args.password, args.insecure)
    try:
        info = es.root_info()
    except RuntimeError as exc:
        raise SystemExit(f"Cannot connect to Elasticsearch at {args.es}: {exc}") from exc
    version = info.get("version", {}).get("number", "unknown")
    print(f"Connected to Elasticsearch {version}")
    created = es.ensure_index(index, nested_mapping({**mappings, **HOST_CASE_MAPPINGS}))
    writer = BulkWriter(es, index, args.batch_size, args.workers)
    read_count = 0
    try:
        for path in files:
            per_file = 0
            for ordinal, record in enumerate(iter_input_records(path, csv_int_fields, csv_bool_fields)):
                if path.suffix.lower() != ".csv":
                    record = normalize_boolean_strings(record)
                doc = add_host_and_case(transform(record, path, hostname, label_type, ingest_time), hostname, case)
                if doc.get("@timestamp") == ingest_time:
                    DATE_STATS.ingest_fallback += 1
                writer.add(document_id(hostname, path, ordinal, record), doc)
                read_count += 1
                per_file += 1
            print(f"  {path.name}: {per_file} record(s) queued")
            run_dates.merge(DATE_STATS)
            DATE_STATS.report(path.name, per_file)
            DATE_STATS.reset()
        stats = writer.finish()
    except Exception:
        try:
            stats = writer.finish()
            print(f"Partial bulk results: {stats['ok']} indexed, {stats['errors']} item errors", file=sys.stderr)
        except Exception:
            pass
        raise
    finally:
        es.finish_index(index, created)
    print(f"Done: {read_count} record(s), {stats['ok']} successful bulk items, {stats['errors']} item errors, {stats['batches']} bulk request(s).")
    log.info("done: index=%s records=%d ok=%d errors=%d batches=%d", index, read_count, stats["ok"], stats["errors"], stats["batches"])
    if len(files) > 1:
        run_dates.report("all files", read_count)
    for reason in stats["examples"]:
        print(f"  Elasticsearch item error: {reason}", file=sys.stderr)
    if stats["errors"]:
        raise SystemExit(2)
    print(f"In Kibana, use the existing {index_prefix}-* Data View with @timestamp as its time field.")
