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
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib import error, request

CHUNK_SIZE = 1024 * 1024
CSV_SUFFIXES = {".csv"}


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def parse_timestamp(value, formats=()):
    """Normalize ISO / common EZ Tools timestamp to UTC ISO8601 milliseconds."""
    if value is None or isinstance(value, (dict, list, bool)):
        return None
    s = str(value).strip()
    if not s:
        return None
    candidates = [s]
    if s.endswith("Z"):
        candidates.insert(0, s[:-1] + "+00:00")
    for candidate in candidates:
        try:
            parsed = datetime.fromisoformat(candidate)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        except ValueError:
            pass
    for fmt in formats:
        try:
            parsed = datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
            return parsed.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        except ValueError:
            pass
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


class Elasticsearch:
    def __init__(self, url, user=None, password=None, insecure=False, timeout=300):
        self.url = url.rstrip("/")
        self.timeout = timeout
        self.headers = {"Content-Type": "application/json"}
        if user:
            import base64
            token = base64.b64encode(f"{user}:{password or ''}".encode()).decode()
            self.headers["Authorization"] = f"Basic {token}"
        self.ssl_context = ssl._create_unverified_context() if insecure else None

    def call(self, method, path, body=None, content_type=None):
        data = body.encode("utf-8") if isinstance(body, str) else body
        headers = dict(self.headers)
        if content_type:
            headers["Content-Type"] = content_type
        req = request.Request(self.url + path, data=data, method=method, headers=headers)
        try:
            with request.urlopen(req, timeout=self.timeout, context=self.ssl_context) as response:
                status, content = response.status, response.read()
        except error.HTTPError as exc:
            status, content = exc.code, exc.read()
        except error.URLError as exc:
            raise RuntimeError(f"Elasticsearch request failed: {exc.reason}") from exc
        try:
            payload = json.loads(content) if content else {}
        except ValueError:
            payload = {"raw": content.decode("utf-8", "replace")}
        return status, payload

    def root_info(self):
        status, payload = self.call("GET", "/")
        if status >= 300:
            raise RuntimeError(f"Elasticsearch returned HTTP {status}: {payload}")
        return payload

    def ensure_index(self, index, properties):
        status, _ = self.call("HEAD", f"/{index}")
        if status == 200:
            print(f"Using existing index: {index}")
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
        body = "\n".join(lines) + "\n"
        status, payload = self.call("POST", "/_bulk", body, "application/x-ndjson")
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
    parser.add_argument("--hostname", required=True, help="Evidence host; used in the target index name")
    parser.add_argument("--es", default="http://localhost:9200", help="Elasticsearch base URL")
    parser.add_argument("--user", help="Elasticsearch username when authentication is enabled")
    parser.add_argument("--password", help="Elasticsearch password")
    parser.add_argument("--insecure", action="store_true", help="Skip TLS certificate validation")
    parser.add_argument("--batch-size", type=int, default=2000, help="Documents per bulk request")
    parser.add_argument("--workers", type=int, default=2, help="Concurrent bulk requests")
    parser.add_argument("--dry-run", action="store_true", help="Parse/transform records without connecting to Elasticsearch")
    parser.add_argument("--sample-docs", type=int, default=2, help="Print this many transformed sample documents in dry-run mode")


def run_import(args, label_type, index_prefix, patterns, exclude_patterns, mappings, transform,
               csv_int_fields=(), csv_bool_fields=()):
    hostname = sanitize_hostname(args.hostname)
    index = f"{index_prefix}-{hostname}"
    files = discover_files(args.paths, patterns, exclude_patterns)
    if not files:
        raise SystemExit("No matching JSON/CSV output files found (or all input paths were missing).")
    print(f"Tool label: {label_type}\nTarget index: {index}\nFiles: {len(files)}")
    if args.batch_size < 1 or args.workers < 1:
        raise SystemExit("--batch-size and --workers must be positive integers.")
    ingest_time = utc_now()
    dry_samples = max(0, args.sample_docs)
    if args.dry_run:
        total = 0
        for path in files:
            in_file = 0
            try:
                records = iter_input_records(path, csv_int_fields, csv_bool_fields)
                for record in records:
                    if path.suffix.lower() != ".csv":
                        record = normalize_boolean_strings(record)
                    doc = transform(record, path, hostname, label_type, ingest_time)
                    if total < dry_samples:
                        print(json.dumps(doc, ensure_ascii=False, indent=2)[:12000])
                    total += 1
                    in_file += 1
            except (OSError, ValueError, csv.Error) as exc:
                raise SystemExit(f"Failed to parse {path}: {exc}") from exc
            print(f"  {path.name}: {in_file} record(s)")
        print(f"Dry run complete: {total} record(s) parsed; nothing sent to Elasticsearch.")
        return

    es = Elasticsearch(args.es, args.user, args.password, args.insecure)
    try:
        info = es.root_info()
    except RuntimeError as exc:
        raise SystemExit(f"Cannot connect to Elasticsearch at {args.es}: {exc}") from exc
    version = info.get("version", {}).get("number", "unknown")
    print(f"Connected to Elasticsearch {version}")
    created = es.ensure_index(index, nested_mapping(mappings))
    writer = BulkWriter(es, index, args.batch_size, args.workers)
    read_count = 0
    try:
        for path in files:
            per_file = 0
            for ordinal, record in enumerate(iter_input_records(path, csv_int_fields, csv_bool_fields)):
                if path.suffix.lower() != ".csv":
                    record = normalize_boolean_strings(record)
                doc = transform(record, path, hostname, label_type, ingest_time)
                writer.add(document_id(hostname, path, ordinal, record), doc)
                read_count += 1
                per_file += 1
            print(f"  {path.name}: {per_file} record(s) queued")
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
    for reason in stats["examples"]:
        print(f"  Elasticsearch item error: {reason}", file=sys.stderr)
    if stats["errors"]:
        raise SystemExit(2)
    print(f"In Kibana, use the existing {index_prefix}-* Data View with @timestamp as its time field.")
