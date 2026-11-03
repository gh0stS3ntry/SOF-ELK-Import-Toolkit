#!/usr/bin/env python3
"""genericjson2sofelk.py - load every JSON file under a directory into genericjson-<hostname>.

For JSON exports that have no dedicated importer. The script walks the given folder
recursively, reads each JSON file, and indexes one document per record with the JSON
key names (sanitized for Elasticsearch) as field names:

  * accepted layouts: a JSON array of records, one object, several concatenated objects,
    and JSON Lines / NDJSON (one record per line); .gz copies of any of them too;
  * a file that is one object wrapping its records ({"Records": [...]} as in CloudTrail,
    {"value": [...]}, ...) is unwrapped automatically, or with --records-key;
  * nested objects stay objects, so {"user": {"name": "x"}} is searchable as user.name;
  * every value is a keyword string, so files with different layouts can share one index
    without type conflicts (see Generic-JSON/README.md);
  * log.file.path (ECS) holds the absolute path of the source file, and event.sequence
    its record number;
  * host.name, the flat `case` keyword and event.dataset=genericjson are added like the
    other toolkit importers;
  * @timestamp comes from --timestamp-field, or from a date field found automatically,
    or from the ingest time when no field holds usable dates;
  * documents get a deterministic _id (host + file path + record number), so loading
    the same files again overwrites instead of duplicating;
  * traffic goes through the shared retrying _bulk client in
    ../Windows/common/sof_elk_es_client.py.

Standard library only. This importer is deliberately not called by
SOF-ELK_ImportWrapper.py: point it at a folder of JSON files yourself.
"""
from __future__ import annotations

import argparse
import codecs
import datetime as dt
import fnmatch
import gzip
import hashlib
import io
import json
import math
import os
import re
import sys
from pathlib import Path
from urllib import error

HERE = Path(__file__).resolve().parent
TEMPLATE_PATH = HERE / "index_templates" / "index-genericjson.json"
PREFIX = "genericjson"
TEMPLATE_NAME = f"sofelk-toolkit-{PREFIX}"

# The retrying bulk client is shared with the Windows, AWS, Generic-CSV and Linux importers.
sys.path.insert(0, str(HERE.parent / "Windows" / "common"))
from sof_elk_es_client import EsClient, add_client_arguments, apply_client_arguments, resolve_index  # noqa: E402

# Top-level names the importer writes itself. A JSON key whose sanitized name equals one
# of these (case-insensitively) gets a "_json" suffix instead of overwriting it.
RESERVED = {"host", "case", "log", "event", "genericjson"}
MAX_FIELD_BYTES = 255
DEFAULT_MAX_DEPTH = 10     # object levels kept as objects; deeper values become JSON text
SAMPLE_RECORDS = 500       # records inspected per file to pick the @timestamp field
DATE_HIT_RATIO = 0.9       # share of sampled non-empty values that must parse as dates
CHUNK_CHARS = 4 * 1024 * 1024
EXTENSIONS = (".json", ".jsonl", ".ndjson", ".json.gz", ".jsonl.gz", ".ndjson.gz")
# Keys that hold the records when a file is one object wrapping them (CloudTrail
# "Records", Azure "records", Microsoft Graph "value", common API "data"/"items"/...).
WRAPPER_KEYS = ("records", "value", "data", "items", "results", "events", "logs", "entries")

LEAF, OBJECT = "leaf", "object"

TIME_NAME_RE = re.compile(
    r"time|date|stamp|created|modified|accessed|written|executed|installed|deleted|"
    r"start|end|first|last|seen|when|^ts$|_ts$", re.I)
LOCAL_RE = re.compile(r"local", re.I)
ISO_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?\s*(Z|UTC|[+-]\d{2}:?\d{2})?$", re.I)
ISO_DATE_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})$")
SLASH_RE = re.compile(
    r"^(\d{1,2})/(\d{1,2})/(\d{4})(?:\s+(\d{1,2}):(\d{2})(?::(\d{2})(?:\.(\d+))?)?\s*([AaPp][Mm])?)?$")
# Epoch numbers accepted for 2001-09-09 .. 2100-01-01, in s, ms, us or ns.
EPOCH_UNITS = ((1e9, 4.1e9, 1), (1e12, 4.1e12, 1e3), (1e15, 4.1e15, 1e6), (1e18, 4.1e18, 1e9))


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
    """ISO 8601 or spreadsheet-style (10/25/2026 8:19 AM) time text -> ISO string, else None.

    A value without a time zone is read in default_tz. Same rules as Generic-CSV.
    """
    v = (value or "").strip() if isinstance(value, str) else ""
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


def parse_epoch(value):
    """A JSON number holding Unix time (s, ms, us or ns) -> ISO string in UTC, else None."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        return None
    for low, high, per_second in EPOCH_UNITS:
        if low <= value < high:
            seconds = value / per_second
            stamp = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(seconds=seconds)
            return stamp.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return None


def to_time(value, path, default_tz, date_order):
    """Time text, or an epoch number when the field's name looks like a time."""
    if isinstance(value, str):
        return parse_time(value, default_tz, date_order)
    if TIME_NAME_RE.search(path.rsplit(".", 1)[-1]):
        return parse_epoch(value)
    return None


def sanitize_key(raw, top, used):
    """One JSON key -> a field name unique among its siblings (see README: Field names)."""
    name = re.sub(r"[^A-Za-z0-9_]+", "_", str(raw).strip().lstrip("﻿")).strip("_")
    if not name:
        name = "field"
    if name[0].isdigit():
        name = "f_" + name
    if top and name.lower() in RESERVED:
        name += "_json"
    name = name.encode("utf-8")[:MAX_FIELD_BYTES].decode("utf-8", "ignore")
    base, i = name, 2
    while name.lower() in used:
        name = f"{base}_{i}"
        i += 1
    used.add(name.lower())
    return name


def scalar_text(value):
    """JSON scalar -> keyword text: strings as is, numbers and booleans as JSON writes them."""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False)


def flatten_list(values):
    out = []
    for v in values:
        if isinstance(v, list):
            out.extend(flatten_list(v))
        elif v is not None and v != "":
            out.append(v)
    return out


class Converter:
    """Turns JSON records into documents, with one consistent shape per field path.

    Elasticsearch cannot map one path as both an object and a value. The first shape seen
    for a path (or the shape already in the index) wins; a later value under an object path
    is stored as <name>_value, and a later object under a value path as <name>_obj. Records
    are always read in the same order, so the import pass makes the same choices as the
    scan pass, and the kinds dict is final after the scan.
    """

    def __init__(self, max_depth=DEFAULT_MAX_DEPTH, kinds=None):
        self.max_depth = max_depth
        self.kinds = dict(kinds or {})      # dotted path -> LEAF | OBJECT
        self.renamed = {}                   # dotted raw path -> dotted field path, when they differ
        self.conflicts = set()              # paths stored under _value / _obj

    def _claim(self, prefix, name, kind):
        while True:
            path = f"{prefix}.{name}" if prefix else name
            have = self.kinds.setdefault(path, kind)
            if have == kind:
                return name, path
            self.conflicts.add(path)
            name += "_value" if kind == LEAF else "_obj"

    def convert(self, record, leaves=None):
        """record (dict) -> document fields; leaves, when given, gets path -> (raw path, value)."""
        return self._object(record, "", "", 1, leaves)

    def _object(self, obj, prefix, raw_prefix, depth, leaves):
        out, used = {}, set()
        for key, value in obj.items():
            raw_path = f"{raw_prefix}.{key}" if raw_prefix else str(key)
            name = sanitize_key(key, not prefix, used)
            if isinstance(value, dict) and depth >= self.max_depth:
                value = json.dumps(value, ensure_ascii=False, sort_keys=True)
            if isinstance(value, dict):
                if not value:
                    continue
                name, path = self._claim(prefix, name, OBJECT)
                sub = self._object(value, path, raw_path, depth + 1, leaves)
                if sub:
                    out[name] = sub
            elif isinstance(value, list):
                items = flatten_list(value)
                if not items:
                    continue
                if all(isinstance(v, dict) for v in items) and depth < self.max_depth:
                    name, path = self._claim(prefix, name, OBJECT)
                    subs = [s for s in (self._object(v, path, raw_path, depth + 1, None) for v in items) if s]
                    if subs:
                        out[name] = subs
                else:
                    name, path = self._claim(prefix, name, LEAF)
                    out[name] = [scalar_text(v) if not isinstance(v, dict)
                                 else json.dumps(v, ensure_ascii=False, sort_keys=True) for v in items]
            elif value is None or value == "":
                continue
            else:
                name, path = self._claim(prefix, name, LEAF)
                out[name] = scalar_text(value)
                if leaves is not None:
                    leaves[path] = (raw_path, value)
            if path != raw_path:
                self.renamed.setdefault(raw_path, path)
        return out


def detect_encoding(head):
    if head.startswith(b"\xef\xbb\xbf"):
        return "utf-8-sig"
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "utf-16"
    try:
        # final=False: the sample may end inside a multi-byte character
        codecs.getincrementaldecoder("utf-8")().decode(head, final=len(head) < 65536)
        return "utf-8"
    except UnicodeDecodeError:
        return "cp1252"


class JsonFileError(Exception):
    pass


class JsonFile:
    """One JSON file: its layout, and a fresh record iterator on each records() call.

    layout is "array" (a JSON array of records), "lines" (JSON Lines / NDJSON) or
    "object" (one or more whole JSON values, such as one object or pretty-printed objects
    one after another). records() yields (record_number, record); bad lines in a JSON
    Lines file are skipped and listed in line_errors, any other syntax error stops the
    file with JsonFileError.
    """

    def __init__(self, path, records_keys=(), unwrap=True):
        self.path = path
        self.records_keys = [k for k in records_keys if k]
        self.unwrap = unwrap
        self.gz = path.name.lower().endswith(".gz")
        with self._binary() as fh:
            head = fh.read(65536)
        self.encoding = detect_encoding(head)
        self.layout = self._detect_layout()
        self.line_errors = []         # (line number, message) of skipped JSON Lines lines
        self.unwrapped_from = set()   # wrapper keys records were taken from

    def _binary(self):
        return gzip.open(self.path, "rb") if self.gz else open(self.path, "rb")

    def open(self):
        return io.TextIOWrapper(self._binary(), encoding=self.encoding, errors="replace", newline="")

    def _detect_layout(self):
        with self.open() as fh:
            head = fh.read(1024 * 1024)
        text = head.lstrip("﻿ \t\r\n")
        if not text:
            return "empty"
        if text[0] == "[":
            return "array"
        try:
            _, end = json.JSONDecoder().raw_decode(text)
        except ValueError:
            # The first value is cut off by the 1 MiB sample or is not valid JSON.
            # A JSON Lines file has a newline within its first record; whole-file mode
            # reports the error with its position either way.
            first_line = text.split("\n", 1)[0].strip()
            try:
                json.loads(first_line)
                return "lines"
            except ValueError:
                return "object"
        rest = text[end:]
        stripped = rest.lstrip(" \t\r")
        if "\n" not in text[:end] and stripped.startswith("\n") and stripped.strip():
            return "lines"
        return "object"

    # -- records
    def records(self):
        self.line_errors, self.unwrapped_from = [], set()
        n = 0
        for value in (self._lines() if self.layout == "lines" else self._stream()):
            for record in self._expand(value):
                n += 1
                yield n, record

    def _expand(self, value):
        """A top-level JSON value -> the records it holds."""
        if isinstance(value, list):
            for item in flatten_list(value):
                yield from self._expand_one(item)
        elif value is not None:
            yield from self._expand_one(value)

    def _expand_one(self, value):
        if not isinstance(value, dict):
            yield {"value": value}
            return
        for key in self.records_keys:
            inner = lookup(value, key)
            if inner is not None:
                self.unwrapped_from.add(key)
                for item in (flatten_list(inner) if isinstance(inner, list) else [inner]):
                    yield item if isinstance(item, dict) else {"value": item}
                return
        if self.unwrap and not self.records_keys and self.layout == "object":
            for key, inner in value.items():
                if (str(key).lower() in WRAPPER_KEYS and isinstance(inner, list) and inner
                        and all(isinstance(v, dict) for v in inner)):
                    self.unwrapped_from.add(str(key))
                    yield from inner
                    return
        yield value

    def _lines(self):
        decoder = json.JSONDecoder()
        with self.open() as fh:
            for line_no, line in enumerate(fh, 1):
                text = line.strip().lstrip("﻿")
                if not text:
                    continue
                try:
                    value, end = decoder.raw_decode(text)
                    if text[end:].strip():
                        raise ValueError("extra data after the JSON value")
                except ValueError as exc:
                    self.line_errors.append((line_no, str(exc)))
                    continue
                yield value

    def _stream(self):
        """Top-level JSON values; the elements of a top-level array are yielded one by one."""
        decoder = json.JSONDecoder()
        buf, pos, eof, offset, in_array = "", 0, False, 0, False
        with self.open() as fh:
            def more():
                nonlocal buf, pos, eof, offset
                if pos > CHUNK_CHARS:
                    offset += pos
                    buf, pos = buf[pos:], 0
                chunk = fh.read(max(CHUNK_CHARS, len(buf) - pos))
                if chunk:
                    buf += chunk
                else:
                    eof = True
                return bool(chunk)

            while True:
                while pos < len(buf) and (buf[pos] in " \t\r\n﻿" or (in_array and buf[pos] == ",")):
                    pos += 1
                if pos >= len(buf):
                    if more():
                        continue
                    if in_array:
                        raise JsonFileError("the file ends before the closing ']' of its array")
                    return
                ch = buf[pos]
                if ch == "[" and not in_array:
                    in_array, pos = True, pos + 1
                    continue
                if ch == "]" and in_array:
                    in_array, pos = False, pos + 1
                    continue
                try:
                    value, end = decoder.raw_decode(buf, pos)
                except ValueError as exc:
                    if not eof and more():
                        continue
                    raise JsonFileError(f"invalid JSON near character {offset + pos + 1}: {exc}") from None
                if end >= len(buf) and not eof and more():
                    continue    # a number or literal may continue in the next chunk
                pos = end
                yield value


def lookup(obj, dotted):
    """obj['a']['b'] for 'a.b', matching keys case-insensitively; None when absent."""
    cur = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        if part in cur:
            cur = cur[part]
            continue
        low = part.lower()
        match = next((k for k in cur if str(k).lower() == low), None)
        if match is None:
            return None
        cur = cur[match]
    return cur


def find_json_files(root, excludes):
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort(key=str.lower)
        for name in sorted(filenames, key=str.lower):
            if not name.lower().endswith(EXTENSIONS):
                continue
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            if any(fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(name, pat) for pat in excludes):
                continue
            out.append(path)
    return out


class TimestampSampler:
    """Collects the leaf values of a file's first records to pick its @timestamp field."""

    def __init__(self, default_tz, date_order):
        self.default_tz, self.date_order = default_tz, date_order
        self.raw = {}     # field path -> raw dotted path
        self.seen = {}
        self.hits = {}
        self.order = []

    def add(self, leaves):
        for path, (raw_path, value) in leaves.items():
            if path not in self.seen:
                self.raw[path], self.seen[path], self.hits[path] = raw_path, 0, 0
                self.order.append(path)
            self.seen[path] += 1
            if to_time(value, path, self.default_tz, self.date_order):
                self.hits[path] += 1

    def choose(self, wanted, detect):
        """Field path for @timestamp, or None.

        wanted is the --timestamp-field list (first match wins; the original key path or
        the field path, case-insensitively); else, when detect is true, the first field
        whose sampled values are nearly all dates, preferring time-like names.
        """
        for name in wanted:
            key = name.strip().lower()
            for path in self.order:
                if key in (path.lower(), self.raw[path].lower()):
                    return path
        if not detect:
            return None
        candidates = [p for p in self.order if not LOCAL_RE.search(p)]
        named = [p for p in candidates if TIME_NAME_RE.search(p.rsplit(".", 1)[-1])]
        others = [p for p in candidates if p not in named]
        for path in named + others:
            if self.seen[path] and self.hits[path] / self.seen[path] >= DATE_HIT_RATIO:
                return path
        return None


def leaf_value(doc, path):
    cur = doc
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def make_doc(fields, record_number, raw_value, *, jf, abs_path, rel_path, hostname, case,
             ts_path, default_tz, date_order, ingested, original=None):
    doc = dict(fields)
    ts = to_time(raw_value, ts_path, default_tz, date_order) if ts_path and raw_value is not None else None
    doc["@timestamp"] = ts or ingested
    doc["host"] = {"name": hostname}
    event = {"dataset": PREFIX, "kind": "event", "ingested": ingested, "sequence": record_number}
    if original is not None:
        event["original"] = original
    doc["event"] = event
    doc["log"] = {"file": {"path": abs_path}}
    doc[PREFIX] = {"file_name": jf.path.name, "relative_path": rel_path, "layout": jf.layout,
                   "timestamp_source": ts_path if ts else "ingest_time"}
    if case:
        doc["case"] = case
    return doc


def doc_id(hostname, abs_path, record_number):
    material = json.dumps([PREFIX, hostname, abs_path, record_number], ensure_ascii=False)
    return hashlib.sha1(material.encode("utf-8", "replace")).hexdigest()


def mapping_kinds(props, prefix=""):
    """Existing index mapping properties -> dotted path -> LEAF | OBJECT."""
    out = {}
    for name, spec in (props or {}).items():
        path = f"{prefix}.{name}" if prefix else name
        if "properties" in spec or spec.get("type") in ("object", "nested"):
            out[path] = OBJECT
            out.update(mapping_kinds(spec.get("properties"), path))
        else:
            out[path] = LEAF
    return out


def mapping_for(paths, kinds):
    """Dotted paths -> nested mapping properties (values keyword, objects object)."""
    root = {}
    for path in sorted(paths):
        parts = path.split(".")
        node = root
        for i in range(1, len(parts)):
            node = node.setdefault(parts[i - 1], {"properties": {}}).setdefault("properties", {})
        if kinds[path] == OBJECT:
            node.setdefault(parts[-1], {"properties": {}})
        else:
            node[parts[-1]] = {"type": "keyword", "ignore_above": 8191}
    return root


# --------------------------------------------------------------------------- Elasticsearch

class ES(EsClient):
    def call(self, method, path, body=None):
        return self.request(method, path, body)

    def install_template(self, template):
        status, resp = self.call("PUT", f"/_index_template/{TEMPLATE_NAME}", template)
        if status >= 300:
            sys.exit(f"Could not install index template {TEMPLATE_NAME} ({status}): {json.dumps(resp)[:500]}")

    def existing_mapping(self, index):
        """Mapping properties of an existing index (None when it does not exist yet)."""
        status, _ = self.call("HEAD", f"/{index}")
        if status == 404:
            return None
        if status >= 300:
            sys.exit(f"Could not check index {index} (HTTP {status})")
        status, resp = self.call("GET", f"/{index}/_mapping")
        if status >= 300:
            sys.exit(f"Could not read mapping of {index} ({status}): {json.dumps(resp)[:500]}")
        mapping = next(iter(resp.values()), {}).get("mappings", {})
        if mapping.get("_meta", {}).get("toolkit_schema") != PREFIX:
            sys.exit(f"Index '{index}' exists but was not created by this importer, so its field"
                     f" types may differ.\nDelete it and reload:  curl -X DELETE '{self.url}/{index}'\n"
                     f"or load into another index with --index <prefix>-<hostname>.")
        return mapping.get("properties", {})

    def prepare_index(self, index, template, existed, new_props):
        """Create the index (from the template) when needed and map the new fields."""
        if not existed:
            status, resp = self.call("PUT", f"/{index}", {"settings": {"index": {"refresh_interval": "-1"}}})
            if status >= 300:
                sys.exit(f"Could not create index {index} ({status}): {json.dumps(resp)[:500]}")
        props = dict(template["template"]["mappings"]["properties"])
        props.update(new_props)
        status, resp = self.call("PUT", f"/{index}/_mapping", {"properties": props})
        if status >= 300:
            sys.exit(f"Could not update the mapping of {index} ({status}): {json.dumps(resp)[:500]}")
        return "appending" if existed else "created"

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
        description="Import every JSON file under a directory into genericjson-<hostname>, with"
                    " field names taken from the JSON keys.")
    ap.add_argument("directory", help="Folder searched recursively for *.json, *.jsonl and *.ndjson"
                                      " (also .gz); a single file of any name also works")
    ap.add_argument("--hostname", required=True, help="Evidence host name; the index is genericjson-<hostname>")
    ap.add_argument("--case", help="Optional case/incident ID added to every document as `case`")
    ap.add_argument("--index", help="Override the target index; must end in -<hostname>")
    ap.add_argument("--records-key", action="append", default=[], metavar="KEY",
                    help="Key (dotted for nested, e.g. hits.hits) whose array holds the records"
                         " (repeatable; the first one present wins). Without it a file that is one"
                         " object wrapping its records in Records/value/data/items/... is unwrapped"
                         " automatically.")
    ap.add_argument("--no-unwrap", action="store_true",
                    help="Do not unwrap wrapper objects automatically; each top-level object is one record")
    ap.add_argument("--timestamp-field", action="append", default=[], metavar="NAME",
                    help="Key to use for @timestamp, dotted for nested keys (repeatable; the first"
                         " one present in a file wins). Without it a date field is detected per file.")
    ap.add_argument("--no-timestamp-detect", action="store_true",
                    help="Do not guess a date field; @timestamp is the ingest time unless"
                         " --timestamp-field matches")
    ap.add_argument("--assume-tz", default="Z",
                    help="Time zone for timestamps that carry none (default Z = UTC, e.g. +08:00)")
    ap.add_argument("--date-order", choices=("mdy", "dmy"), default="mdy",
                    help="Day/month order of spreadsheet-style dates such as 10/25/2026 8:19 AM")
    ap.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH,
                    help=f"Object levels kept as objects (default {DEFAULT_MAX_DEPTH}); anything"
                         " deeper is stored as JSON text")
    ap.add_argument("--keep-original", action="store_true",
                    help="Also store each record's original JSON text in event.original (not indexed)")
    ap.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                    help="Skip files whose name or relative path matches this glob (repeatable),"
                         " e.g. --exclude '*CloudTrail-Digest*'")
    ap.add_argument("--es", default="http://localhost:9200", help="Elasticsearch URL")
    ap.add_argument("--user", help="Elasticsearch username, if security is enabled")
    ap.add_argument("--password")
    ap.add_argument("--insecure", action="store_true", help="Skip TLS certificate checks")
    ap.add_argument("--batch-size", type=int, default=2000, help="Documents per bulk request")
    ap.add_argument("--dry-run", action="store_true", help="Read every file and show sample documents; send nothing")
    ap.add_argument("--sample-docs", type=int, default=2, help="Sample documents shown by --dry-run")
    add_client_arguments(ap)
    return ap


def scan_file(jf, conv, sampler):
    """Pass 1 over one file: field shapes and timestamp sample. Returns (records, error)."""
    n = 0
    try:
        for n, record in jf.records():
            leaves = {} if n <= SAMPLE_RECORDS else None
            conv.convert(record, leaves)
            if leaves is not None:
                sampler.add(leaves)
    except (OSError, EOFError, JsonFileError) as exc:
        return n, str(exc)
    return n, None


def main(argv=None):
    args = build_parser().parse_args(argv)
    apply_client_arguments(args)
    if args.batch_size < 1:
        sys.exit("--batch-size must be a positive integer")
    if args.max_depth < 1:
        sys.exit("--max-depth must be a positive integer")
    hostname = sanitize_hostname(args.hostname)
    index = resolve_index(PREFIX, hostname, args.index)
    default_tz = normalize_tz(args.assume_tz)
    try:
        template = json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        sys.exit(f"Cannot read index template {TEMPLATE_PATH}: {exc}")

    root = Path(args.directory).expanduser().resolve()
    if root.is_file():
        files, root = [root], root.parent
    elif root.is_dir():
        files = find_json_files(root, args.exclude)
    else:
        sys.exit(f"No such file or directory: {args.directory}")
    if not files:
        sys.exit(f"No JSON files (*.json, *.jsonl, *.ndjson, .gz) found under {root}")

    # Connect first: the shapes already mapped in an existing index take precedence.
    es, existing = None, None
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
        existing = es.existing_mapping(index)
    existing_kinds = mapping_kinds(existing)
    conv = Converter(args.max_depth, existing_kinds)

    # Pass 1: layout, field shapes and timestamp field of every file.
    plans = []
    for path in files:
        rel = path.relative_to(root).as_posix()
        try:
            jf = JsonFile(path, args.records_key, not args.no_unwrap)
        except (OSError, EOFError) as exc:
            print(f"  ! {rel}: cannot read ({exc}); skipped", file=sys.stderr)
            continue
        if jf.layout == "empty":
            print(f"  - {rel}: empty file; skipped")
            continue
        sampler = TimestampSampler(default_tz, args.date_order)
        n, err = scan_file(jf, conv, sampler)
        if err and not n:
            print(f"  ! {rel}: not readable as JSON ({err}); skipped", file=sys.stderr)
            continue
        if not n:
            print(f"  - {rel}: no records; skipped")
            continue
        ts_path = sampler.choose(args.timestamp_field, not args.no_timestamp_detect)
        plans.append((jf, rel, ts_path))
    if not plans:
        sys.exit("No JSON file with records was found.")

    new_paths = sorted(p for p in conv.kinds if p not in existing_kinds)
    n_leaf = sum(1 for p in conv.kinds if conv.kinds[p] == LEAF and p not in existing_kinds)
    print(f"\n{len(plans)} JSON file(s) under {root} -> index '{index}' (host '{hostname}')")
    print(f"{n_leaf} new value field(s) and {len(new_paths) - n_leaf} new object(s); every value"
          " is mapped as keyword")
    if conv.renamed:
        print("Key names changed to valid field names:")
        for raw, field in sorted(conv.renamed.items())[:40]:
            print(f"  {raw!s:<40} -> {field}")
        if len(conv.renamed) > 40:
            print(f"  ... and {len(conv.renamed) - 40} more (see --log-file)")
    if conv.conflicts:
        print("These keys hold objects in some records and plain values in others; the minority"
              " shape is stored as <key>_obj or <key>_value: " + ", ".join(sorted(conv.conflicts)[:20]))

    limit = int(template["template"]["settings"]["index"]["mapping"]["total_fields"]["limit"])
    if len(conv.kinds) + 20 > limit:
        sys.exit(f"Index '{index}' would need about {len(conv.kinds) + 20} fields, over its limit"
                 f" of {limit}. Lower --max-depth, split the folder (--exclude), or load into"
                 " another index with --index <prefix>-<hostname>.")

    if es is not None:
        state = es.prepare_index(index, template, existing is not None, mapping_for(new_paths, conv.kinds))
        print(f"Index '{index}': {state}, {len(new_paths)} new field(s) mapped")

    # Pass 2: stream the records.
    ingested = dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    total = {"records": 0, "ok": 0, "errors": 0, "updated": 0, "bad_lines": 0}
    samples, lines = [], []
    print()
    for jf, rel, ts_path in plans:
        abs_path = str(jf.path)
        records = no_ts = 0
        stop = None
        try:
            for n, record in jf.records():
                leaves = {}
                fields = conv.convert(record, leaves)
                raw_value = leaves.get(ts_path, (None, None))[1] if ts_path else None
                original = json.dumps(record, ensure_ascii=False) if args.keep_original else None
                doc = make_doc(fields, n, raw_value, jf=jf, abs_path=abs_path, rel_path=rel,
                               hostname=hostname, case=args.case, ts_path=ts_path,
                               default_tz=default_tz, date_order=args.date_order,
                               ingested=ingested, original=original)
                records += 1
                if doc[PREFIX]["timestamp_source"] == "ingest_time":
                    no_ts += 1
                if args.dry_run:
                    if len(samples) < args.sample_docs:
                        samples.append(doc)
                    continue
                lines.append(json.dumps({"index": {"_index": index, "_id": doc_id(hostname, abs_path, n)}}))
                lines.append(json.dumps(doc, ensure_ascii=False))
                if len(lines) >= args.batch_size * 2:
                    es.send(lines, total)
        except (OSError, EOFError, JsonFileError) as exc:
            stop = str(exc)
        total["records"] += records
        total["bad_lines"] += len(jf.line_errors)
        ts_note = f"@timestamp <- {ts_path}" if ts_path else "@timestamp <- ingest time"
        if ts_path and no_ts:
            ts_note += f" ({no_ts} record(s) without a usable value use the ingest time)"
        layout = jf.layout + (f", records from '{', '.join(sorted(jf.unwrapped_from))}'"
                              if jf.unwrapped_from else "")
        print(f"  {rel}: {records} record(s) ({layout}), {ts_note}")
        for line_no, msg in jf.line_errors[:3]:
            print(f"    ! line {line_no} skipped: {msg}", file=sys.stderr)
        if len(jf.line_errors) > 3:
            print(f"    ! ... {len(jf.line_errors) - 3} more invalid line(s) skipped", file=sys.stderr)
        if stop:
            print(f"    ! stopped after {records} record(s): {stop}", file=sys.stderr)
    if es is not None:
        es.send(lines, total)

    if total["bad_lines"]:
        print(f"\nnote: {total['bad_lines']} invalid JSON Lines line(s) were skipped.")

    if args.dry_run:
        print(f"\n{total['records']} record(s) read. Sample document(s):")
        for doc in samples:
            print("  " + json.dumps(doc, ensure_ascii=False)[:1500])
        print("\nDry run only - nothing sent.")
        return 0

    new = total["ok"] - total["updated"]
    print(f"\nDone: {total['records']} record(s) read -> {new} new document(s), {total['updated']}"
          f" already in the index (re-run), {total['errors']} error(s).")
    in_index = es.finish(index)
    if in_index is not None:
        print(f"Index '{index}' now holds {in_index} document(s).")
    print(f"In Kibana, use the '{PREFIX}-*' data view (time field @timestamp).")
    return 1 if total["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
