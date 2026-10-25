#!/usr/bin/env python3
"""Shared streaming CSV -> Elasticsearch bulk ingestion helpers."""
from __future__ import annotations

import csv
import datetime as dt
import hashlib
import json
import re
import sys
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "common"))
from sof_elk_es_client import (EsClient, add_client_arguments, apply_client_arguments,  # noqa: E402,F401
                               log, resolve_index)

try:
    csv.field_size_limit(sys.maxsize)
except OverflowError:
    csv.field_size_limit(2**31 - 1)

ISO_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.(\d+))?\s*(Z|[+-]\d{2}:?\d{2})?$")
INT_RE = re.compile(r"^-?(?:0|[1-9]\d{0,18})$")
BOOLS = {"true": True, "false": False}
INT64_MAX = 2**63 - 1
LOCAL_RE = re.compile(r"local", re.I)
TIME_NAME_RE = re.compile(r"time|date|stamp|last|first|created|modified|accessed|opened|executed|installed|updated|deleted|removed|start|end|connect", re.I)
OTHER_DATE_RE = re.compile(r"\b(?:\d{1,2}[-/.]\d{1,2}[-/.]\d{4}|\d{4}[-/.]\d{1,2}[-/.]\d{1,2})\b")
RESERVED = {"@timestamp", "host", "kape", "case"}
ES_FAMILY = {
    "text": "string", "keyword": "string", "match_only_text": "string", "wildcard": "string",
    "long": "long", "integer": "long", "short": "long", "byte": "long",
    "date": "date", "date_nanos": "date", "boolean": "boolean",
}


def sanitize_hostname(hostname: str) -> str:
    value = re.sub(r"[^a-z0-9._-]+", "-", hostname.strip().lower()).strip("._-")
    if not value:
        raise ValueError("--hostname must contain at least one letter or digit")
    return value


def select_csv_files(root: Path, hints, header_match=None) -> list[Path]:
    """CSV files to import: an explicit file as-is, else files whose name contains a hint
    or whose normalized header set satisfies header_match."""
    if root.is_file():
        return [root] if root.suffix.lower() == ".csv" else []
    out = []
    for p in sorted(root.rglob("*.csv"), key=lambda x: str(x).lower()):
        if not p.is_file():
            continue
        if any(h in p.name.lower() for h in hints):
            out.append(p)
            continue
        if header_match is not None:
            try:
                header, _ = read_header_and_rows(p)
            except RuntimeError:
                continue
            if header and header_match({normalize_header(h) for h in header}):
                out.append(p)
    return out


def es_try_call(base_url, method, path, body=None, user=None, password=None, insecure=False):
    """(status, payload) for one request; timeouts, connection errors and HTTP 429/5xx are
    retried, and EsUnavailable (a URLError) is raised if Elasticsearch stays unreachable."""
    return EsClient(base_url, user, password, insecure).request(method, path, body)


def sanitize_fields(header: list[str]) -> list[str]:
    used = set(RESERVED)
    out: list[str] = []
    for raw in header:
        field = re.sub(r"[^A-Za-z0-9_]+", "_", (raw or "").strip()).strip("_") or "field"
        if field[0].isdigit():
            field = "f_" + field
        base = field
        idx = 2
        while field in used:
            field = f"{base}_{idx}"
            idx += 1
        used.add(field)
        out.append(field)
    return out


def read_header_and_rows(path: Path):
    """Return (header, streaming row iterator). The iterator reopens the file so it remains valid."""
    encodings = ("utf-8-sig", "utf-16", "cp1252", "latin-1")
    last_exc = None
    chosen = None
    header = []
    delimiter = ","
    for encoding in encodings:
        try:
            with path.open("r", encoding=encoding, errors="strict", newline="") as fh:
                first = fh.readline()
                if not first:
                    return [], iter(())
                delimiter = max((",", "\t", ";", "|"), key=first.count)
                header = next(csv.reader([first], delimiter=delimiter), [])
                chosen = encoding
                break
        except (UnicodeError, OSError, csv.Error) as exc:
            last_exc = exc
    if chosen is None:
        raise RuntimeError(f"cannot read CSV '{path}': {last_exc}")

    def gen():
        with path.open("r", encoding=chosen, errors="replace", newline="") as fh:
            fh.readline()
            reader = csv.reader(fh, delimiter=delimiter)
            for row in reader:
                if any((cell or "").strip() for cell in row):
                    yield row
    return header, gen()


def normalize_header(v: str) -> str:
    return re.sub(r"\s+", " ", (v or "").strip().lstrip("\ufeff")).lower()


def parse_ts(value: str, default_tz: str = "Z") -> str | None:
    m = ISO_RE.match((value or "").strip())
    if not m:
        return None
    date_s, time_s, frac, tz = m.groups()
    frac = (frac or "")[:3].ljust(3, "0")
    tz = tz or default_tz
    if tz != "Z" and ":" not in tz and len(tz) == 5:
        tz = tz[:3] + ":" + tz[3:]
    return f"{date_s}T{time_s}.{frac}{tz}"


def field_tz(field: str, local_tz: str | None) -> str:
    return local_tz if local_tz and LOCAL_RE.search(field) else "Z"


def init_type_state(fields):
    return {f: {"seen": False, "boolean": True, "long": True, "date": True, "date_hits": 0, "bad": None} for f in fields}


def scan_rows(rows_iter, fields, state, ts_index=None, ts_tz="Z"):
    """Update type state; return (row count, rows with a parseable value at ts_index)."""
    count = usable = 0
    for row in rows_iter:
        count += 1
        if ts_index is not None and ts_index < len(row) and parse_ts(row[ts_index], ts_tz):
            usable += 1
        for i, field in enumerate(fields):
            raw = row[i] if i < len(row) else ""
            value = (raw or "").strip()
            if not value:
                continue
            s = state[field]
            s["seen"] = True
            low = value.lower()
            if s["boolean"] and low not in BOOLS:
                s["boolean"] = False
            if s["long"]:
                try:
                    n = int(value)
                    if abs(n) > INT64_MAX:
                        s["long"] = False
                except ValueError:
                    s["long"] = False
            if ISO_RE.match(value):
                s["date_hits"] += 1
            else:
                s["date"] = False
                if s["bad"] is None and OTHER_DATE_RE.search(value):
                    s["bad"] = value[:80]
    return count, usable


def finalize_types(state, local_tz: str | None):
    out = {}
    for field, s in state.items():
        if not s["seen"]:
            out[field] = None
        elif s["boolean"]:
            out[field] = "boolean"
        elif s["long"]:
            out[field] = "long"
        elif s["date"] and not (LOCAL_RE.search(field) and not local_tz):
            out[field] = "date"
        else:
            out[field] = "string"
    return out


def merge_types(states: list[dict[str, str | None]]):
    by_field: dict[str, set[str]] = {}
    for state in states:
        for field, t in state.items():
            if t:
                by_field.setdefault(field, set()).add(t)
    types = {}
    conflicts = {}
    for field, vals in by_field.items():
        if len(vals) == 1:
            types[field] = next(iter(vals))
        else:
            types[field] = "string"
            conflicts[field] = sorted(vals)
    return types, conflicts


def choose_timestamp_field(fields: list[str], preferred: list[str]) -> str | None:
    by_norm = {re.sub(r"[^a-z0-9]", "", f.lower()): f for f in fields}
    for pref in preferred:
        key = re.sub(r"[^a-z0-9]", "", pref.lower())
        if key in by_norm:
            return by_norm[key]
    candidates = [f for f in fields if TIME_NAME_RE.search(f) and "local" not in f.lower()]
    return candidates[0] if candidates else None


def build_mapping(types: dict[str, str | None], existing: dict[str, str], reserved_dynamic=True):
    props = {}
    renames = {}
    for field, t in types.items():
        if not t:
            continue
        existing_type = existing.get(field)
        if existing_type:
            fam = ES_FAMILY.get(existing_type, "other")
            if fam == t or (fam == "string" and t == "string"):
                continue
            if fam == "string":
                continue
            renames[field] = f"{field}_text"
            continue
        if t == "date":
            props[field] = {"type": "date", "format": "strict_date_optional_time||yyyy-MM-dd HH:mm:ss.SSS||yyyy-MM-dd HH:mm:ss.SSSSSSS"}
        elif t == "long":
            props[field] = {"type": "long"}
        elif t == "boolean":
            props[field] = {"type": "boolean"}
        else:
            props[field] = {"type": "keyword", "ignore_above": 32766}
    return props, renames


def get_flat_mappings(es, index, user, password, insecure):
    status, body = es_try_call(es, "GET", f"/{index}/_mapping", user=user, password=password, insecure=insecure)
    if status == 200:
        root = body.get(index, body)
        return {k: v.get("type", "object") for k, v in root.get("mappings", {}).get("properties", {}).items()}
    if status == 404:
        return {}
    raise RuntimeError(f"Elasticsearch mapping query failed: HTTP {status}: {json.dumps(body, ensure_ascii=False)[:500]}")


def ensure_index(es, index, types, user, password, insecure):
    status, body = es_try_call(es, "HEAD", f"/{index}", user=user, password=password, insecure=insecure)
    if status == 200:
        return False
    if status != 404:
        raise RuntimeError(f"Elasticsearch HEAD index failed: HTTP {status}")
    props = {}
    for field, t in types.items():
        if not t:
            continue
        if t == "date":
            props[field] = {"type": "date", "format": "strict_date_optional_time||yyyy-MM-dd HH:mm:ss.SSS||yyyy-MM-dd HH:mm:ss.SSSSSSS"}
        elif t == "long":
            props[field] = {"type": "long"}
        elif t == "boolean":
            props[field] = {"type": "boolean"}
        else:
            props[field] = {"type": "keyword", "ignore_above": 32766}
    body = {"settings": {"refresh_interval": "-1"}, "mappings": {"properties": {
        **props,
        "@timestamp": {"type": "date"},
        "host": {"properties": {"name": {"type": "keyword"}}},
        "kape": {"properties": {
            "source_file": {"type": "keyword", "ignore_above": 32766},
            "timestamp_source": {"type": "keyword", "ignore_above": 1024},
        }},
        "case": {"type": "keyword", "ignore_above": 1024},
    }}}
    status, body = es_try_call(es, "PUT", f"/{index}", body=body, user=user, password=password, insecure=insecure)
    if status not in (200, 201):
        raise RuntimeError(f"failed to create index '{index}': HTTP {status}: {json.dumps(body, ensure_ascii=False)[:1000]}")
    return True


def apply_new_mappings(es, index, props, user, password, insecure):
    if not props:
        return
    status, body = es_try_call(es, "PUT", f"/{index}/_mapping", body={"properties": props}, user=user, password=password, insecure=insecure)
    if status not in (200, 201):
        raise RuntimeError(f"failed to update mapping for '{index}': HTTP {status}: {json.dumps(body, ensure_ascii=False)[:1000]}")


def convert_value(raw: str, t: str | None, field: str, local_tz: str | None):
    value = (raw or "").strip()
    if not value:
        return None
    if t == "date":
        return parse_ts(value, field_tz(field, local_tz)) or value
    if t == "long":
        try:
            return int(value)
        except ValueError:
            return value
    if t == "boolean":
        low = value.lower()
        return BOOLS.get(low, value)
    return raw


def deterministic_id(host, tool, source_file, row_number, row):
    material = json.dumps([host.lower(), tool, source_file, row_number, row], ensure_ascii=False, separators=(",", ":"), default=str)
    return hashlib.sha1(material.encode("utf-8", "replace")).hexdigest()


def bulk_send(es, index, actions, user, password, insecure, workers=2, batch_size=2000):
    """Send (meta, doc) actions in batches; at most workers*2 batches are held at once.
    Failed requests and rejected (429/5xx) items are retried with backoff by EsClient.bulk."""
    client = EsClient(es, user, password, insecure)

    def send(one_batch):
        lines = []
        for meta, doc in one_batch:
            lines.append(json.dumps(meta, ensure_ascii=False))
            lines.append(json.dumps(doc, ensure_ascii=False))
        status, body = client.bulk(lines)
        if status >= 300:
            raise RuntimeError(f"bulk request failed: HTTP {status}: {json.dumps(body, ensure_ascii=False)[:500]}")
        errors = []
        if body.get("errors"):
            for item in body.get("items", []):
                op = next(iter(item.values()))
                if op.get("error"):
                    errors.append(op.get("error"))
        return len(one_batch) - len(errors), len(errors), errors

    workers = max(1, workers)
    success = errors = n_batches = 0
    error_samples = []
    pending = deque()

    def collect_one():
        nonlocal success, errors
        ok, bad, errs = pending.popleft().result()
        success += ok; errors += bad
        if len(error_samples) < 10:
            error_samples.extend(errs[:10-len(error_samples)])

    with ThreadPoolExecutor(max_workers=workers) as pool:
        batch = []
        for action in actions:
            batch.append(action)
            if len(batch) >= batch_size:
                pending.append(pool.submit(send, batch))
                n_batches += 1
                batch = []
                if len(pending) >= workers * 2:
                    collect_one()
        if batch:
            pending.append(pool.submit(send, batch))
            n_batches += 1
        while pending:
            collect_one()
    return success, errors, n_batches, error_samples


def process_csv_import(paths, *, hostname, tool_key, index, es="http://localhost:9200", user=None,
                       password=None, insecure=False, batch_size=2000, workers=2, case=None,
                       local_tz=None, time_preferences=None, transform=None, dry_run=False,
                       sample_docs=2):
    hostname = sanitize_hostname(hostname)
    log.info("start: tool=%s index=%s files=%d case=%s dry_run=%s", tool_key, index, len(paths), case, dry_run)
    plans = []
    for path in paths:
        header, rows = read_header_and_rows(path)
        if not header:
            continue
        fields = sanitize_fields(header)
        state = init_type_state(fields)
        ts_field = choose_timestamp_field(fields, time_preferences or [])
        ts_index = fields.index(ts_field) if ts_field else None
        count, usable = scan_rows(rows, fields, state, ts_index, field_tz(ts_field or "", local_tz))
        types = finalize_types(state, local_tz)
        plans.append((path, header, fields, types, ts_field, count, usable))

    merged_types, conflicts = merge_types([p[3] for p in plans])
    print(f"{len(paths)} CSV files, {sum(p[5] for p in plans)} rows -> index '{index}'", flush=True)
    if conflicts:
        print("\nFields with inconsistent inferred types (stored as text):", flush=True)
        for f, vals in sorted(conflicts.items()):
            print(f"  {f}: {', '.join(vals)}", flush=True)
    print("\nTimestamp check", flush=True)
    for p in plans:
        path, _header, fields, _types, ts_field, count, usable = p
        if ts_field:
            print(f"  {path.stem[:55]:<55} @timestamp <- {ts_field} {usable}/{count}", flush=True)
        else:
            print(f"  {path.stem[:55]:<55} WARN @timestamp <- ingest time", flush=True)
    if dry_run:
        print("\nDry run only - nothing sent.", flush=True)
        shown = 0
        now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        for path, header, fields, _types, ts_field, _count, _usable in plans:
            if shown >= sample_docs:
                break
            _, rows = read_header_and_rows(path)
            for rn, row in enumerate(rows, 1):
                doc = make_doc(hostname, tool_key, path.name, row, fields, merged_types, ts_field, now, local_tz, case, transform)
                print("  " + json.dumps(doc, ensure_ascii=False)[:1000], flush=True)
                shown += 1
                if shown >= sample_docs:
                    break
        print(f"Dry run complete: {sum(p[5] for p in plans)} rows parsed; nothing sent to Elasticsearch.", flush=True)
        return 0

    version_status, version_body = es_try_call(es, "GET", "/", user=user, password=password, insecure=insecure)
    if version_status != 200:
        raise RuntimeError(f"Cannot reach Elasticsearch at {es}: HTTP {version_status}: {json.dumps(version_body, ensure_ascii=False)[:500]}")
    print(f"Connected to Elasticsearch {version_body.get('version', {}).get('number', '?')}", flush=True)
    created = ensure_index(es, index, merged_types, user, password, insecure)
    print(f"{'Created' if created else 'Using existing'} index '{index}'", flush=True)
    if not created:
        existing = get_flat_mappings(es, index, user, password, insecure)
        _, renames = build_mapping(merged_types, existing)
        props = {}
        for field, t in merged_types.items():
            if field in existing:
                continue
            if t == "date": props[field] = {"type": "date"}
            elif t == "long": props[field] = {"type": "long"}
            elif t == "boolean": props[field] = {"type": "boolean"}
            else: props[field] = {"type": "keyword", "ignore_above": 32766}
        apply_new_mappings(es, index, props, user, password, insecure)
    else:
        renames = {}

    now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    def actions():
        for path, _header, fields, _types, ts_field, _count, _usable in plans:
            _, rows = read_header_and_rows(path)
            for rn, row in enumerate(rows, 1):
                doc = make_doc(hostname, tool_key, path.name, row, fields, merged_types, ts_field, now, local_tz, case, transform, renames)
                yield ({"index": {"_index": index, "_id": deterministic_id(hostname, tool_key, path.name, rn, row)}}, doc)
    ok, bad, n_batches, errs = bulk_send(es, index, actions(), user, password, insecure, workers, batch_size)
    status, _ = es_try_call(es, "PUT", f"/{index}/_settings", body={"index": {"refresh_interval": "1s"}}, user=user, password=password, insecure=insecure)
    if status >= 300:
        print(f"WARNING: could not restore refresh interval for '{index}' (HTTP {status})", flush=True)
    print(f"Done: {ok + bad} documents read, {ok} successful bulk items, {bad} errors, {n_batches} bulk request(s).", flush=True)
    log.info("done: index=%s ok=%d errors=%d batches=%d", index, ok, bad, n_batches)
    for e in errs[:6]:
        print(f"  Elasticsearch item error: {json.dumps(e, ensure_ascii=False)[:700]}", flush=True)
    return 0 if bad == 0 else 2


def make_doc(hostname, tool_key, source_file, row, fields, types, ts_field, ingest_time, local_tz, case, transform=None, renames=None):
    renames = renames or {}
    doc = {}
    for i, field in enumerate(fields):
        raw = row[i] if i < len(row) else ""
        if not (raw or "").strip():
            continue
        out_field = renames.get(field, field)
        doc[out_field] = convert_value(raw, types.get(field), field, local_tz)
    ts = None
    if ts_field and ts_field in fields:
        i = fields.index(ts_field)
        if i < len(row):
            ts = parse_ts(row[i], field_tz(ts_field, local_tz))
    doc["@timestamp"] = ts or ingest_time
    doc["host"] = {"name": hostname.lower()}
    doc["kape"] = {"source_file": source_file, "timestamp_source": ts_field if ts else "ingest_time"}
    if case:
        doc["case"] = case
    if transform:
        transform(doc)
    return doc
