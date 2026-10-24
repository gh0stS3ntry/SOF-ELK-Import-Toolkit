#!/usr/bin/env python3
"""Bulk-load ConvertUsageLogsTo-CSV.ps1 output into Elasticsearch.

Input CSV fields expected:
  User, AssemblyName, FirstExecutionTimestamp, LastExecutionTimestamp, File

Actual Elasticsearch index name is lowercase because Elasticsearch index names
must be lowercase: clrusagelogs-<hostname>.
"""
from __future__ import annotations

import argparse
import base64
import csv
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import ssl
import sys
from pathlib import Path
from urllib import error, request

INDEX_PREFIX = "clrusagelogs"
REQUIRED = {"user", "assemblyname", "firstexecutiontimestamp", "lastexecutiontimestamp", "file"}
TRUE = {"true", "yes", "y", "1"}
FALSE = {"false", "no", "n", "0"}


def auth_header(user: str | None, password: str | None) -> dict[str, str]:
    if not user:
        return {}
    token = base64.b64encode(f"{user}:{password or ''}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def http_json(base: str, method: str, path: str, body=None, headers=None, insecure=False, timeout=120):
    payload = None if body is None else json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    merged = {"Content-Type": "application/json", **(headers or {})}
    req = request.Request(base.rstrip("/") + path, data=payload, method=method, headers=merged)
    context = ssl._create_unverified_context() if insecure else None
    try:
        with request.urlopen(req, timeout=timeout, context=context) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else {}
    except error.HTTPError as exc:
        raw = exc.read()
        try:
            obj = json.loads(raw) if raw else {}
        except Exception:
            obj = {"raw": raw.decode("utf-8", "replace")}
        return exc.code, obj
    except error.URLError as exc:
        raise RuntimeError(str(exc.reason)) from exc


def parse_timestamp(value: str) -> str | None:
    if not value:
        return None
    s = value.strip()
    if not s:
        return None
    try:
        parsed = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
            try:
                parsed = dt.datetime.strptime(s, fmt).replace(tzinfo=dt.timezone.utc)
                break
            except ValueError:
                parsed = None
        if parsed is None:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def clean_text(value: str | None) -> str:
    return (value or "").strip()


def set_nested(doc: dict, path: str, value):
    parts = path.split(".")
    cur = doc
    for part in parts[:-1]:
        cur = cur.setdefault(part, {})
    cur[parts[-1]] = value


def sanitize_hostname(hostname: str) -> str:
    """Lower-case host name safe for an Elasticsearch index name."""
    value = re.sub(r"[^a-z0-9._-]+", "-", hostname.strip().lower()).strip("._-")
    if not value:
        raise ValueError("--hostname must contain at least one letter or digit")
    return value


def index_name(hostname: str) -> str:
    return f"{INDEX_PREFIX}-{sanitize_hostname(hostname)}"


def detect_csv(path: Path):
    last = None
    for encoding in ("utf-8-sig", "utf-16", "cp1252"):
        try:
            handle = path.open("r", encoding=encoding, errors="strict", newline="")
            sample = handle.read(8192)
            handle.seek(0)
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
            except csv.Error:
                dialect = csv.excel
            reader = csv.DictReader(handle, dialect=dialect)
            fields = [(f or "").strip().lstrip("\ufeff") for f in (reader.fieldnames or [])]
            normalized = {re.sub(r"\s+", "", f).lower() for f in fields}
            if not REQUIRED.issubset(normalized):
                handle.close()
                raise RuntimeError(f"CSV header does not match ConvertUsageLogsTo-CSV.ps1: {fields}")
            return handle, reader, fields
        except Exception as exc:
            last = exc
            try:
                handle.close()
            except Exception:
                pass
    raise RuntimeError(f"Could not read CSV {path}: {last}")


def first_value(row: dict[str, str], target: str) -> str:
    for key, value in row.items():
        normalized = re.sub(r"\s+", "", (key or "").strip().lstrip("\ufeff")).lower()
        if normalized == target:
            return clean_text(value)
    return ""


def runtime_from_path(file_path: str) -> str | None:
    m = re.search(r"\\CLR_v(\d+\.\d+(?:_32)?)\\UsageLogs\\", file_path, re.IGNORECASE)
    return m.group(1) if m else None


def stable_id(index: str, source_file: str, rownum: int, row: dict) -> str:
    # Built from the raw CSV row, not the document, so the ingest-time fallback for
    # rows without a timestamp does not change the ID between runs.
    values = [[str(k), v] for k, v in row.items()]
    basis = json.dumps({"index": index, "file": source_file, "row": rownum, "values": values},
                       sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha1(basis.encode("utf-8")).hexdigest()


def create_index(es: str, index: str, user=None, password=None, insecure=False):
    headers = auth_header(user, password)
    status, _ = http_json(es, "HEAD", f"/{index}", headers=headers, insecure=insecure)
    if status == 200:
        return False
    if status != 404:
        raise RuntimeError(f"Cannot inspect index {index}: HTTP {status}")
    body = {
        "settings": {"index": {"refresh_interval": "-1"}},
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "user": {"properties": {"name": {"type": "keyword"}}},
                "file": {
                    "properties": {
                        "name": {"type": "keyword"},
                        "path": {"type": "keyword", "ignore_above": 1024},
                    }
                },
                "clr_usage": {
                    "properties": {
                        "first_execution_timestamp": {"type": "date"},
                        "last_execution_timestamp": {"type": "date"},
                        "runtime": {"type": "keyword"},
                        "assembly_name": {"type": "keyword"},
                        "source_user": {"type": "keyword"},
                    }
                },
                "kape": {
                    "properties": {
                        "source_file": {"type": "keyword"},
                        "timestamp_source": {"type": "keyword"},
                    }
                },
                "host": {"properties": {"name": {"type": "keyword"}}},
            },
            "dynamic_templates": [
                {"strings_as_text": {"match_mapping_type": "string", "mapping": {"type": "text", "fields": {"keyword": {"type": "keyword", "ignore_above": 256}}}}}
            ],
        },
    }
    status, result = http_json(es, "PUT", f"/{index}", body=body, headers=headers, insecure=insecure)
    if status >= 300:
        raise RuntimeError(f"Failed to create index {index}: HTTP {status}: {json.dumps(result)[:800]}")
    return True


def bulk_index(es: str, index: str, batch: list[dict], user=None, password=None, insecure=False):
    if not batch:
        return 0, []
    lines = []
    for item in batch:
        lines.append(json.dumps({"index": {"_index": index, "_id": item["_id"]}}, separators=(",", ":")))
        lines.append(json.dumps(item["_source"], ensure_ascii=False, separators=(",", ":")))
    payload = ("\n".join(lines) + "\n").encode("utf-8")
    req = request.Request(
        es.rstrip("/") + "/_bulk",
        data=payload,
        method="POST",
        headers={"Content-Type": "application/x-ndjson", **auth_header(user, password)},
    )
    context = ssl._create_unverified_context() if insecure else None
    try:
        with request.urlopen(req, timeout=180, context=context) as response:
            result = json.loads(response.read())
    except error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace")
        raise RuntimeError(f"Bulk request failed HTTP {exc.code}: {raw[:1000]}") from exc
    successes = 0
    errors = []
    for item in result.get("items", []):
        op = item.get("index", {})
        if op.get("status", 500) >= 300:
            errors.append(op)
        else:
            successes += 1
    return successes, errors


def build_document(row: dict[str, str], hostname: str, source_file: str, rownum: int):
    user = first_value(row, "user")
    assembly = first_value(row, "assemblyname")
    first_ts_raw = first_value(row, "firstexecutiontimestamp")
    last_ts_raw = first_value(row, "lastexecutiontimestamp")
    source_file_path = first_value(row, "file")
    first_ts = parse_timestamp(first_ts_raw)
    last_ts = parse_timestamp(last_ts_raw)
    event_ts = last_ts or first_ts

    doc = {
        "host": {"name": sanitize_hostname(hostname)},
        "kape": {
            "source_file": source_file,
            "timestamp_source": "LastExecutionTimestamp" if last_ts else "FirstExecutionTimestamp" if first_ts else "ingest_time",
        },
        "clr_usage": {
            "source_user": user or None,
            "assembly_name": assembly or None,
            "runtime": runtime_from_path(source_file_path),
            "first_execution_timestamp": first_ts,
            "last_execution_timestamp": last_ts,
        },
    }
    if user:
        doc.setdefault("user", {})["name"] = user
    if assembly:
        set_nested(doc, "file.name", assembly)
        doc["process"] = {"name": assembly}
    if source_file_path:
        set_nested(doc, "file.path", source_file_path)
    if event_ts:
        doc["@timestamp"] = event_ts
    else:
        doc["@timestamp"] = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
        doc["kape"]["timestamp_source"] = "ingest_time"
    if user or assembly or source_file_path:
        doc["message"] = "CLR usage log: " + ":".join(x for x in (user, assembly, source_file_path) if x)
    return doc


def parse_args():
    p = argparse.ArgumentParser(description="Bulk-load ConvertUsageLogsTo-CSV.ps1 CSV output into Elasticsearch.")
    p.add_argument("input", help="CSV file or directory containing ConvertUsageLogsTo-CSV output")
    p.add_argument("--hostname", required=True, help="Evidence hostname")
    p.add_argument("--es", default="http://localhost:9200", help="Elasticsearch base URL")
    p.add_argument("--user", help="Elasticsearch username")
    p.add_argument("--password", help="Elasticsearch password")
    p.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")
    p.add_argument("--batch-size", type=int, default=2000, help="Documents per bulk request")
    p.add_argument("--case", help="Optional case/incident ID")
    p.add_argument("--dry-run", action="store_true", help="Parse and preview without sending to Elasticsearch")
    p.add_argument("--sample-docs", type=int, default=3, help="Number of sample documents to print")
    return p.parse_args()


def main():
    args = parse_args()
    try:
        return run(args)
    except (RuntimeError, ValueError, error.URLError, OSError) as exc:
        print(f"ERROR: {getattr(exc, 'reason', exc)}")
        return 1


def run(args):
    if args.batch_size < 1:
        raise SystemExit("--batch-size must be >= 1")
    root = Path(args.input)
    if root.is_file():
        files = [root]
    elif root.is_dir():
        files = sorted(root.rglob("*.csv"), key=lambda p: str(p).lower())
    else:
        raise SystemExit(f"Input path does not exist: {root}")
    if not files:
        raise SystemExit(f"No CSV files found under {root}")

    idx = index_name(args.hostname)
    print("Tool label: ConvertUsageLogsTo-CSV")
    print(f"Target index: {idx}")
    print(f"Files: {len(files)}")
    print(f"Elasticsearch: {args.es}")
    if args.dry_run:
        print("Mode: dry run")
    else:
        status, info = http_json(args.es, "GET", "/", headers=auth_header(args.user, args.password), insecure=args.insecure)
        if status >= 300:
            raise RuntimeError(f"Elasticsearch at {args.es} returned HTTP {status}: {json.dumps(info)[:300]}")
        print(f"Connected to Elasticsearch {info.get('version', {}).get('number', '?')}")
        created = create_index(args.es, idx, args.user, args.password, args.insecure)
        print(f"{'Created' if created else 'Using existing'} index: {idx} (refresh disabled during initial bulk load)")

    total = 0
    success = 0
    error_count = 0
    samples = 0
    now = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")

    for path in files:
        handle, reader, _fields = detect_csv(path)
        batch = []
        count = 0
        try:
            for rownum, row in enumerate(reader, start=2):
                if not any(clean_text(v) for v in row.values() if v is not None):
                    continue
                doc = build_document(row, args.hostname, path.name, rownum)
                if args.case:
                    doc["case"] = {"id": args.case}
                if not doc.get("@timestamp"):
                    doc["@timestamp"] = now
                if args.dry_run:
                    if samples < args.sample_docs:
                        print("  SAMPLE", json.dumps(doc, ensure_ascii=False)[:1400])
                        samples += 1
                else:
                    batch.append({"_id": stable_id(idx, path.name, rownum, row), "_source": doc})
                    if len(batch) >= args.batch_size:
                        s, e = bulk_index(args.es, idx, batch, args.user, args.password, args.insecure)
                        success += s
                        error_count += len(e)
                        for err in e[:5]:
                            print(f"  Elasticsearch item error: {err}")
                        batch.clear()
                count += 1
                total += 1
            if batch:
                s, e = bulk_index(args.es, idx, batch, args.user, args.password, args.insecure)
                success += s
                error_count += len(e)
                for err in e[:5]:
                    print(f"  Elasticsearch item error: {err}")
        finally:
            handle.close()
        print(f"  {path.name}: {count} record(s) queued")

    if args.dry_run:
        print(f"Dry run complete: {total} record(s) parsed; nothing sent to Elasticsearch.")
        return 0

    http_json(args.es, "PUT", f"/{idx}/_settings", body={"index": {"refresh_interval": "1s"}}, headers=auth_header(args.user, args.password), insecure=args.insecure)
    print(f"Done: {total} record(s), {success} successful bulk items, {error_count} item errors.")
    print(f"In Kibana, use the clrusagelogs-* Data View with @timestamp as its time field.")
    return 2 if error_count else 0


if __name__ == "__main__":
    raise SystemExit(main())
