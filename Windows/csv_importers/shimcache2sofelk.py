#!/usr/bin/env python3
"""Load AppCompatCache / ShimCache CSVs into shimcache-<hostname>.

Preserves the original pe2sofelk.py ShimCache field mappings and timestamp meaning while
omitting `forensic_tag`. ShimCache last-modified times are not asserted to be execution times.
"""
import argparse
import base64
import csv
import datetime as dt
import hashlib
import json
import re
import ssl
import sys
from pathlib import Path
from urllib import error, request

try:
    csv.field_size_limit(sys.maxsize)
except OverflowError:  # Windows: C long is 32-bit
    csv.field_size_limit(2**31 - 1)

# EZ Tools write UTC timestamps like "2026-10-08 09:12:44.1234567" (7 fractional digits)
ISO_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.(\d+))?\s*(Z|[+-]\d{2}:?\d{2})?$"
)
# Numbers only; leading zeros (IDs like 0000, 0001) stay text so nothing is lost
INT_RE = re.compile(r"^-?(?:0|[1-9]\d{0,18})$")
BOOLS = {"true": True, "false": False}
INT64_MAX = 2**63 - 1

# Preferred @timestamp columns per tool (first one with a value in the row wins)
def time_prefs(tag):
    if tag == "AppCompatCache":
        return ["LastModifiedTimeUTC"]
    if tag.endswith("FileEntries"):
        return ["FileKeyLastWriteTimestamp", "KeyLastWriteTimestamp"]
    if tag == "Amcache_ProgramEntries":
        return ["InstallDate", "KeyLastWriteTimestamp"]
    if tag.startswith("Amcache_"):
        return ["KeyLastWriteTimestamp", "FileKeyLastWriteTimestamp"]
    return []


# What each @timestamp source means (stored in kape.timestamp_meaning)
TIME_MEANING = {
    "lastmodifiedtimeutc": "File last-modified time ($SI) recorded in ShimCache - NOT an execution time",
    "filekeylastwritetimestamp": "Amcache file key last write - often close to first execution, not proof of it",
    "keylastwritetimestamp": "Amcache registry key last write time",
    "installdate": "Program install date recorded in Amcache",
    "ingest_time": "No usable time in this row - time the row was loaded",
}

# Fallback for unrecognised CSVs: column names (lower-case, no underscores) in order
TIME_PRIORITY = [
    "lastinteracted", "lastaccessed", "sourcemodified",
    "lastwritetimestamp", "lastwritetime", "lastwrite", "lastexecuted", "lastexecution",
    "lastrun", "lastruntime", "executedon", "timestamp", "lastmodified", "modified",
    "lastopened", "opened", "lastconnected", "lastupdated", "created", "createdon",
    "firstconnected",
]

# Column names that suggest a time value (used only by the timestamp check)
TIME_NAME_RE = re.compile(
    r"time|date|stamp|last|first|created|modified|connected|opened|executed|installed|accessed|updated",
    re.I)
# A date written in some other format, e.g. 10/08/2026 or 08.10.2026
OTHER_DATE_RE = re.compile(r"\b(?:\d{1,2}[-/.]\d{1,2}[-/.]\d{4}|\d{4}[-/.]\d{1,2}[-/.]\d{1,2})\b")
# Columns holding the host's local time rather than UTC, e.g. "Last Connected LOCAL"
LOCAL_RE = re.compile(r"local", re.I)
TZ_ARG_RE = re.compile(r"^([+-])(\d{1,2}):?(\d{2})?$")

# Fields the script adds itself; CSV columns with these names get a suffix
RESERVED = {"@timestamp", "forensic_tag", "host", "file", "kape", "case"}

# Columns that hold the executable's path, in order of preference
PATH_COLUMNS = ["path", "fullpath", "lowercaselongpath"]

# Elasticsearch mapping type -> our type family
ES_FAMILY = {
    "text": "string", "keyword": "string", "match_only_text": "string", "wildcard": "string",
    "long": "long", "integer": "long", "short": "long", "byte": "long",
    "date": "date", "date_nanos": "date", "boolean": "boolean",
}


# --------------------------------------------------------------------------- helpers

def parse_ts(value, default_tz="Z"):
    """EZ Tools timestamp -> ISO 8601 with millisecond precision, or None.
    default_tz is applied when the value has no offset (UTC unless it's a LOCAL column)."""
    m = ISO_RE.match(value.strip())
    if not m:
        return None
    date, time, frac, tz = m.groups()
    frac = (frac or "")[:3].ljust(3, "0")
    if not tz:
        tz = default_tz  # EZ Tools output is UTC unless the column says LOCAL
    elif tz != "Z" and ":" not in tz:
        tz = tz[:3] + ":" + tz[3:]
    return f"{date}T{time}.{frac}{tz}"


def sanitize_hostname(hostname):
    """Lower-case host name safe for an Elasticsearch index name."""
    value = re.sub(r"[^a-z0-9._-]+", "-", hostname.strip().lower()).strip("._-")
    if not value:
        raise ValueError("--hostname must contain at least one letter or digit")
    return value


def clean_fields(header):
    """CSV header -> Elasticsearch-safe, unique field names (no dots, no leading _)."""
    used, out = set(RESERVED), []
    for name in header:
        f = re.sub(r"[^\w]+", "_", name.strip()).strip("_") or "field"
        if f[0].isdigit():
            f = "f_" + f
        base, i = f, 2
        while f in used:
            f, i = f"{base}_{i}", i + 1
        used.add(f)
        out.append(f)
    return out


def detect_tag(path, fields):
    """AppCompatCache / Amcache_<Section> from the file name or columns; None = not ours."""
    h = {f.lower() for f in fields}
    stem = re.sub(r"^\d{8,}_", "", path.stem)
    if re.search(r"appcompatcache|shimcache", stem, re.I) or {"cacheentryposition", "lastmodifiedtimeutc"} <= h:
        return "AppCompatCache"
    m = re.search(r"amcache[_ -]+(.+)$", stem, re.I)
    if m:
        section = re.sub(r"[^A-Za-z0-9]+", "_", m.group(1)).strip("_")[:50]
        return f"Amcache_{section}" if section else "Amcache"
    if "filekeylastwritetimestamp" in h or ("sha1" in h and "programid" in h):
        return "Amcache_FileEntries"
    return None


def other_tag(path):
    stem = re.sub(r"^\d{8,}_", "", path.stem)
    return re.sub(r"[^A-Za-z0-9]+", "_", stem).strip("_")[:60] or "Unknown"


def is_local(field):
    return bool(LOCAL_RE.search(field))


def field_tz(field, local_tz):
    return local_tz if is_local(field) else "Z"


def read_rows(path):
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as fh:
        reader = csv.reader(fh)
        header = next(reader, None)
        yield header
        for row in reader:
            if any(cell.strip() for cell in row):
                yield row


# --------------------------------------------------------------------------- type inference

def scan(path, fields, state):
    """Update per-field type candidates for one file. state is shared per forensic_tag."""
    rows = read_rows(path)
    next(rows)  # header
    for f in fields:
        state.setdefault(f, {"boolean": True, "long": True, "date": True, "seen": False,
                             "filled": 0, "date_hits": 0, "bad": None})
    count = 0
    for row in rows:
        count += 1
        for i, f in enumerate(fields):
            v = row[i].strip() if i < len(row) else ""
            if not v:
                continue
            s = state[f]
            s["seen"] = True
            s["filled"] += 1
            if s["boolean"] and v.lower() not in BOOLS:
                s["boolean"] = False
            if s["long"] and not (INT_RE.match(v) and abs(int(v)) <= INT64_MAX):
                s["long"] = False
            if ISO_RE.match(v):
                s["date_hits"] += 1
            else:
                s["date"] = False
                if s["bad"] is None:
                    s["bad"] = v[:60]
    return count


def finalize(state, local_tz=None):
    """Per-tag types. None = column never had a value (no vote on its type).
    LOCAL date columns stay text unless --local-tz says what offset they are in."""
    types = {}
    for f, s in state.items():
        if not s["seen"]:
            types[f] = None
        elif s["boolean"]:
            types[f] = "boolean"
        elif s["long"]:
            types[f] = "long"
        elif s["date"]:
            types[f] = "date" if (local_tz or not is_local(f)) else "string"
        else:
            types[f] = "string"
    return types


def merge_types(plan):
    """One type per field across all tools; disagreement -> string. Returns (types, conflicts)."""
    votes = {}
    for tag, p in plan.items():
        for f, t in p["types"].items():
            votes.setdefault(f, {})
            if t:
                votes[f].setdefault(t, []).append(p["tag"])
    types, conflicts = {}, {}
    for f, v in votes.items():
        if not v:
            types[f] = "string"
        elif len(v) == 1:
            types[f] = next(iter(v))
        else:
            types[f] = "string"
            conflicts[f] = v
    return types, conflicts


def pick_time_fields(types, tag):
    """
    Ordered @timestamp candidates for a tool, tried row by row (first non-empty wins).
    Tool preferences first; otherwise the best generic match. UTC columns beat LOCAL ones.
    """
    dates = [f for f, t in types.items() if t == "date"]
    utc = [f for f in dates if not is_local(f)]
    dates = utc or dates
    by_lower = {f.lower(): f for f in dates}
    chain = [by_lower[n.lower()] for n in time_prefs(tag) if n.lower() in by_lower]
    if chain:
        return chain
    lower = {re.sub(r"local|utc", "", f.lower().replace("_", "")): f for f in dates}
    for name in TIME_PRIORITY:
        if name in lower:
            return [lower[name]]
    return dates[:1]


def first_ts(row, fields, chain, local_tz):
    """(timestamp, column) from the first chain column with a value in this row."""
    for f in chain:
        i = fields.index(f)
        if i < len(row) and row[i].strip():
            ts = parse_ts(row[i], field_tz(f, local_tz))
            if ts:
                return ts, f
    return None, None


def count_ts_coverage(p, local_tz):
    """How many rows get @timestamp from each chain column, and how many from none."""
    used = {f: 0 for f in p["ts"]}
    none = 0
    for f, fields in p["files"]:
        rows = read_rows(f)
        next(rows)
        for row in rows:
            _, col = first_ts(row, fields, p["ts"], local_tz)
            if col:
                used[col] += 1
            else:
                none += 1
    return used, none


def resolve_against_existing(types, existing):
    """
    Fit the inferred types to an index that already has mappings.
    Returns (write, renames): write = field -> type to send; renames = field -> new name.
    """
    write, renames = {}, {}
    for f, t in types.items():
        if f not in existing:
            write[f] = t
            continue
        fam = ES_FAMILY.get(existing[f], "other")
        if fam == t:
            write[f] = t
        elif fam == "string":
            write[f] = "string"  # anything can be stored as a string
        else:
            renames[f] = f"{f}_text"
            write[f] = "string"
    return write, renames


def build_doc(row, fields, write, renames, ts_field, meta, ingest_time, local_tz=None):
    doc = {}
    for i, f in enumerate(fields):
        raw = row[i] if i < len(row) else ""
        v = raw.strip()
        if not v:
            continue
        t = write[f]
        if t == "date":
            val = parse_ts(v, field_tz(f, local_tz))
        elif t == "long":
            val = int(v)
        elif t == "boolean":
            val = BOOLS[v.lower()]
        else:
            val = raw
        doc[renames.get(f, f)] = val

    ts, ts_col = first_ts(row, fields, ts_field, local_tz)
    doc["@timestamp"] = ts or ingest_time
    doc["host"] = {"name": meta["host"]}
    fobj = {}
    pi = meta.get("path_col")
    if pi is not None and pi < len(row) and row[pi].strip():
        path = row[pi].strip().lower()
        fobj["path"] = path
        fobj["name"] = re.split(r"[\\/]", path)[-1]
    hi = meta.get("sha1_col")
    if hi is not None and hi < len(row) and row[hi].strip():
        sha1 = row[hi].strip().lower()
        if len(sha1) == 44 and sha1.startswith("0000"):
            sha1 = sha1[4:]  # older Amcache stores SHA1 with a 0000 prefix
        fobj["hash"] = {"sha1": sha1}
    if fobj:
        doc["file"] = fobj
    src = ts_col or "ingest_time"
    doc["kape"] = {
        "source_file": meta["source_file"],
        "timestamp_source": src,
        "timestamp_meaning": TIME_MEANING.get(src.lower(), "Timestamp column: " + src),
    }
    if meta.get("case"):
        doc["case"] = meta["case"]
    return doc


def timestamp_check(plan, types, local_tz):
    """Print how each tool's @timestamp is set and anything that needs a look. Returns note count."""
    notes_total = 0
    print("\nTimestamp check")
    for p in sorted(plan.values(), key=lambda x: x["tag"].lower()):
        st, chain, rows = p["state"], p["ts"], p["rows"]
        notes = []
        if chain:
            used, none = count_ts_coverage(p, local_tz)
            parts = []
            for c in chain:
                zone = f"local {local_tz}" if is_local(c) else "UTC"
                parts.append(f"{c} ({zone}) {used[c]}")
            head = f"OK    @timestamp <- " + ", then ".join(parts) + f"  [of {rows} rows]"
            if none:
                notes.append(f"{none} row(s) have none of {', '.join(chain)} -> those use ingest time")
            for c in chain:
                if types.get(c) != "date":
                    notes.append(f"{c} is text in other tools, so it is a text field in the index"
                                 f" (this tool's @timestamp is still correct)")
        else:
            head = "WARN  @timestamp <- ingest time (no usable UTC date column)"
            if not rows:
                head = "OK    header only, no rows"
            if rows:
                notes.append("these rows will all sit at the load time in Kibana timelines")
        for f, s in st.items():
            if not s["filled"]:
                continue
            all_dates = s["date_hits"] == s["filled"]
            if is_local(f) and all_dates and not local_tz:
                notes.append(f"{f}: host LOCAL time with no offset -> stored as text, not used for"
                             f" @timestamp (add --local-tz +HH:MM to convert it)")
            elif is_local(f) and all_dates:
                notes.append(f"{f}: LOCAL time, converted using offset {local_tz}")
            elif not all_dates and s["date_hits"]:
                notes.append(f"{f}: {s['date_hits']}/{s['filled']} values are timestamps, the rest"
                             f" aren't (e.g. \"{s['bad']}\") -> stored as text")
            elif (s["date_hits"] == 0 and TIME_NAME_RE.search(f) and s["bad"]
                  and OTHER_DATE_RE.search(s["bad"])):
                notes.append(f"{f}: looks like a date in an unrecognised format"
                             f" (e.g. \"{s['bad']}\") -> stored as text")
        print(f"  {p['tag']:<32} {head}")
        if chain:
            meaning = TIME_MEANING.get(chain[0].lower())
            if meaning:
                print(f"  {'':<32}   means: {meaning}")
        for n in notes:
            print(f"  {'':<32}   - {n}")
        notes_total += len(notes)
    if notes_total:
        print(f"\n  {notes_total} note(s). None of these stop ingestion: every row still loads,"
              f" affected values are kept as text.")
    else:
        print("\n  No timestamp issues found.")
    return notes_total


# --------------------------------------------------------------------------- Elasticsearch

META_PROPS = {
    "@timestamp": {"type": "date"},
    "host": {"properties": {"name": {"type": "keyword"}}},
    "file": {"properties": {
        "path": {"type": "keyword", "ignore_above": 4096},
        "name": {"type": "keyword"},
        "hash": {"properties": {"sha1": {"type": "keyword"}}},
    }},
    "kape": {"properties": {
        "source_file": {"type": "keyword"},
        "timestamp_source": {"type": "keyword"},
        "timestamp_meaning": {"type": "keyword"},
    }},
    "case": {"type": "keyword"},
}


class ES:
    def __init__(self, url, user=None, password=None, insecure=False):
        self.url = url.rstrip("/")
        self.headers = {}
        if user:
            token = base64.b64encode(f"{user}:{password or ''}".encode()).decode()
            self.headers["Authorization"] = f"Basic {token}"
        self.ctx = ssl._create_unverified_context() if insecure else None

    def call(self, method, path, body=None, ctype="application/json"):
        data = body.encode("utf-8") if body is not None else None
        req = request.Request(self.url + path, data=data, method=method,
                              headers={**self.headers, "Content-Type": ctype})
        try:
            with request.urlopen(req, timeout=300, context=self.ctx) as r:
                status, raw = r.status, r.read()
        except error.HTTPError as e:
            status, raw = e.code, e.read()
        try:
            return status, (json.loads(raw) if raw else {})
        except ValueError:
            return status, {"raw": raw.decode("utf-8", "replace")}

    def existing_fields(self, index):
        """Top-level field -> mapping type for an existing index, or None if it doesn't exist."""
        status, _ = self.call("HEAD", f"/{index}")
        if status != 200:
            return None
        status, resp = self.call("GET", f"/{index}/_mapping")
        if status >= 300:
            sys.exit(f"Could not read mapping of {index} ({status}): {json.dumps(resp)[:500]}")
        props = next(iter(resp.values()), {}).get("mappings", {}).get("properties", {})
        return {f: m.get("type", "object") for f, m in props.items()}

    def create_index(self, index, typed_props):
        body = {
            "settings": {
                "number_of_replicas": 0,
                "index.mapping.total_fields.limit": 5000,
                # safety net: a stray bad value is kept in _source instead of failing the doc
                "index.mapping.ignore_malformed": True,
            },
            "mappings": {
                "date_detection": False,
                "numeric_detection": False,
                "dynamic_templates": [{"strings": {
                    "match_mapping_type": "string",
                    "mapping": {"type": "text",
                                "fields": {"keyword": {"type": "keyword", "ignore_above": 1024}}},
                }}],
                "properties": {**typed_props, **META_PROPS},
            },
        }
        status, resp = self.call("PUT", f"/{index}", json.dumps(body))
        if status >= 300:
            sys.exit(f"Could not create index {index} ({status}): {json.dumps(resp)[:500]}")

    def add_fields(self, index, typed_props):
        if not typed_props:
            return
        status, resp = self.call("PUT", f"/{index}/_mapping",
                                 json.dumps({"properties": typed_props}))
        if status >= 300:
            sys.exit(f"Could not update mapping of {index} ({status}): {json.dumps(resp)[:500]}")

    def bulk(self, lines, stats):
        if not lines:
            return
        status, resp = self.call("POST", "/_bulk", "\n".join(lines) + "\n", "application/x-ndjson")
        if status >= 300:
            sys.exit(f"Bulk request failed ({status}): {json.dumps(resp)[:500]}")
        for item in resp.get("items", []):
            res = next(iter(item.values()))
            if "error" in res:
                stats["errors"] += 1
                if stats["errors"] <= 5:
                    reason = res["error"].get("reason", res["error"])
                    print(f"    ! {reason}", file=sys.stderr)
            else:
                stats["ok"] += 1
                if res.get("result") == "updated":
                    stats["updated"] += 1
        lines.clear()

    def host_count(self, index, host):
        """Refresh, then count the documents this host has in the index."""
        self.call("POST", f"/{index}/_refresh")
        q = {"query": {"term": {"host.name": host}}}
        status, resp = self.call("POST", f"/{index}/_count", json.dumps(q))
        return resp.get("count") if status < 300 else None


def typed_props(write, renames, only_new_from=None):
    """Explicit mappings for non-string fields (strings go through the dynamic template)."""
    props = {}
    for f, t in write.items():
        if t == "string":
            continue
        name = renames.get(f, f)
        if only_new_from is not None and name in only_new_from:
            continue
        props[name] = {"type": t}
    return props


# --------------------------------------------------------------------------- main

def file_meta(f, fields, host, tag, case):
    """Per-file values build_doc needs: where the path and hash columns are, and labels."""
    lower = [x.lower() for x in fields]
    path_col = next((lower.index(c) for c in PATH_COLUMNS if c in lower), None)
    sha1_col = lower.index("sha1") if "sha1" in lower else None
    return {"host": host, "tag": tag, "source_file": f.name, "case": case,
            "path_col": path_col, "sha1_col": sha1_col}


def main():
    ap = argparse.ArgumentParser(
        description="Load AppCompatCacheParser / ShimCache CSVs into a host-specific SOF-ELK index.")
    ap.add_argument("paths", nargs="+", help="CSV files or folders (searched recursively)")
    ap.add_argument("--hostname", required=True, help="Host the KAPE collection came from")
    ap.add_argument("--case", help="Optional case/incident ID added to every document")
    ap.add_argument("--index", default=None,
                    help="Override target index (default: shimcache-<hostname>)")
    ap.add_argument("--local-tz", metavar="+HH:MM",
                    help="UTC offset of the host's clock, used to convert *LOCAL* time columns"
                         " (e.g. +08:00). Without it LOCAL columns are kept as text.")
    ap.add_argument("--es", default="http://localhost:9200", help="Elasticsearch URL")
    ap.add_argument("--batch-size", type=int, default=2000)
    ap.add_argument("--user", help="Elasticsearch username, if security is enabled")
    ap.add_argument("--password")
    ap.add_argument("--insecure", action="store_true", help="Skip TLS certificate checks")
    ap.add_argument("--dry-run", action="store_true",
                    help="Show tools, inferred types and sample docs; send nothing")
    args = ap.parse_args()

    local_tz = None
    if args.local_tz:
        m = TZ_ARG_RE.match(args.local_tz.strip())
        if not m or int(m.group(2)) > 14:
            sys.exit(f"--local-tz must look like +08:00 or -0500, got '{args.local_tz}'")
        local_tz = f"{m.group(1)}{int(m.group(2)):02d}:{m.group(3) or '00'}"

    try:
        host = sanitize_hostname(args.hostname)
    except ValueError as exc:
        sys.exit(str(exc))
    index = (args.index or f"shimcache-{host}").lower()
    if args.index and index != args.index:
        print(f"note: Elasticsearch index names must be lower-case, using '{index}'\n")

    files = []
    for p in map(Path, args.paths):
        if p.is_dir():
            files += sorted(x for x in p.rglob("*") if x.suffix.lower() == ".csv")
        elif p.is_file():
            files.append(p)
        else:
            print(f"skip: {p} not found", file=sys.stderr)
    if not files:
        sys.exit("No CSV files found.")

    # Pass 1: group files by forensic_tag and infer types per tag
    plan, skipped = {}, []
    for f in files:
        header = next(read_rows(f), None)
        if not header:
            print(f"skip: {f.name} is empty", file=sys.stderr)
            continue
        fields = clean_fields(header)
        tag = detect_tag(f, fields)
        if tag != "AppCompatCache":
            skipped.append(f.name)
            continue
        p = plan.setdefault(tag.lower(), {"tag": tag, "files": [], "state": {}, "rows": 0})
        p["files"].append((f, fields))
        p["rows"] += scan(f, fields, p["state"])

    if not plan:
        sys.exit("No matching CSV files found for this importer.")

    for p in plan.values():
        p["types"] = finalize(p["state"], local_tz)
        p["ts"] = pick_time_fields(p["types"], p["tag"])

    # One type per field across every tool
    types, conflicts = merge_types(plan)

    ingest_time = dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

    if skipped:
        print(f"Skipped {len(skipped)} CSV(s) outside this importer's supported source type"
              f":")
        for n in skipped:
            print(f"  - {n}")
        print()
    if not plan:
        sys.exit("Nothing to load.")
    loaded = sum(len(p["files"]) for p in plan.values())
    total_rows = sum(p["rows"] for p in plan.values())
    print(f"{loaded} CSV files, {total_rows} rows -> index '{index}', {len(plan)} source groups\n")
    for p in sorted(plan.values(), key=lambda x: x["tag"].lower()):
        print(f"  source={p['tag']:<32} {len(p['files']):>3} file(s) {p['rows']:>8} rows")
    if conflicts:
        print("\nColumns with different types in different tools (stored as string):")
        for f, v in sorted(conflicts.items()):
            print(f"  {f}: " + "; ".join(f"{t} in {', '.join(tags)}" for t, tags in v.items()))

    timestamp_check(plan, types, local_tz)

    if args.dry_run:
        typed = {f: t for f, t in types.items() if t != "string"}
        print(f"\nTyped fields: {typed or 'none (all strings)'}")
        print("\nSample document per source group:")
        for p in sorted(plan.values(), key=lambda x: x["tag"].lower()):
            f, fields = p["files"][0]
            rows = read_rows(f)
            next(rows)
            sample = next(rows, None)
            if sample:
                meta = file_meta(f, fields, host, p["tag"], args.case)
                doc = build_doc(sample, fields, types, {}, p["ts"], meta, ingest_time, local_tz)
                print(f"  {p['tag']}: " + json.dumps(doc, ensure_ascii=False)[:700])
        print("\nDry run only - nothing sent.")
        return

    es = ES(args.es, args.user, args.password, args.insecure)
    try:
        status, info = es.call("GET", "/")
    except error.URLError as e:
        sys.exit(f"\nCannot reach Elasticsearch at {args.es}: {e.reason}")
    if status >= 300:
        sys.exit(f"\nElasticsearch returned {status}: {json.dumps(info)[:300]}")
    print(f"\nConnected to Elasticsearch {info.get('version', {}).get('number', '?')} at {args.es}")

    existing = es.existing_fields(index)
    if existing is None:
        write, renames = types, {}
        es.create_index(index, typed_props(write, renames))
        print(f"Created index '{index}'")
    else:
        write, renames = resolve_against_existing(types, existing)
        es.add_fields(index, typed_props(write, renames, only_new_from=existing))
        print(f"Index '{index}' exists - appending")
        for f, new in sorted(renames.items()):
            print(f"  note: '{f}' is mapped as {existing[f]} in the index but this data doesn't fit;"
                  f" storing it as '{new}'")

    total = {"ok": 0, "errors": 0, "updated": 0}
    for p in sorted(plan.values(), key=lambda x: x["tag"].lower()):
        stats, lines = {"ok": 0, "errors": 0, "updated": 0}, []
        for f, fields in p["files"]:
            meta = file_meta(f, fields, host, p["tag"], args.case)
            # ID = host + tool + file name (minus KAPE's run timestamp) + row position + row.
            # Re-runs overwrite instead of duplicating; identical rows in a file stay separate.
            stable_name = re.sub(r"^\d{8,}_", "", f.name)
            rows = read_rows(f)
            next(rows)
            for n, row in enumerate(rows):
                doc = build_doc(row, fields, write, renames, p["ts"], meta, ingest_time, local_tz)
                doc_id = hashlib.sha1(json.dumps(
                    [host, p["tag"], stable_name, n, row], ensure_ascii=False).encode()).hexdigest()
                lines.append(json.dumps({"index": {"_index": index, "_id": doc_id}}))
                lines.append(json.dumps(doc, ensure_ascii=False))
                if len(lines) >= args.batch_size * 2:
                    es.bulk(lines, stats)
            es.bulk(lines, stats)
        new = stats["ok"] - stats["updated"]
        print(f"  {p['tag']:<34} {p['rows']:>8} rows: {new} new, {stats['updated']} already in index,"
              f" {stats['errors']} errors")
        for k in total:
            total[k] += stats[k]

    rows_total = sum(p["rows"] for p in plan.values())
    new = total["ok"] - total["updated"]
    print(f"\nDone: {rows_total} rows read -> {new} new documents, {total['updated']} already in"
          f" index (re-run), {total['errors']} errors.")
    in_index = es.host_count(index, host)
    if in_index is not None:
        verdict = "matches" if in_index == rows_total else "DOES NOT MATCH"
        print(f"Index check: '{index}' now holds {in_index} documents for host '{host}'"
              f" ({verdict} the {rows_total} rows read).")
        if in_index > rows_total:
            print("  More documents than rows: this host was probably loaded earlier with different"
                  " files or an older version of the script. Delete its documents and reload"
                  " to get a clean count.")
    print(f"In Kibana, create a data view for '{index}' with @timestamp as the time field,"
          f" then search file.name / file.hash.sha1.")


if __name__ == "__main__":
    main()
